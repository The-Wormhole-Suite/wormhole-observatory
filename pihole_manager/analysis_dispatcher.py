from __future__ import annotations

import hashlib
import json
import math
import time
from collections import defaultdict
from collections.abc import Mapping, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, replace
from typing import Any

import requests

from pihole_manager.cancellation import (
    CancellationToken,
    OperationCancelledError,
    cancel_pending,
    raise_if_cancelled,
)
from pihole_manager.config import (
    AnalysisPoolOptions,
    LLMProviderOptions,
    Options,
    ProviderPoolMembershipOptions,
    load_options,
)
from pihole_manager.database import (
    analysis_run_finish,
    analysis_run_start,
    benchmark_result_save,
    benchmark_run_finish,
    benchmark_run_start,
    provider_health_failure,
    provider_health_get,
    provider_health_success,
)
from pihole_manager.llm import (
    build_batch_messages,
    classify_domains_with_metadata,
)
from pihole_manager.models import AnalysisPoolMode, Classification, ProviderUsage
from pihole_manager.provider_api import ProviderRateLimitError
from pihole_manager.provider_registry import (
    ProviderLimitProfile,
    resolve_provider_limit_profile,
)
from pihole_manager.quota import (
    QuotaUnavailableError,
    batch_fits_context,
    estimate_provider_usage,
    maximum_provider_batch_size,
)


@dataclass(frozen=True, slots=True)
class ProviderAnalysisResult:
    provider_id: str
    provider_name: str
    model: str
    profile_name: str
    limit_source: str
    classifications: tuple[Classification, ...]
    latency_ms: int
    usage: ProviderUsage
    is_primary: bool


@dataclass(frozen=True, slots=True)
class ProviderAnalysisError:
    provider_id: str
    provider_name: str
    error: str
    retry_at: float = 0.0


@dataclass(frozen=True, slots=True)
class AnalysisDispatchResult:
    run_id: str
    pool_id: str
    mode: str
    dossier_hash: str
    provider_results: tuple[ProviderAnalysisResult, ...]
    errors: tuple[ProviderAnalysisError, ...] = ()

    def primary_classifications(self) -> dict[str, Classification]:
        return {
            classification.domain: classification
            for result in self.provider_results
            if result.is_primary
            for classification in result.classifications
        }


@dataclass(frozen=True, slots=True)
class _Candidate:
    membership: ProviderPoolMembershipOptions
    provider: LLMProviderOptions
    limit_profile: ProviderLimitProfile


class AnalysisUnavailableError(RuntimeError):
    def __init__(self, message: str, *, retry_at: float = 0.0) -> None:
        super().__init__(message)
        self.retry_at = max(0.0, float(retry_at))


class ProviderPartialAnalysisError(RuntimeError):
    def __init__(
        self,
        result: ProviderAnalysisResult,
        failed_domains: Sequence[str],
        cause: Exception,
    ) -> None:
        super().__init__(str(cause))
        self.result = result
        self.failed_domains = tuple(failed_domains)
        self.cause = cause


def dispatch_analysis(
    pool_id: str,
    domains: Sequence[str],
    dossiers: Sequence[Mapping[str, Any]],
    *,
    options: Options | None = None,
    source: str = "",
    cancel_token: CancellationToken | None = None,
) -> AnalysisDispatchResult:
    raise_if_cancelled(cancel_token)
    selected_options = options or load_options()
    pool = _pool_by_id(selected_options, pool_id)
    normalized_domains, frozen_dossiers, dossier_hash = _freeze_dossiers(domains, dossiers)
    if not normalized_domains:
        raise ValueError("At least one domain is required for analysis.")
    candidates = _pool_candidates(selected_options, pool)
    if not candidates:
        cooling_candidates = _pool_candidates(
            selected_options,
            pool,
            include_cooldown=True,
        )
        now = time.time()
        retry_at = min(
            (
                health.cooldown_until
                for candidate in cooling_candidates
                if (health := provider_health_get(candidate.provider.provider_id)).cooldown_until
                > now
            ),
            default=0.0,
        )
        if retry_at > now:
            raise AnalysisUnavailableError(
                f"All providers in analysis pool {pool.name} are cooling down.",
                retry_at=retry_at,
            )
        raise RuntimeError(f"Analysis pool {pool.name} has no usable providers.")
    run_id = analysis_run_start(
        pool.pool_id,
        pool.mode,
        source=source,
        dossier_hash=dossier_hash,
    )
    try:
        mode = AnalysisPoolMode(pool.mode)
        if mode is AnalysisPoolMode.DISTRIBUTE:
            results, errors = _dispatch_distribute(
                pool,
                candidates,
                normalized_domains,
                frozen_dossiers,
                selected_options,
                cancel_token,
            )
        elif mode is AnalysisPoolMode.FALLBACK:
            results, errors = _dispatch_fallback(
                pool,
                candidates,
                normalized_domains,
                frozen_dossiers,
                selected_options,
                cancel_token,
            )
        elif mode is AnalysisPoolMode.COMPARE:
            results, errors = _dispatch_compare(
                pool,
                candidates,
                normalized_domains,
                frozen_dossiers,
                selected_options,
                cancel_token,
            )
        else:
            results, errors = _dispatch_verify(
                pool,
                candidates,
                normalized_domains,
                frozen_dossiers,
                selected_options,
                cancel_token,
            )
        if not results:
            message = "; ".join(error.error for error in errors) or "No provider result"
            raise AnalysisUnavailableError(
                message,
                retry_at=max((error.retry_at for error in errors), default=0.0),
            )
        analysis_run_finish(
            run_id,
            error="; ".join(error.error for error in errors),
            status="completed_with_errors" if errors else "completed",
        )
        return AnalysisDispatchResult(
            run_id=run_id,
            pool_id=pool.pool_id,
            mode=pool.mode,
            dossier_hash=dossier_hash,
            provider_results=tuple(results),
            errors=tuple(errors),
        )
    except OperationCancelledError as exc:
        analysis_run_finish(run_id, error=str(exc), status="cancelled")
        raise
    except Exception as exc:
        analysis_run_finish(run_id, error=str(exc))
        raise


def benchmark_domain(
    domain: str,
    dossier: Mapping[str, Any],
    provider_ids: Sequence[str],
    *,
    pool_id: str = "background",
    options: Options | None = None,
    cancel_token: CancellationToken | None = None,
) -> str:
    raise_if_cancelled(cancel_token)
    selected_options = options or load_options()
    pool = _pool_by_id(selected_options, pool_id)
    normalized_domains, frozen_dossiers, dossier_hash = _freeze_dossiers(
        [domain],
        [dossier],
    )
    selected_ids = {str(provider_id).strip() for provider_id in provider_ids}
    candidates = [
        candidate
        for candidate in _pool_candidates(selected_options, pool, include_cooldown=True)
        if candidate.provider.provider_id in selected_ids
    ]
    if not candidates:
        raise RuntimeError("No selected benchmark provider is usable.")
    run_id = benchmark_run_start(
        normalized_domains[0],
        pool.pool_id,
        frozen_dossiers[0],
        dossier_hash,
    )

    def execute(candidate: _Candidate) -> ProviderAnalysisResult:
        return _call_execute_provider(
            pool,
            candidate,
            normalized_domains,
            frozen_dossiers,
            selected_options,
            is_primary=False,
            cancel_token=cancel_token,
        )

    maximum_workers = min(max(1, pool.max_parallel_requests), len(candidates))
    executor = ThreadPoolExecutor(max_workers=maximum_workers)
    futures: dict[Future[ProviderAnalysisResult], _Candidate] = {}
    cancelled = False
    try:
        futures = {executor.submit(execute, candidate): candidate for candidate in candidates}
        for future in _iter_completed(futures, cancel_token):
            candidate = futures[future]
            try:
                result = future.result()
            except OperationCancelledError:
                raise
            except Exception as exc:
                benchmark_result_save(
                    run_id,
                    provider_id=candidate.provider.provider_id,
                    provider_name=candidate.provider.name,
                    model=candidate.provider.model,
                    status="failed",
                    error=str(exc),
                )
                continue
            benchmark_result_save(
                run_id,
                provider_id=result.provider_id,
                provider_name=result.provider_name,
                model=result.model,
                status="completed",
                latency_ms=result.latency_ms,
                usage=result.usage,
                classification=result.classifications[0],
            )
    except OperationCancelledError:
        cancelled = True
        cancel_pending(futures)
        benchmark_run_finish(run_id, status="cancelled", error="Operation cancelled")
        raise
    finally:
        # A running provider request cannot be force-stopped safely. Wait for it
        # to observe the token (or reach its HTTP timeout) before returning the
        # cancelled job to the worker, otherwise a requeued job could overlap it.
        executor.shutdown(wait=True, cancel_futures=cancelled)
    benchmark_run_finish(run_id)
    return run_id


def _dispatch_distribute(
    pool: AnalysisPoolOptions,
    candidates: Sequence[_Candidate],
    domains: Sequence[str],
    dossiers: Sequence[Mapping[str, Any]],
    options: Options,
    cancel_token: CancellationToken | None,
) -> tuple[list[ProviderAnalysisResult], list[ProviderAnalysisError]]:
    assignments: dict[str, list[str]] = defaultdict(list)
    dossier_by_domain = {str(dossier["domain"]): dossier for dossier in dossiers}
    weighted = [
        candidate
        for candidate in candidates
        for _index in range(max(1, candidate.membership.weight))
    ]
    candidate_by_id = {candidate.provider.provider_id: candidate for candidate in candidates}
    for domain in domains:
        digest = hashlib.sha256(domain.encode("utf-8")).digest()
        candidate = weighted[int.from_bytes(digest[:8], "big") % len(weighted)]
        assignments[candidate.provider.provider_id].append(domain)

    results: list[ProviderAnalysisResult] = []
    errors: list[ProviderAnalysisError] = []
    maximum_workers = min(max(1, pool.max_parallel_requests), len(assignments))
    executor = ThreadPoolExecutor(max_workers=maximum_workers)
    futures: dict[Future[ProviderAnalysisResult], _Candidate] = {}
    cancelled = False
    try:
        for provider_id, assigned_domains in assignments.items():
            raise_if_cancelled(cancel_token)
            candidate = candidate_by_id[provider_id]
            selected_dossiers = [dossier_by_domain[domain] for domain in assigned_domains]
            future = executor.submit(
                _call_execute_provider,
                pool,
                candidate,
                assigned_domains,
                selected_dossiers,
                options,
                is_primary=True,
                cancel_token=cancel_token,
            )
            futures[future] = candidate
        for future in _iter_completed(futures, cancel_token):
            candidate = futures[future]
            try:
                results.append(future.result())
            except OperationCancelledError:
                raise
            except ProviderPartialAnalysisError as exc:
                results.append(exc.result)
                errors.append(_provider_error(candidate, exc.cause))
            except Exception as exc:
                errors.append(_provider_error(candidate, exc))
    except OperationCancelledError:
        cancelled = True
        cancel_pending(futures)
        raise
    finally:
        executor.shutdown(wait=True, cancel_futures=cancelled)
    return _sort_results(results, candidates), errors


def _dispatch_fallback(
    pool: AnalysisPoolOptions,
    candidates: Sequence[_Candidate],
    domains: Sequence[str],
    dossiers: Sequence[Mapping[str, Any]],
    options: Options,
    cancel_token: CancellationToken | None,
) -> tuple[list[ProviderAnalysisResult], list[ProviderAnalysisError]]:
    dossier_by_domain = {str(dossier["domain"]): dossier for dossier in dossiers}
    remaining_domains = list(domains)
    results: list[ProviderAnalysisResult] = []
    errors: list[ProviderAnalysisError] = []
    for candidate in _fallback_order(candidates):
        raise_if_cancelled(cancel_token)
        if not remaining_domains:
            break
        try:
            result = _call_execute_provider(
                pool,
                candidate,
                remaining_domains,
                [dossier_by_domain[domain] for domain in remaining_domains],
                options,
                is_primary=True,
                cancel_token=cancel_token,
            )
            results.append(result)
            remaining_domains = []
        except OperationCancelledError:
            raise
        except ProviderPartialAnalysisError as exc:
            results.append(exc.result)
            errors.append(_provider_error(candidate, exc.cause))
            remaining_domains = list(exc.failed_domains)
            if not _is_fallback_eligible(exc.cause):
                break
        except Exception as exc:
            errors.append(_provider_error(candidate, exc))
            if not _is_fallback_eligible(exc):
                raise
    return results, errors


def _dispatch_compare(
    pool: AnalysisPoolOptions,
    candidates: Sequence[_Candidate],
    domains: Sequence[str],
    dossiers: Sequence[Mapping[str, Any]],
    options: Options,
    cancel_token: CancellationToken | None,
) -> tuple[list[ProviderAnalysisResult], list[ProviderAnalysisError]]:
    results: list[ProviderAnalysisResult] = []
    errors: list[ProviderAnalysisError] = []
    maximum_workers = min(max(1, pool.max_parallel_requests), len(candidates))
    executor = ThreadPoolExecutor(max_workers=maximum_workers)
    futures: dict[Future[ProviderAnalysisResult], _Candidate] = {}
    cancelled = False
    try:
        futures = {
            executor.submit(
                _call_execute_provider,
                pool,
                candidate,
                domains,
                dossiers,
                options,
                is_primary=False,
                cancel_token=cancel_token,
            ): candidate
            for candidate in candidates
        }
        for future in _iter_completed(futures, cancel_token):
            candidate = futures[future]
            try:
                results.append(future.result())
            except OperationCancelledError:
                raise
            except ProviderPartialAnalysisError as exc:
                results.append(exc.result)
                errors.append(_provider_error(candidate, exc.cause))
            except Exception as exc:
                errors.append(_provider_error(candidate, exc))
    except OperationCancelledError:
        cancelled = True
        cancel_pending(futures)
        raise
    finally:
        executor.shutdown(wait=True, cancel_futures=cancelled)
    return _sort_results(results, candidates), errors


def _dispatch_verify(
    pool: AnalysisPoolOptions,
    candidates: Sequence[_Candidate],
    domains: Sequence[str],
    dossiers: Sequence[Mapping[str, Any]],
    options: Options,
    cancel_token: CancellationToken | None,
) -> tuple[list[ProviderAnalysisResult], list[ProviderAnalysisError]]:
    raise_if_cancelled(cancel_token)
    ordered = _fallback_order(candidates)
    primary_candidate = ordered[0]
    errors: list[ProviderAnalysisError] = []
    try:
        primary = _call_execute_provider(
            pool,
            primary_candidate,
            domains,
            dossiers,
            options,
            is_primary=True,
            cancel_token=cancel_token,
        )
    except OperationCancelledError:
        raise
    except ProviderPartialAnalysisError as exc:
        primary = exc.result
        errors.append(_provider_error(primary_candidate, exc.cause))
    verify_domains = [
        classification.domain
        for classification in primary.classifications
        if _requires_verification(classification, pool)
    ]
    if not verify_domains:
        return [primary], errors

    verifier = next(
        (
            candidate
            for candidate in _verification_order(candidates)
            if candidate.provider.provider_id != primary.provider_id
        ),
        None,
    )
    if verifier is None:
        return [_mark_verification_unavailable(primary, verify_domains)], [
            *errors,
            ProviderAnalysisError(
                provider_id="",
                provider_name="",
                error="No independent verification provider is configured.",
            ),
        ]

    dossier_by_domain = {str(dossier["domain"]): dossier for dossier in dossiers}
    verify_dossiers = [dossier_by_domain[domain] for domain in verify_domains]
    try:
        secondary = _call_execute_provider(
            pool,
            verifier,
            verify_domains,
            verify_dossiers,
            options,
            is_primary=False,
            cancel_token=cancel_token,
        )
    except OperationCancelledError:
        raise
    except ProviderPartialAnalysisError as exc:
        secondary = exc.result
        missing_verifications = list(exc.failed_domains)
        primary = _mark_verification_unavailable(primary, missing_verifications)
        errors.append(_provider_error(verifier, exc.cause))
    except Exception as exc:
        return [_mark_verification_unavailable(primary, verify_domains)], [
            *errors,
            _provider_error(verifier, exc),
        ]

    secondary_by_domain = {
        classification.domain: classification for classification in secondary.classifications
    }
    updated: list[Classification] = []
    for classification in primary.classifications:
        other = secondary_by_domain.get(classification.domain)
        if other is not None and not _classifications_agree(classification, other):
            updated.append(
                replace(
                    classification,
                    needs_review=True,
                    review_reason=(
                        "Independent provider verification disagreed with the primary result."
                    ),
                )
            )
        else:
            updated.append(classification)
    return [replace(primary, classifications=tuple(updated)), secondary], errors


def _call_execute_provider(
    pool: AnalysisPoolOptions,
    candidate: _Candidate,
    domains: Sequence[str],
    dossiers: Sequence[Mapping[str, Any]],
    options: Options,
    *,
    is_primary: bool,
    cancel_token: CancellationToken | None,
) -> ProviderAnalysisResult:
    if cancel_token is None:
        return _execute_provider(
            pool,
            candidate,
            domains,
            dossiers,
            options,
            is_primary=is_primary,
        )
    return _execute_provider(
        pool,
        candidate,
        domains,
        dossiers,
        options,
        is_primary=is_primary,
        cancel_token=cancel_token,
    )


def _execute_provider(
    pool: AnalysisPoolOptions,
    candidate: _Candidate,
    domains: Sequence[str],
    dossiers: Sequence[Mapping[str, Any]],
    options: Options,
    *,
    is_primary: bool,
    cancel_token: CancellationToken | None = None,
) -> ProviderAnalysisResult:
    raise_if_cancelled(cancel_token)
    provider = candidate.provider
    profile = options.prompt_profiles[pool.profile_index]
    dossier_by_domain = {str(dossier["domain"]): dossier for dossier in dossiers}
    classifications: list[Classification] = []
    total_latency = 0
    total_usage = ProviderUsage()
    batches = _provider_batches(
        domains,
        dossier_by_domain,
        provider,
        candidate.limit_profile,
        profile,
        options,
    )
    batch_index = 0
    try:
        while batch_index < len(batches):
            raise_if_cancelled(cancel_token)
            batch = batches[batch_index]
            try:
                selected_dossiers = [dossier_by_domain[domain] for domain in batch]
                result = classify_domains_with_metadata(
                    batch,
                    provider=provider,
                    profile=profile,
                    dossiers=selected_dossiers,
                    options=options,
                    pool_id=pool.pool_id,
                    limit_profile=candidate.limit_profile,
                    cancel_token=cancel_token,
                )
                raise_if_cancelled(cancel_token)
            except QuotaUnavailableError:
                if len(batch) <= 1:
                    raise
                midpoint = max(1, len(batch) // 2)
                batches[batch_index : batch_index + 1] = [
                    batch[:midpoint],
                    batch[midpoint:],
                ]
                continue
            classifications.extend(result.classifications)
            total_latency += result.response.latency_ms
            total_usage = ProviderUsage(
                input_tokens=total_usage.input_tokens + result.response.usage.input_tokens,
                output_tokens=total_usage.output_tokens + result.response.usage.output_tokens,
                total_tokens=total_usage.total_tokens + result.response.usage.total_tokens,
                units=total_usage.units + result.response.usage.units,
            )
            batch_index += 1
        provider_health_success(provider.provider_id, total_latency)
    except OperationCancelledError:
        raise
    except Exception as exc:
        retry_at = _retry_at(exc)
        if not isinstance(exc, QuotaUnavailableError):
            if retry_at <= time.time():
                previous = provider_health_get(provider.provider_id)
                retry_at = time.time() + min(
                    300.0,
                    max(5.0, 2.0 ** min(8, previous.consecutive_failures)),
                )
            provider_health_failure(
                provider.provider_id,
                str(exc),
                cooldown_until=retry_at,
            )
        if classifications:
            failed_domains = [domain for batch in batches[batch_index:] for domain in batch]
            partial = _analysis_result(
                candidate,
                profile.name,
                classifications,
                total_latency,
                total_usage,
                is_primary=is_primary,
            )
            raise ProviderPartialAnalysisError(partial, failed_domains, exc) from exc
        raise
    return _analysis_result(
        candidate,
        profile.name,
        classifications,
        total_latency,
        total_usage,
        is_primary=is_primary,
    )


def _iter_completed(
    futures: Mapping[Future[ProviderAnalysisResult], _Candidate],
    cancel_token: CancellationToken | None,
):
    remaining = set(futures)
    while remaining:
        raise_if_cancelled(cancel_token)
        done, remaining = wait(
            remaining,
            timeout=0.2,
            return_when=FIRST_COMPLETED,
        )
        raise_if_cancelled(cancel_token)
        yield from done


def _analysis_result(
    candidate: _Candidate,
    profile_name: str,
    classifications: Sequence[Classification],
    latency_ms: int,
    usage: ProviderUsage,
    *,
    is_primary: bool,
) -> ProviderAnalysisResult:
    provider = candidate.provider
    return ProviderAnalysisResult(
        provider_id=provider.provider_id,
        provider_name=provider.name,
        model=provider.model,
        profile_name=profile_name,
        limit_source=candidate.limit_profile.source,
        classifications=tuple(classifications),
        latency_ms=latency_ms,
        usage=usage,
        is_primary=is_primary,
    )


def _provider_batches(
    domains: Sequence[str],
    dossiers: Mapping[str, Mapping[str, Any]],
    provider: LLMProviderOptions,
    limit_profile: ProviderLimitProfile,
    profile: Any,
    options: Options,
) -> list[list[str]]:
    maximum = maximum_provider_batch_size(provider, limit_profile, options.llm)
    remaining = list(domains)
    batches: list[list[str]] = []
    while remaining:
        size = min(maximum, len(remaining))
        while size > 0:
            selected = remaining[:size]
            messages = build_batch_messages(
                profile,
                [dossiers[domain] for domain in selected],
                llm_options=options.llm,
            )
            estimate = estimate_provider_usage(
                messages,
                provider=provider,
                profile=limit_profile,
                domain_count=size,
            )
            if batch_fits_context(
                estimate,
                provider=provider,
                profile=limit_profile,
            ):
                break
            size -= 1
        if size <= 0:
            raise RuntimeError(
                f"The dossier for {remaining[0]} exceeds the context limit of {provider.name}."
            )
        batches.append(remaining[:size])
        del remaining[:size]
    return batches


def _pool_candidates(
    options: Options,
    pool: AnalysisPoolOptions,
    *,
    include_cooldown: bool = False,
) -> list[_Candidate]:
    providers = {provider.provider_id: provider for provider in options.llm_providers}
    candidates: list[_Candidate] = []
    now = time.time()
    for membership in pool.memberships:
        provider = providers.get(membership.provider_id)
        if (
            not membership.enabled
            or provider is None
            or not provider.base_url.strip()
            or not provider.model.strip()
        ):
            continue
        health = provider_health_get(provider.provider_id)
        if not include_cooldown and health.cooldown_until > now:
            continue
        candidates.append(
            _Candidate(
                membership=membership,
                provider=provider,
                limit_profile=resolve_provider_limit_profile(provider),
            )
        )
    return sorted(
        candidates,
        key=lambda item: (
            _role_order(item.membership.role),
            item.membership.priority,
            item.provider.name.casefold(),
        ),
    )


def _fallback_order(candidates: Sequence[_Candidate]) -> list[_Candidate]:
    return sorted(
        candidates,
        key=lambda item: (
            0 if item.membership.role == "primary" else 1,
            item.membership.priority,
            item.provider.name.casefold(),
        ),
    )


def _verification_order(candidates: Sequence[_Candidate]) -> list[_Candidate]:
    return sorted(
        candidates,
        key=lambda item: (
            0 if item.membership.role == "verifier" else 1,
            item.membership.priority,
            item.provider.name.casefold(),
        ),
    )


def _requires_verification(
    classification: Classification,
    pool: AnalysisPoolOptions,
) -> bool:
    if classification.security_risk >= pool.verify_security_risk_at_least:
        return True
    if classification.breakage_risk >= pool.verify_breakage_risk_at_least:
        return True
    if (
        pool.verify_automatic_actions
        and not classification.needs_review
        and classification.policy.value in {"allow", "deny"}
    ):
        return True
    sample = min(100, max(0, int(pool.verification_sample_percent)))
    bucket = int.from_bytes(
        hashlib.sha256(classification.domain.encode("utf-8")).digest()[:4],
        "big",
    )
    return bucket % 100 < sample


def _classifications_agree(
    primary: Classification,
    secondary: Classification,
) -> bool:
    return (
        primary.policy is secondary.policy
        and primary.category == secondary.category
        and set(primary.tags) == set(secondary.tags)
        and abs(primary.security_risk - secondary.security_risk) <= 20
        and abs(primary.breakage_risk - secondary.breakage_risk) <= 20
    )


def _mark_verification_unavailable(
    result: ProviderAnalysisResult,
    domains: Sequence[str],
) -> ProviderAnalysisResult:
    selected = set(domains)
    return replace(
        result,
        classifications=tuple(
            replace(
                classification,
                needs_review=True,
                review_reason=(
                    classification.review_reason
                    or "Independent provider verification was unavailable."
                ),
            )
            if classification.domain in selected
            else classification
            for classification in result.classifications
        ),
    )


def _freeze_dossiers(
    domains: Sequence[str],
    dossiers: Sequence[Mapping[str, Any]],
) -> tuple[list[str], tuple[dict[str, Any], ...], str]:
    normalized_domains = list(
        dict.fromkeys(domain.strip().lower().rstrip(".") for domain in domains if domain.strip())
    )
    supplied = {
        str(dossier.get("domain") or "").strip().lower().rstrip("."): dict(dossier)
        for dossier in dossiers
    }
    normalized_dossiers = []
    for domain in normalized_domains:
        dossier = supplied.get(domain, {"domain": domain})
        dossier["domain"] = domain
        normalized_dossiers.append(dossier)
    serialized = json.dumps(
        normalized_dossiers,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    frozen = tuple(json.loads(serialized))
    return normalized_domains, frozen, hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _pool_by_id(options: Options, pool_id: str) -> AnalysisPoolOptions:
    normalized = pool_id.strip().lower()
    for pool in options.analysis_pools:
        if pool.pool_id == normalized and pool.enabled:
            return pool
    raise RuntimeError(f"Analysis pool is disabled or missing: {normalized or '<empty>'}")


def _is_fallback_eligible(exc: Exception) -> bool:
    for error in _exception_chain(exc):
        if isinstance(
            error,
            (
                QuotaUnavailableError,
                ProviderRateLimitError,
                requests.ConnectionError,
                requests.Timeout,
            ),
        ):
            return True
        if isinstance(error, requests.HTTPError):
            response = error.response
            if response is not None and response.status_code in {
                408,
                429,
                500,
                502,
                503,
                504,
            }:
                return True
    return False


def _retry_at(exc: Exception) -> float:
    now = time.time()
    for error in _exception_chain(exc):
        if isinstance(error, QuotaUnavailableError):
            return error.retry_at
        if isinstance(error, ProviderRateLimitError) and error.retry_after is not None:
            return now + max(0.0, error.retry_after)
    return 0.0


def _exception_chain(exc: Exception) -> list[Exception]:
    output: list[Exception] = []
    current: BaseException | None = exc
    while isinstance(current, Exception) and current not in output:
        output.append(current)
        current = current.__cause__ or current.__context__
    return output


def _provider_error(candidate: _Candidate, exc: Exception) -> ProviderAnalysisError:
    health = provider_health_get(candidate.provider.provider_id)
    return ProviderAnalysisError(
        provider_id=candidate.provider.provider_id,
        provider_name=candidate.provider.name,
        error=str(exc),
        retry_at=max(_retry_at(exc), health.cooldown_until),
    )


def _sort_results(
    results: Sequence[ProviderAnalysisResult],
    candidates: Sequence[_Candidate],
) -> list[ProviderAnalysisResult]:
    order = {candidate.provider.provider_id: index for index, candidate in enumerate(candidates)}
    return sorted(results, key=lambda result: order.get(result.provider_id, math.inf))


def _role_order(role: str) -> int:
    return {"primary": 0, "verifier": 1, "fallback": 2}.get(role, 3)
