from __future__ import annotations

import logging
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from typing import Any

import requests

from pihole_manager.cancellation import (
    CancellationToken,
    OperationCancelledError,
    cancel_pending,
    raise_if_cancelled,
)
from pihole_manager.config import ResearchProviderOptions, load_options
from pihole_manager.database import (
    get_domain_lock,
    research_findings_get,
    save_research_findings,
)
from pihole_manager.evidence_quality import (
    annotate_source_kind,
    detect_contradictions,
    quality_summary,
    score_finding,
)
from pihole_manager.models import ResearchFinding
from pihole_manager.repository_lists import research_repository_lists
from pihole_manager.research_catalogs import (
    research_adguard_services,
    research_disconnect_tracking,
    research_phishtank,
)
from pihole_manager.research_common import (
    ResearchError,
    normalize_domain,
    provider_snapshot,
    redact_provider_text,
    register_provider_failure,
    register_provider_success,
)
from pihole_manager.research_lookups import (
    research_cloudflare_radar,
    research_dns_records,
    research_netcraft,
    research_rdap,
    research_ripestat,
    research_threatfox,
    research_urlscan,
    research_virustotal,
)

log = logging.getLogger(__name__)
_MAX_PROMPT_FINDINGS = 12
_MAX_SUMMARY_LENGTH = 900


@dataclass(frozen=True, slots=True)
class EvidenceSourceTestResult:
    provider: str
    kind: str
    domain: str
    status: str
    finding_count: int
    elapsed_ms: int
    summary: str

    @property
    def success(self) -> bool:
        return self.status == "pass"


_TEST_DOMAINS = {
    "adguard_services": "wechat.com",
    "dns_records": "cloudflare.com",
    "disconnect_tracking": "google-analytics.com",
    "rdap": "example.com",
    "ripestat": "cloudflare.com",
    "netcraft": "google.com",
    "virustotal": "example.com",
    "threatfox": "example.com",
    "phishtank": "example.com",
    "urlscan": "google.com",
    "cloudflare_radar": "google.com",
    "repository_lists": "example.com",
}

_PROVIDER_HANDLERS: dict[
    str,
    Callable[[str, ResearchProviderOptions], list[ResearchFinding]],
] = {
    "adguard_services": research_adguard_services,
    "dns_records": research_dns_records,
    "disconnect_tracking": research_disconnect_tracking,
    "rdap": research_rdap,
    "ripestat": research_ripestat,
    "netcraft": research_netcraft,
    "virustotal": research_virustotal,
    "threatfox": research_threatfox,
    "phishtank": research_phishtank,
    "urlscan": research_urlscan,
    "cloudflare_radar": research_cloudflare_radar,
    "repository_lists": research_repository_lists,
}


def test_research_provider(
    provider: ResearchProviderOptions,
    *,
    domain: str | None = None,
    skip_api_key_sources: bool = False,
    skip_missing_api_keys: bool = False,
) -> EvidenceSourceTestResult:
    selected_domain = normalize_domain(
        domain or provider.test_domain or _TEST_DOMAINS.get(provider.kind, "example.com")
    )
    definition = provider_snapshot(provider)
    requires_key = bool(definition.get("requires_api_key"))
    if skip_api_key_sources and requires_key:
        return EvidenceSourceTestResult(
            provider=provider.name,
            kind=provider.kind,
            domain=selected_domain,
            status="skip",
            finding_count=0,
            elapsed_ms=0,
            summary="Skipped because this source requires an API key.",
        )
    if requires_key and not provider.api_key.strip():
        status = "skip" if skip_missing_api_keys else "fail"
        summary = (
            "Skipped because no API key is configured."
            if status == "skip"
            else "API key is required but not configured."
        )
        return EvidenceSourceTestResult(
            provider=provider.name,
            kind=provider.kind,
            domain=selected_domain,
            status=status,
            finding_count=0,
            elapsed_ms=0,
            summary=summary,
        )
    started = time.monotonic()
    try:
        findings = _run_provider_with_retries(selected_domain, provider)[: provider.max_results]
    except Exception as exc:
        return EvidenceSourceTestResult(
            provider=provider.name,
            kind=provider.kind,
            domain=selected_domain,
            status="fail",
            finding_count=0,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            summary=_test_error_summary(exc, provider),
        )
    visible = [item for item in findings if item.raw_data.get("include_in_prompt", True)]
    first = visible[0] if visible else findings[0] if findings else None
    if first is None:
        summary = "Source responded and the response was parsed successfully."
    elif first.verdict == "no_match" or not first.raw_data.get("include_in_prompt", True):
        summary = "Source responded successfully; no evidence matched the test domain."
    else:
        summary = f"{first.title} ({first.verdict})"
    return EvidenceSourceTestResult(
        provider=provider.name,
        kind=provider.kind,
        domain=selected_domain,
        status="pass",
        finding_count=len(visible),
        elapsed_ms=int((time.monotonic() - started) * 1000),
        summary=summary,
    )


def _test_error_summary(exc: Exception, provider: ResearchProviderOptions) -> str:
    text = redact_provider_text(exc, provider).strip().replace("\n", " ")
    lowered = text.lower()
    if "failed to resolve" in lowered or "nameresolutionerror" in lowered:
        return "DNS resolution failed for the source host."
    if "timed out" in lowered or "timeout" in lowered:
        return "The source did not respond before the timeout."
    if "401" in text or "403" in text:
        return "Authentication was rejected by the source."
    if "429" in text:
        return "The source rate limit was reached."
    return text[:500] or exc.__class__.__name__


def research_domain(
    domain: str,
    *,
    force: bool = False,
    cancel_token: CancellationToken | None = None,
) -> list[ResearchFinding]:
    normalized = normalize_domain(domain)
    if not normalized:
        raise ValueError("domain must not be empty")
    return research_many(
        [normalized],
        force=force,
        cancel_token=cancel_token,
    ).get(normalized, [])


def research_many(
    domains: list[str],
    *,
    force: bool = False,
    cancel_token: CancellationToken | None = None,
) -> dict[str, list[ResearchFinding]]:
    raise_if_cancelled(cancel_token)
    normalized_domains = list(
        dict.fromkeys(normalized for value in domains if (normalized := normalize_domain(value)))
    )
    output: dict[str, list[ResearchFinding]] = {domain: [] for domain in normalized_domains}
    if not normalized_domains:
        return output

    cached_by_domain: dict[str, list[ResearchFinding]] = {}
    locked_domains: list[str] = []
    for domain in normalized_domains:
        raise_if_cancelled(cancel_token)
        cached = [
            _finding_from_row(row)
            for row in research_findings_get(domain, fresh_only=True, limit=500)
        ]
        cached_by_domain[domain] = cached
        if get_domain_lock(domain) is not None:
            locked_domains.append(domain)
            output[domain] = cached
        elif not force:
            output[domain] = list(cached)

    if force and locked_domains:
        raise RuntimeError(
            "Protected domain(s) cannot be refreshed. Unlock it before refreshing evidence: "
            + ", ".join(locked_domains)
        )

    options = load_options()
    providers = [provider for provider in options.research_providers if provider.enabled]
    if not providers:
        return output

    pending: list[tuple[str, int, ResearchProviderOptions]] = []
    locked = set(locked_domains)
    for domain in normalized_domains:
        raise_if_cancelled(cancel_token)
        if domain in locked:
            continue
        cached_providers = (
            set() if force else {finding.provider for finding in cached_by_domain[domain]}
        )
        for provider_index, provider in enumerate(providers):
            if provider.name not in cached_providers:
                pending.append((domain, provider_index, provider))
    if not pending:
        return output

    executors = [
        ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix=f"evidence-{provider.kind}",
        )
        for provider in providers
    ]
    futures: dict[
        Future[list[ResearchFinding]],
        tuple[str, ResearchProviderOptions],
    ] = {}
    collected: list[ResearchFinding] = []
    cancelled = False
    try:
        for domain, provider_index, provider in pending:
            raise_if_cancelled(cancel_token)
            future = executors[provider_index].submit(
                _run_provider_with_retries,
                domain,
                provider,
                cancel_token,
            )
            futures[future] = (domain, provider)

        remaining = set(futures)
        while remaining:
            raise_if_cancelled(cancel_token)
            done, remaining = wait(
                remaining,
                timeout=0.2,
                return_when=FIRST_COMPLETED,
            )
            raise_if_cancelled(cancel_token)
            for future in done:
                domain, provider = futures[future]
                try:
                    selected = [
                        annotate_source_kind(item, provider.kind)
                        for item in future.result()[: provider.max_results]
                    ]
                except OperationCancelledError:
                    raise
                except Exception as exc:
                    log.warning(
                        "Evidence source %s failed for %s: %s",
                        provider.name,
                        domain,
                        redact_provider_text(exc, provider),
                    )
                    continue
                output[domain].extend(selected)
                collected.extend(selected)
    except OperationCancelledError:
        cancelled = True
        cancel_pending(futures)
        raise
    finally:
        for executor in executors:
            # Do not leave an in-flight source request running after the caller
            # treats the job as cancelled and potentially starts it again.
            executor.shutdown(wait=True, cancel_futures=cancelled)

    if collected:
        save_research_findings(
            collected,
            default_max_age_days=getattr(
                getattr(options, "research", None),
                "max_age_days",
                30,
            ),
        )
    return output


def research_context(
    domain: str,
    findings: list[ResearchFinding] | None = None,
) -> dict[str, Any]:
    normalized = normalize_domain(domain)
    selected = findings
    if selected is None:
        selected = [
            _finding_from_row(row)
            for row in research_findings_get(normalized, fresh_only=True, limit=500)
        ]

    visible = [item for item in selected if _include_in_prompt(item)]
    visible.sort(
        key=lambda item: (
            not item.decision_relevant,
            -score_finding(item).evidence_score,
            -float(item.confidence),
            -int(item.retrieved_at),
        )
    )
    contradictions = detect_contradictions(visible)
    prompt_findings = visible[:_MAX_PROMPT_FINDINGS]
    return {
        "domain": normalized,
        "finding_count": len(visible),
        "decision_relevant_count": sum(1 for item in visible if item.decision_relevant),
        "omitted_count": max(0, len(visible) - len(prompt_findings)),
        "quality": quality_summary(visible, contradictions),
        "contradictions": [item.as_dict() for item in contradictions],
        "findings": [_compact_finding(item) for item in prompt_findings],
    }


def _run_provider(
    domain: str,
    provider: ResearchProviderOptions,
) -> list[ResearchFinding]:
    handler = _PROVIDER_HANDLERS.get(provider.kind)
    if handler is None:
        raise ResearchError(f"Unsupported evidence source kind: {provider.kind}")
    return handler(domain, provider)


def _run_provider_with_retries(
    domain: str,
    provider: ResearchProviderOptions,
    cancel_token: CancellationToken | None = None,
) -> list[ResearchFinding]:
    attempts = max(1, load_options().llm.max_retries + 1)
    for attempt in range(attempts):
        raise_if_cancelled(cancel_token)
        try:
            findings = _run_provider(domain, provider)
        except requests.HTTPError as exc:
            response = exc.response
            status_code = response.status_code if response is not None else 0
            if status_code not in {408, 429, 500, 502, 503, 504}:
                raise
            register_provider_failure(provider, attempt, response)
            if attempt + 1 >= attempts:
                raise
        except (requests.ConnectionError, requests.Timeout):
            register_provider_failure(provider, attempt)
            if attempt + 1 >= attempts:
                raise
        else:
            raise_if_cancelled(cancel_token)
            register_provider_success(provider)
            return findings
    raise RuntimeError(f"Evidence source {provider.name} exhausted its retries")


def _compact_finding(item: ResearchFinding) -> dict[str, Any]:
    quality = score_finding(item)
    return {
        "provider": item.provider,
        "kind": item.kind,
        "signal_type": item.signal_type,
        "verdict": item.verdict,
        "decision_relevant": item.decision_relevant,
        "title": item.title,
        "summary": item.summary[:_MAX_SUMMARY_LENGTH],
        "source_url": item.source_url,
        "confidence": round(float(item.confidence), 3),
        "source_quality": round(quality.source_score, 3),
        "evidence_quality": round(quality.evidence_score, 3),
        "quality_tier": quality.tier,
        "retrieved_at": item.retrieved_at,
    }


def _include_in_prompt(item: ResearchFinding) -> bool:
    return bool(item.raw_data.get("include_in_prompt", True))


def _finding_from_row(row: dict[str, Any]) -> ResearchFinding:
    return ResearchFinding(
        domain=str(row.get("domain") or ""),
        provider=str(row.get("provider") or ""),
        kind=str(row.get("kind") or ""),
        title=str(row.get("title") or ""),
        summary=str(row.get("summary") or ""),
        source_url=str(row.get("source_url") or ""),
        confidence=float(row.get("confidence") or 0.0),
        signal_type=str(row.get("signal_type") or "context"),
        verdict=str(row.get("verdict") or "unknown"),
        decision_relevant=bool(row.get("decision_relevant", False)),
        retrieved_at=int(row.get("retrieved_at") or 0),
        expires_at=int(row.get("expires_at") or 0),
        raw_data=dict(row.get("raw_data") or {}),
    )
