from __future__ import annotations

import logging
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass, replace

from pihole_manager.analysis_dispatcher import (
    AnalysisDispatchResult,
    AnalysisUnavailableError,
    dispatch_analysis,
)
from pihole_manager.cancellation import CancellationToken, OperationCancelledError
from pihole_manager.compatibility_profiles import apply_compatibility_profile
from pihole_manager.config import (
    LLMOptions,
    LLMProviderOptions,
    Options,
    PromptProfileOptions,
    load_options,
)
from pihole_manager.database import (
    create_review_task,
    domain_observation_summary,
    get_domain_lock,
    get_state,
    manual_tags,
    queue_domains_needing_analysis,
    queue_due_rechecks,
    record_discovered_domains,
    record_query_observations,
    review_save_classification,
    set_state,
    staging_ack,
    staging_claim_items,
    staging_defer,
    staging_fail,
    staging_ready,
    staging_requeue_processing,
)
from pihole_manager.llm import prompt_fingerprint
from pihole_manager.models import (
    AutomationMode,
    Classification,
    ClassificationRunContext,
    Policy,
    ReviewPriority,
    ServiceRole,
)
from pihole_manager.notifications import Notifier
from pihole_manager.pihole_service import (
    add_exact_domain,
    fetch_queries,
    test_connection,
)
from pihole_manager.research import research_context, research_many

log = logging.getLogger(__name__)


class ManagedWorker(threading.Thread):
    def __init__(self, name: str) -> None:
        super().__init__(name=name, daemon=True)
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def wait(self, seconds: float) -> bool:
        return self._stop_event.wait(max(0.1, seconds))


class Scanner(ManagedWorker):
    def __init__(self) -> None:
        super().__init__("PiHoleScanner")
        options = load_options()
        now = time.time()
        fallback = now - options.scans.initial_lookback_sec
        try:
            stored = float(get_state("scanner_from_ts", str(fallback)))
        except ValueError:
            stored = fallback
        if stored <= 0 or stored > now + 60:
            stored = fallback
        self._from_ts = stored
        self._last_live_activity = time.monotonic()

    def run(self) -> None:
        log.info("Pi-hole scanner started")
        backoff = 1
        while not self._stop_event.is_set():
            options = load_options()
            if not options.scans.enabled:
                self.wait(options.scans.interval_sec)
                continue
            try:
                result = test_connection()
                if not result.success:
                    raise RuntimeError(result.summary)
                request_from = float(max(0, int(self._from_ts)))
                rows = fetch_queries(options.scans.batch_size, request_from)
                rows = [row for row in rows if float(row.get("time") or 0) > self._from_ts]
                recorded = record_query_observations(rows)
                domains = {
                    str(row.get("domain") or "").strip().lower()
                    for row in rows
                    if str(row.get("domain") or "").strip()
                }
                added = queue_domains_needing_analysis(domains)
                timestamps = [float(row.get("time") or 0) for row in rows]
                if timestamps:
                    self._from_ts = max(self._from_ts, max(timestamps) + 0.001)
                    set_state("scanner_from_ts", f"{self._from_ts:.6f}")
                    self._last_live_activity = time.monotonic()
                elif (
                    options.scans.history_backfill_enabled
                    and time.monotonic() - self._last_live_activity
                    >= options.scans.history_idle_after_sec
                ):
                    self._run_history_backfill(options)
                queue_due_rechecks(limit=options.scans.batch_size)
                if rows or added:
                    log.info(
                        "Collector fetched %s query row(s), recorded %s, saw %s domain(s), "
                        "queued %s",
                        len(rows),
                        recorded,
                        len(domains),
                        added,
                    )
                backoff = 1
                self.wait(options.scans.interval_sec)
            except Exception as exc:
                log.warning("Scanner cycle failed: %s", exc)
                self.wait(min(60, backoff))
                backoff = min(60, backoff * 2)
        log.info("Pi-hole scanner stopped")

    def _run_history_backfill(self, options) -> None:
        now = time.time()
        last_completed = float(get_state("history_backfill_completed_at", "0") or 0)
        if now - last_completed < 21_600:
            return
        start_ts = now - options.scans.history_lookback_days * 86_400
        try:
            until_ts = float(get_state("history_backfill_until_ts", str(now)))
        except ValueError:
            until_ts = now
        if until_ts <= start_ts or until_ts > now + 60:
            until_ts = now

        rows = fetch_queries(
            options.scans.history_batch_size,
            start_ts,
            until_ts,
        )
        if not rows:
            set_state("history_backfill_completed_at", str(int(now)))
            set_state("history_backfill_until_ts", str(now))
            self._last_live_activity = time.monotonic()
            log.info("History backfill completed; no older query rows remain")
            return

        record_discovered_domains(rows)
        domains = {
            str(row.get("domain") or "").strip().lower()
            for row in rows
            if str(row.get("domain") or "").strip()
        }
        added = queue_domains_needing_analysis(domains)
        timestamps = [float(row.get("time") or 0) for row in rows if row.get("time")]
        next_until = min(timestamps) - 0.001 if timestamps else start_ts
        set_state("history_backfill_until_ts", f"{next_until:.6f}")
        if next_until <= start_ts or len(rows) < options.scans.history_batch_size:
            set_state("history_backfill_completed_at", str(int(now)))
            set_state("history_backfill_until_ts", str(now))
            self._last_live_activity = time.monotonic()
        log.info(
            "History backfill inspected %s query row(s), found %s domain(s), queued %s",
            len(rows),
            len(domains),
            added,
        )


class Classifier(ManagedWorker):
    def __init__(self, pool_id: str = "background") -> None:
        normalized_pool = pool_id.strip().lower()
        if normalized_pool not in {"realtime", "background"}:
            raise ValueError(f"Unsupported analysis pool: {pool_id}")
        super().__init__(f"LLMClassifier-{normalized_pool}")
        self.pool_id = normalized_pool
        self._notifier = Notifier()
        self._active_job_lock = threading.RLock()
        self._active_cancel_token: CancellationToken | None = None

    def stop(self) -> None:
        super().stop()
        self.cancel_active_job()

    def cancel_active_job(self) -> bool:
        with self._active_job_lock:
            if self._active_cancel_token is None:
                return False
            self._active_cancel_token.cancel()
            return True

    def _begin_job(self) -> CancellationToken:
        token = CancellationToken(self._stop_event)
        with self._active_job_lock:
            self._active_cancel_token = token
        return token

    def _finish_job(self, token: CancellationToken) -> None:
        with self._active_job_lock:
            if self._active_cancel_token is token:
                self._active_cancel_token = None

    def run(self) -> None:
        staging_requeue_processing(pool_id=self.pool_id)
        log.info("%s LLM classifier started", self.pool_id)
        while not self._stop_event.is_set():
            options = load_options()
            if not options.llm.enabled:
                self.wait(options.llm.interval_sec)
                continue
            pool = next(
                (item for item in options.analysis_pools if item.pool_id == self.pool_id),
                None,
            )
            if pool is None or not pool.enabled:
                self.wait(options.llm.interval_sec)
                continue

            if not staging_ready(
                options.scans.queue_trigger_size,
                options.scans.max_queue_wait_sec,
                pool_id=self.pool_id,
            ):
                self.wait(options.llm.interval_sec)
                continue

            claimed_items = staging_claim_items(
                options.llm.worker_batch_size,
                pool_id=self.pool_id,
            )
            if not claimed_items:
                self.wait(options.llm.interval_sec)
                continue
            domains = [str(item["domain"]) for item in claimed_items]
            queue_sources = {
                str(item["domain"]): str(item.get("source") or "") for item in claimed_items
            }

            if self._stop_event.is_set():
                for domain in domains:
                    staging_defer(domain, "Classifier stopped before processing", time.time())
                break
            unlocked_domains = []
            for domain in domains:
                if get_domain_lock(domain) is not None:
                    staging_ack(domain)
                    log.info("Skipped protected domain analysis: %s", domain)
                else:
                    unlocked_domains.append(domain)
            if not unlocked_domains:
                continue
            cancel_token = self._begin_job()
            try:
                dossiers = self._build_dossiers(
                    unlocked_domains,
                    cancel_token=cancel_token,
                )
                result = dispatch_analysis(
                    self.pool_id,
                    unlocked_domains,
                    dossiers,
                    options=options,
                    source="queue",
                    cancel_token=cancel_token,
                )
                completed = self._handle_dispatch_result(
                    result,
                    dossiers,
                    queue_sources=queue_sources,
                    options=options,
                )
                retry_at = max(
                    (error.retry_at for error in result.errors),
                    default=0.0,
                )
                for domain in unlocked_domains:
                    if domain in completed:
                        staging_ack(domain)
                    elif retry_at > time.time():
                        staging_defer(
                            domain,
                            "Assigned provider is temporarily unavailable.",
                            retry_at,
                        )
                    else:
                        staging_fail(
                            domain,
                            "No provider returned a classification.",
                            max_attempts=1,
                        )
            except OperationCancelledError:
                log.info("%s classification cancelled for %s", self.pool_id, unlocked_domains)
                for domain in unlocked_domains:
                    staging_defer(domain, "Classification cancelled", time.time())
                if self._stop_event.is_set():
                    break
            except AnalysisUnavailableError as exc:
                log.warning(
                    "%s classification deferred for %s: %s",
                    self.pool_id,
                    unlocked_domains,
                    exc,
                )
                for domain in unlocked_domains:
                    if exc.retry_at > time.time():
                        staging_defer(domain, str(exc), exc.retry_at)
                    else:
                        staging_fail(domain, str(exc), max_attempts=1)
            except Exception as exc:
                log.warning(
                    "%s classification batch failed for %s: %s",
                    self.pool_id,
                    unlocked_domains,
                    exc,
                )
                for domain in unlocked_domains:
                    staging_fail(domain, str(exc), max_attempts=1)
            finally:
                self._finish_job(cancel_token)
        log.info("%s LLM classifier stopped", self.pool_id)

    def _handle_dispatch_result(
        self,
        result: AnalysisDispatchResult,
        dossiers: list[dict],
        *,
        queue_sources: dict[str, str],
        options: Options,
    ) -> set[str]:
        dossier_by_domain = {str(item.get("domain") or ""): item for item in dossiers}
        completed: set[str] = set()
        provider_by_id = {provider.provider_id: provider for provider in options.llm_providers}
        pool = next(item for item in options.analysis_pools if item.pool_id == result.pool_id)
        profile = options.prompt_profiles[pool.profile_index]
        for provider_result in result.provider_results:
            provider = provider_by_id.get(provider_result.provider_id)
            if provider is None:
                continue
            count = max(1, len(provider_result.classifications))
            for classification in provider_result.classifications:
                run_context = ClassificationRunContext(
                    analysis_run_id=result.run_id,
                    pool_id=result.pool_id,
                    pool_mode=result.mode,
                    provider_id=provider.provider_id,
                    model=provider.model,
                    profile=profile.name,
                    prompt_hash=prompt_fingerprint(profile, options=options),
                    is_primary=provider_result.is_primary,
                    latency_ms=round(provider_result.latency_ms / count),
                    usage=replace(
                        provider_result.usage,
                        input_tokens=round(provider_result.usage.input_tokens / count),
                        output_tokens=round(provider_result.usage.output_tokens / count),
                        total_tokens=round(provider_result.usage.total_tokens / count),
                        units=provider_result.usage.units / count,
                    ),
                )
                if provider_result.is_primary:
                    self._handle_classification(
                        classification,
                        dossier_by_domain.get(
                            classification.domain,
                            {"domain": classification.domain},
                        ),
                        queue_source=queue_sources.get(classification.domain, ""),
                        provider=provider,
                        profile=profile,
                        run_context=run_context,
                        options=options,
                    )
                else:
                    review_save_classification(
                        classification,
                        status="compared",
                        provider_id=provider.provider_id,
                        model=provider.model,
                        profile=profile.name,
                        prompt_hash=run_context.prompt_hash,
                        analysis_run_id=result.run_id,
                        pool_id=result.pool_id,
                        pool_mode=result.mode,
                        is_primary=False,
                        latency_ms=run_context.latency_ms,
                        input_tokens=run_context.usage.input_tokens,
                        output_tokens=run_context.usage.output_tokens,
                        update_current=False,
                    )
                completed.add(classification.domain)
        return completed

    def _build_dossier(self, domain: str) -> dict:
        return self._build_dossiers([domain])[0]

    def _build_dossiers(
        self,
        domains: list[str],
        *,
        cancel_token: CancellationToken | None = None,
    ) -> list[dict]:
        findings_by_domain = research_many(domains, cancel_token=cancel_token)
        return [
            {
                "domain": domain,
                "query_context": domain_observation_summary(domain),
                "research": research_context(
                    domain,
                    findings_by_domain.get(domain, []),
                ),
                "lock": get_domain_lock(domain),
            }
            for domain in domains
        ]

    def _handle_classification(
        self,
        classification: Classification,
        dossier: dict,
        *,
        queue_source: str = "",
        provider: LLMProviderOptions | None = None,
        profile: PromptProfileOptions | None = None,
        run_context: ClassificationRunContext | None = None,
        options: Options | None = None,
    ) -> None:
        selected_options = options or load_options()
        selected_provider = (
            provider or selected_options.llm_providers[selected_options.llm.active_provider_index]
        )
        selected_profile = (
            profile or selected_options.prompt_profiles[selected_options.llm.active_profile_index]
        )
        context = run_context or ClassificationRunContext(
            provider_id=selected_provider.provider_id,
            model=selected_provider.model,
            profile=selected_profile.name,
            prompt_hash=prompt_fingerprint(
                selected_profile,
                options=selected_options,
            ),
        )
        manual_review_requested = queue_source.startswith("manual_")
        classification = replace(
            classification,
            recheck_after_days=_configured_recheck_days(
                classification,
                llm_options=selected_options.llm,
            ),
            needs_review=classification.needs_review or manual_review_requested,
            review_reason=(
                classification.review_reason
                or ("Manually queued for review." if manual_review_requested else "")
            ),
        )
        classification = apply_compatibility_profile(classification)
        policy_classification = apply_manual_tag_override(classification)
        research_data = dossier.get("research") or {}
        decision_evidence_count = int(research_data.get("decision_relevant_count") or 0)
        decision = resolve_automatic_decision(
            policy_classification,
            evidence_count=decision_evidence_count,
            llm_options=selected_options.llm,
        )
        action = decision.action
        lock = get_domain_lock(classification.domain)
        status = "classified"

        if decision.review_reason:
            create_review_task(
                classification.domain,
                decision.review_reason,
                priority=_review_priority(classification),
                source="policy",
            )

        if lock and action is not None and lock["list_type"] != action.value:
            create_review_task(
                classification.domain,
                "Automatic recommendation conflicts with a protected list entry.",
                priority=ReviewPriority.CRITICAL,
                source="lock_conflict",
            )
            action = None
            status = "locked_conflict"

        planned_action = ""
        action_status = "none"
        if action is not None:
            planned_action = action.value
            action_name = "whitelist" if action is Policy.ALLOW else "blacklist"
            if selected_options.llm.simulation_mode:
                action_status = "simulated"
                status = f"simulation_{action.value}"
                create_review_task(
                    classification.domain,
                    f"Simulation mode: automatic {action_name} would have been applied.",
                    priority=ReviewPriority.NORMAL,
                    source="simulation",
                )
                self._notifier.notify(
                    "Pi-hole Manager",
                    f"Simulation: would {action_name} {classification.domain} — "
                    f"{classification.short}",
                )
            else:
                add_exact_domain(classification.domain, action, classification.short)
                action_status = "applied"
                status = f"auto_{action.value}"
                self._notifier.notify(
                    "Pi-hole Manager",
                    f"{action_name}: {classification.domain} — {classification.short}",
                )

        if classification.needs_review or classification.policy in {
            Policy.MANUAL_REVIEW,
            Policy.UNKNOWN,
        }:
            priority = _review_priority(classification)
            reason = classification.review_reason or "The classification requires manual review."
            create_review_task(
                classification.domain,
                reason,
                priority=priority,
                source="llm",
            )

        review_save_classification(
            classification,
            status=status,
            provider_id=selected_provider.provider_id,
            model=context.model or selected_provider.model,
            profile=context.profile or selected_profile.name,
            prompt_hash=context.prompt_hash,
            planned_action=planned_action,
            action_status=action_status,
            analysis_run_id=context.analysis_run_id,
            pool_id=context.pool_id,
            pool_mode=context.pool_mode,
            is_primary=context.is_primary,
            latency_ms=context.latency_ms,
            input_tokens=context.usage.input_tokens,
            output_tokens=context.usage.output_tokens,
        )


@dataclass(frozen=True, slots=True)
class AutomaticActionDecision:
    action: Policy | None
    review_reason: str = ""


def apply_manual_tag_override(classification: Classification) -> Classification:
    override_tags = manual_tags(classification.domain)
    if not override_tags:
        return classification
    return replace(classification, tags=tuple(override_tags))


def resolve_automatic_decision(
    classification: Classification,
    *,
    evidence_count: int = 0,
    llm_options: LLMOptions | None = None,
) -> AutomaticActionDecision:
    options = llm_options or load_options().llm
    try:
        mode = AutomationMode(options.automation_mode)
    except ValueError:
        mode = AutomationMode.HYBRID
    if mode is AutomationMode.MANUAL:
        return AutomaticActionDecision(None)
    if classification.needs_review:
        return AutomaticActionDecision(
            None,
            classification.review_reason or "The model marked the result for manual review.",
        )
    if classification.confidence < options.auto_action_min_confidence:
        return AutomaticActionDecision(None)
    if classification.service_role in {ServiceRole.CORE, ServiceRole.SHARED}:
        return AutomaticActionDecision(
            None,
            "Core or shared service infrastructure must be reviewed manually.",
        )
    if classification.breakage_risk >= 50:
        return AutomaticActionDecision(
            None,
            "Breakage risk is too high for an automatic Pi-hole change.",
        )
    tags = tuple(dict.fromkeys(classification.tags or (classification.category,)))
    policies_by_tag = {
        tag: options.tag_policies.get(tag, Policy.MANUAL_REVIEW.value) for tag in tags
    }
    invalid_tags = [
        tag
        for tag, policy in policies_by_tag.items()
        if policy not in {Policy.ALLOW.value, Policy.DENY.value, Policy.MANUAL_REVIEW.value}
    ]
    if invalid_tags:
        return AutomaticActionDecision(
            None,
            "Invalid default policy for tag(s): " + ", ".join(sorted(invalid_tags)),
        )

    manual_review_tags = [
        tag for tag, policy in policies_by_tag.items() if policy == Policy.MANUAL_REVIEW.value
    ]
    if manual_review_tags:
        return AutomaticActionDecision(
            None,
            "Manual review is required by tag policy: "
            + ", ".join(sorted(manual_review_tags)),
        )

    actionable = {policy for policy in policies_by_tag.values()}
    if len(actionable) != 1:
        mapping = ", ".join(f"{tag}={policy}" for tag, policy in sorted(policies_by_tag.items()))
        return AutomaticActionDecision(
            None,
            "Tag policies conflict and no automatic action is safe: " + mapping,
        )

    tag_policy = Policy(actionable.pop())
    if options.require_research_for_auto_action and evidence_count <= 0:
        return AutomaticActionDecision(
            None,
            "No decision-relevant structured evidence is available for an automatic "
            "Pi-hole change.",
        )
    if mode is AutomationMode.AUTO:
        return AutomaticActionDecision(tag_policy)
    if classification.policy is tag_policy:
        return AutomaticActionDecision(tag_policy)
    return AutomaticActionDecision(
        None,
        "The model recommendation does not match the configured tag policy.",
    )


def resolve_automatic_action(classification: Classification) -> Policy | None:
    return resolve_automatic_decision(classification, evidence_count=1).action


def _configured_recheck_days(
    classification: Classification,
    *,
    llm_options: LLMOptions | None = None,
) -> int:
    options = llm_options or load_options().llm
    tags = tuple(dict.fromkeys(classification.tags or (classification.category,)))
    suggested = max(
        1,
        int(classification.recheck_after_days or options.default_recheck_days),
    )
    configured = [
        int(options.tag_recheck_days[tag]) for tag in tags if tag in options.tag_recheck_days
    ]
    if configured:
        return min(suggested, max(1, min(configured)))
    return suggested


def _review_priority(classification: Classification) -> ReviewPriority:
    if classification.security_risk >= 80:
        return ReviewPriority.CRITICAL
    if classification.breakage_risk >= 70 or classification.service_role is ServiceRole.CORE:
        return ReviewPriority.HIGH
    if classification.confidence < 0.5:
        return ReviewPriority.HIGH
    return ReviewPriority.NORMAL


def _chunks(values: list[str], size: int) -> Iterable[list[str]]:
    for index in range(0, len(values), max(1, size)):
        yield values[index : index + max(1, size)]


_SCANNER: Scanner | None = None
_CLASSIFIERS: dict[str, Classifier] = {}
_WORKER_LOCK = threading.RLock()


def get_scanner() -> Scanner:
    global _SCANNER
    with _WORKER_LOCK:
        if _SCANNER is None or not _SCANNER.is_alive():
            _SCANNER = Scanner()
            _SCANNER.start()
        return _SCANNER


def get_classifier() -> Classifier:
    with _WORKER_LOCK:
        for pool_id in ("realtime", "background"):
            worker = _CLASSIFIERS.get(pool_id)
            if worker is None or not worker.is_alive():
                worker = Classifier(pool_id)
                _CLASSIFIERS[pool_id] = worker
                worker.start()
        return _CLASSIFIERS["background"]


def cancel_classifier_jobs(pool_id: str = "") -> int:
    normalized = pool_id.strip().lower()
    if normalized and normalized not in {"realtime", "background"}:
        raise ValueError(f"Unsupported analysis pool: {pool_id}")
    with _WORKER_LOCK:
        workers = [
            worker
            for worker_id, worker in _CLASSIFIERS.items()
            if not normalized or worker_id == normalized
        ]
        return sum(1 for worker in workers if worker.cancel_active_job())


def stop_workers(timeout: float = 5.0) -> None:
    global _SCANNER
    with _WORKER_LOCK:
        workers: list[ManagedWorker] = [
            worker for worker in (_SCANNER, *_CLASSIFIERS.values()) if worker is not None
        ]
        for worker in workers:
            worker.stop()
        deadline = time.monotonic() + timeout
        for worker in workers:
            remaining = max(0.0, deadline - time.monotonic())
            worker.join(remaining)
        _SCANNER = None
        _CLASSIFIERS.clear()
