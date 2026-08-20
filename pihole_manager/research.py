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
from pihole_manager.research_reputation import research_crtsh, research_google_safe_browsing
from pihole_manager.research_urlhaus import research_urlhaus

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
    "urlhaus": "example.com",
    "crtsh": "example.com",
    "google_safe_browsing": "testsafebrowsing.appspot.com",
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
    "urlhaus": research_urlhaus,
    "crtsh": research_crtsh,
    "google_safe_browsing": research_google_safe_browsing,
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
        return EvidenceSourceTestResult(
            provider=provider.name,
            kind=provider.kind,
            domain=selected_domain,
            status=status,
            finding_count=0,
            elapsed_ms=0,
            summary="No API key configured.",
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

    elapsed_ms = int((time.monotonic() - started) * 1000)
    summary = findings[0].summary if findings else "No findings returned."
    return EvidenceSourceTestResult(
        provider=provider.name,
        kind=provider.kind,
        domain=selected_domain,
        status="pass",
        finding_count=len(findings),
        elapsed_ms=elapsed_ms,
        summary=summary,
    )


def _test_error_summary(exc: Exception, provider: ResearchProviderOptions) -> str:
    text = redact_provider_text(exc, provider).strip().replace("\n", " ")
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        return f"HTTP {exc.response.status_code}: {text}"[:500]
    return f"{type(exc).__name__}: {text}"[:500]


def research_domain(
    domain: str,
    *,
    force: bool = False,
    options=None,
    cancellation_token: CancellationToken | None = None,
) -> list[ResearchFinding]:
    return research_many(
        [domain],
        force=force,
        options=options,
        cancellation_token=cancellation_token,
    ).get(normalize_domain(domain), [])


def research_many(
    domains: list[str],
    *,
    force: bool = False,
    options=None,
    cancellation_token: CancellationToken | None = None,
) -> dict[str, list[ResearchFinding]]:
    options = options or load_options()
    normalized_domains = list(dict.fromkeys(normalize_domain(domain) for domain in domains if domain))
    cached_by_domain: dict[str, list[ResearchFinding]] = {
        domain: [
            _finding_from_row(row)
            for row in research_findings_get(domain, fresh_only=True, limit=500)
        ]
        for domain in normalized_domains
    }
    providers = [provider for provider in options.research_providers if provider.enabled]
    if not providers:
        return cached_by_domain

    pending: list[tuple[str, int, ResearchProviderOptions]] = []
    for domain in normalized_domains:
        cached_providers = set() if force else {finding.provider for finding in cached_by_domain[domain]}
        for provider_index, provider in enumerate(providers):
            if provider.name not in cached_providers:
                pending.append((domain, provider_index, provider))

    if not pending:
        return cached_by_domain

    executors = [
        ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"evidence-{provider.kind}")
        for provider in providers
    ]
    futures: dict[Future[list[ResearchFinding]], tuple[str, ResearchProviderOptions]] = {}
    try:
        for domain, provider_index, provider in pending:
            raise_if_cancelled(cancellation_token)
            future = executors[provider_index].submit(
                _run_provider_with_retries,
                domain,
                provider,
            )
            futures[future] = (domain, provider)

        unfinished = set(futures)
        while unfinished:
            raise_if_cancelled(cancellation_token)
            done, unfinished = wait(unfinished, timeout=0.2, return_when=FIRST_COMPLETED)
            for future in done:
                domain, provider = futures[future]
                try:
                    items = [
                        annotate_source_kind(item, provider.kind)
                        for item in future.result()[: provider.max_results]
                    ]
                    cached_by_domain[domain].extend(items)
                except OperationCancelledError:
                    raise
                except Exception as exc:
                    log.warning(
                        "Evidence source %s failed for %s: %s",
                        provider.name,
                        domain,
                        redact_provider_text(exc, provider),
                    )
    except OperationCancelledError:
        cancel_pending(futures)
        raise
    finally:
        for executor in executors:
            executor.shutdown(wait=True, cancel_futures=True)

    for domain, findings in cached_by_domain.items():
        if not findings:
            continue
        lock = get_domain_lock(domain)
        if lock is None or not lock.evidence_locked:
            save_research_findings(
                domain,
                [_finding_to_row(item) for item in findings],
                replace_existing=True,
            )
    return cached_by_domain


def research_context(
    domain: str,
    *,
    findings: list[ResearchFinding] | None = None,
) -> dict[str, Any]:
    normalized = normalize_domain(domain)
    selected = findings or [
        _finding_from_row(row)
        for row in research_findings_get(normalized, fresh_only=True, limit=500)
    ]
    ordered = sorted(
        selected,
        key=lambda item: (
            not item.decision_relevant,
            -score_finding(item).evidence_score,
            -item.confidence,
            item.provider.casefold(),
        ),
    )[:_MAX_PROMPT_FINDINGS]
    contradictions = detect_contradictions(ordered)
    return {
        "domain": normalized,
        "findings": [_finding_to_prompt(item) for item in ordered],
        "quality": quality_summary(ordered, contradictions),
        "contradictions": [item.as_dict() for item in contradictions],
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
) -> list[ResearchFinding]:
    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        try:
            findings = _run_provider(domain, provider)
        except requests.HTTPError as exc:
            response = exc.response
            if response is None or response.status_code not in {429, 500, 502, 503, 504}:
                raise
            register_provider_failure(provider, attempt, response)
            if attempt >= max_attempts:
                raise
        except (requests.ConnectionError, requests.Timeout):
            register_provider_failure(provider, attempt)
            if attempt >= max_attempts:
                raise
        else:
            register_provider_success(provider)
            return findings
    raise RuntimeError(f"Evidence source {provider.name} exhausted its retries")


def _finding_to_prompt(item: ResearchFinding) -> dict[str, Any]:
    quality = score_finding(item)
    return {
        "provider": item.provider,
        "kind": item.kind,
        "title": item.title,
        "summary": item.summary[:_MAX_SUMMARY_LENGTH],
        "source_url": item.source_url,
        "confidence": item.confidence,
        "signal_type": item.signal_type,
        "verdict": item.verdict,
        "decision_relevant": item.decision_relevant,
        "retrieved_at": item.retrieved_at,
        "expires_at": item.expires_at,
        "quality": quality.as_dict(),
    }


def _finding_to_row(item: ResearchFinding) -> dict[str, Any]:
    return {
        "provider": item.provider,
        "kind": item.kind,
        "title": item.title,
        "summary": item.summary,
        "source_url": item.source_url,
        "confidence": item.confidence,
        "signal_type": item.signal_type,
        "verdict": item.verdict,
        "decision_relevant": item.decision_relevant,
        "retrieved_at": item.retrieved_at,
        "expires_at": item.expires_at,
        "raw_data": item.raw_data,
    }


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
        decision_relevant=bool(row.get("decision_relevant")),
        retrieved_at=int(row.get("retrieved_at") or 0),
        expires_at=int(row.get("expires_at") or 0),
        raw_data=dict(row.get("raw_data") or {}),
    )
