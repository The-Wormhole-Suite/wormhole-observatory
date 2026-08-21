from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from typing import Any

from pihole_manager.database_core import _DB_LOCK, _connection, _normalize_domain
from pihole_manager.models import ResearchFinding

POLICY_VERSION = 1

# Tag policies are evidence-age ceilings, not classification recheck schedules. Dynamic security
# evidence is intentionally short-lived; service/catalog context can remain useful longer.
_DEFAULT_TAG_MAX_AGE_HOURS: dict[str, int] = {
    "advertising": 72,
    "cross_site_tracking": 72,
    "analytics": 72,
    "telemetry": 72,
    "crash_reporting": 168,
    "authentication": 72,
    "payments": 48,
    "api_backend": 72,
    "content_media": 168,
    "cdn_shared_infrastructure": 168,
    "software_updates": 24,
    "notifications_messaging": 72,
    "security_antifraud": 12,
    "iot_cloud": 72,
    "malware": 6,
    "phishing": 6,
    "command_and_control": 6,
    "unknown": 24,
}

# Used only when a source is not represented by a configured ResearchProviderOptions entry.
# Normal configured sources use their existing refresh_interval_hours value.
_FALLBACK_SOURCE_MAX_AGE_HOURS: dict[str, int] = {
    "adguard_services": 24,
    "dns_records": 6,
    "disconnect_tracking": 24,
    "rdap": 168,
    "ripestat": 24,
    "netcraft": 168,
    "virustotal": 24,
    "threatfox": 6,
    "phishtank": 1,
    "urlscan": 12,
    "cloudflare_radar": 168,
    "repository_lists": 12,
    "urlhaus": 6,
    "crtsh": 24,
    "google_safe_browsing": 6,
    "compatibility_profile": 8760,
}

_TAG_INSENSITIVE_SOURCES = {"compatibility_profile"}


@dataclass(frozen=True, slots=True)
class EvidenceFreshnessContext:
    domain: str
    tags: tuple[str, ...]
    global_max_age_hours: int
    provider_hours: Mapping[str, int]
    provider_kinds: Mapping[str, str]
    tag_max_age_hours: Mapping[str, int]


@dataclass(frozen=True, slots=True)
class EvidenceFreshnessDecision:
    source_kind: str
    source_max_age_hours: int
    tag_max_age_hours: int | None
    matched_tags: tuple[str, ...]
    effective_max_age_seconds: int
    effective_expires_at: int
    original_expires_at: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "policy_version": POLICY_VERSION,
            "source_kind": self.source_kind,
            "source_max_age_hours": self.source_max_age_hours,
            "tag_max_age_hours": self.tag_max_age_hours,
            "matched_tags": list(self.matched_tags),
            "effective_max_age_seconds": self.effective_max_age_seconds,
            "effective_expires_at": self.effective_expires_at,
            "original_expires_at": self.original_expires_at,
            "rule": "minimum of provider expiry, source refresh interval, and tag ceiling",
        }


def default_tag_max_age_hours() -> dict[str, int]:
    return dict(_DEFAULT_TAG_MAX_AGE_HOURS)


def build_freshness_context(
    domain: str,
    *,
    default_max_age_days: int = 30,
) -> EvidenceFreshnessContext:
    # Lazy import avoids coupling config loading to database module import order.
    from pihole_manager.config import load_options

    options = load_options()
    provider_hours: dict[str, int] = {}
    provider_kinds: dict[str, str] = {}
    for provider in getattr(options, "research_providers", ()):
        name = _provider_key(getattr(provider, "name", ""))
        if not name:
            continue
        provider_hours[name] = max(1, int(getattr(provider, "refresh_interval_hours", 24)))
        provider_kinds[name] = str(getattr(provider, "kind", "") or "").strip().lower()
    global_days = max(
        1,
        int(getattr(getattr(options, "research", None), "max_age_days", default_max_age_days)),
    )
    return EvidenceFreshnessContext(
        domain=_normalize_domain(domain),
        tags=_effective_domain_tags(domain),
        global_max_age_hours=global_days * 24,
        provider_hours=provider_hours,
        provider_kinds=provider_kinds,
        tag_max_age_hours=_DEFAULT_TAG_MAX_AGE_HOURS,
    )


def freshness_decision_for_finding(
    finding: ResearchFinding,
    context: EvidenceFreshnessContext,
) -> EvidenceFreshnessDecision:
    retrieved_at = max(0, int(finding.retrieved_at or 0))
    source_kind = _source_kind(
        provider=finding.provider,
        kind=finding.kind,
        raw_data=finding.raw_data,
        context=context,
    )
    source_hours = _source_hours(finding.provider, source_kind, context)
    tag_hours, matched_tags = _tag_ceiling(source_kind, context)
    effective_hours = min(
        source_hours,
        tag_hours if tag_hours is not None else source_hours,
        context.global_max_age_hours,
    )
    policy_expires_at = retrieved_at + effective_hours * 3600
    original_expires_at = max(0, int(finding.expires_at or 0))
    effective_expires_at = (
        min(original_expires_at, policy_expires_at)
        if original_expires_at > 0
        else policy_expires_at
    )
    return EvidenceFreshnessDecision(
        source_kind=source_kind,
        source_max_age_hours=source_hours,
        tag_max_age_hours=tag_hours,
        matched_tags=matched_tags,
        effective_max_age_seconds=effective_hours * 3600,
        effective_expires_at=effective_expires_at,
        original_expires_at=original_expires_at,
    )


def apply_freshness_policy(
    finding: ResearchFinding,
    context: EvidenceFreshnessContext,
) -> ResearchFinding:
    decision = freshness_decision_for_finding(finding, context)
    raw_data = dict(finding.raw_data or {})
    raw_data["freshness_policy"] = decision.as_dict()
    return replace(
        finding,
        expires_at=decision.effective_expires_at,
        raw_data=raw_data,
    )


def apply_freshness_policies(
    findings: Iterable[ResearchFinding],
    *,
    default_max_age_days: int = 30,
) -> list[ResearchFinding]:
    items = list(findings)
    contexts: dict[str, EvidenceFreshnessContext] = {}
    output: list[ResearchFinding] = []
    for finding in items:
        domain = _normalize_domain(finding.domain)
        context = contexts.get(domain)
        if context is None:
            context = build_freshness_context(
                domain,
                default_max_age_days=default_max_age_days,
            )
            contexts[domain] = context
        output.append(apply_freshness_policy(finding, context))
    return output


def row_is_fresh(
    row: Mapping[str, Any],
    context: EvidenceFreshnessContext,
    *,
    now: int,
) -> bool:
    finding = ResearchFinding(
        domain=str(row.get("domain") or context.domain),
        provider=str(row.get("provider") or ""),
        kind=str(row.get("kind") or "context"),
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
    return freshness_decision_for_finding(finding, context).effective_expires_at > int(now)


def _effective_domain_tags(domain: str) -> tuple[str, ...]:
    normalized = _normalize_domain(domain)
    if not normalized:
        return ()
    with _DB_LOCK, _connection() as connection:
        rows = connection.execute(
            """
            SELECT tag, source FROM domain_tags
            WHERE domain = ?
            ORDER BY CASE source WHEN 'manual' THEN 0 WHEN 'llm' THEN 1 ELSE 2 END, tag
            """,
            (normalized,),
        ).fetchall()
    by_source: dict[str, list[str]] = {}
    for row in rows:
        source = str(row["source"] or "").strip().lower()
        tag = _normalize_tag(row["tag"])
        if tag:
            by_source.setdefault(source, []).append(tag)
    for source in ("manual", "llm", "current"):
        selected = by_source.get(source)
        if selected:
            return tuple(dict.fromkeys(selected))
    remaining = [tag for values in by_source.values() for tag in values]
    return tuple(dict.fromkeys(remaining))


def _tag_ceiling(
    source_kind: str,
    context: EvidenceFreshnessContext,
) -> tuple[int | None, tuple[str, ...]]:
    if source_kind in _TAG_INSENSITIVE_SOURCES:
        return None, ()
    matches = tuple(tag for tag in context.tags if tag in context.tag_max_age_hours)
    if not matches:
        return None, ()
    return min(int(context.tag_max_age_hours[tag]) for tag in matches), matches


def _source_hours(
    provider: str,
    source_kind: str,
    context: EvidenceFreshnessContext,
) -> int:
    configured = context.provider_hours.get(_provider_key(provider))
    if configured is not None:
        return max(1, int(configured))
    fallback = _FALLBACK_SOURCE_MAX_AGE_HOURS.get(source_kind)
    if fallback is not None:
        return max(1, int(fallback))
    return max(1, int(context.global_max_age_hours))


def _source_kind(
    *,
    provider: str,
    kind: str,
    raw_data: Mapping[str, Any],
    context: EvidenceFreshnessContext,
) -> str:
    explicit = str(raw_data.get("wormhole_source_kind") or "").strip().lower()
    if explicit:
        return explicit
    configured = context.provider_kinds.get(_provider_key(provider))
    if configured:
        return configured
    return str(kind or "unknown").strip().lower()


def _provider_key(value: object) -> str:
    return " ".join(str(value or "").strip().casefold().split())


def _normalize_tag(value: object) -> str:
    return str(value or "").strip().lower().replace(" ", "_")
