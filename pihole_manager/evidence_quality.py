from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from pihole_manager.models import ResearchFinding

_SOURCE_BASE_SCORES: dict[str, float] = {
    "phishtank": 0.99,
    "threatfox": 0.97,
    "virustotal": 0.93,
    "disconnect_tracking": 0.92,
    "adguard_services": 0.90,
    "rdap": 0.89,
    "dns_records": 0.87,
    "ripestat": 0.85,
    "cloudflare_radar": 0.84,
    "urlscan": 0.80,
    "netcraft": 0.70,
    "hagezi_tif_mini": 0.92,
    "easyprivacy_trackingservers": 0.91,
    "urlhaus": 0.99,
    "crtsh": 0.94,
    "google_safe_browsing": 0.99,
}

_EVIDENCE_KIND_TO_SOURCE_KIND: dict[str, str] = {
    "phishing_database": "phishtank",
    "ioc_database": "threatfox",
    "threat_intelligence": "virustotal",
    "tracker_catalog": "disconnect_tracking",
    "service_catalog": "adguard_services",
    "registration": "rdap",
    "dns_records": "dns_records",
    "network_routing": "ripestat",
    "domain_popularity": "cloudflare_radar",
    "archived_web_scan": "urlscan",
    "site_infrastructure": "netcraft",
    "malware_url_host": "urlhaus",
}

# Contradictions are intentionally conservative. Missing detections are not evidence of safety,
# so verdicts such as ``no_detection`` and ``no_match`` remain neutral instead of contradicting
# malicious findings.
_VERDICT_STANCES: dict[str, tuple[str, str, float]] = {
    "malicious": ("security", "harmful", 1.0),
    "phishing": ("security", "harmful", 1.0),
    "malware": ("security", "harmful", 1.0),
    "command_and_control": ("security", "harmful", 1.0),
    "malicious_scan": ("security", "harmful", 0.85),
    "suspicious": ("security", "harmful", 0.65),
    "benign": ("security", "safe", 1.0),
    "safe": ("security", "safe", 1.0),
    "clean": ("security", "safe", 0.9),
    "trusted": ("security", "safe", 0.9),
    "advertising": ("privacy", "tracking", 0.9),
    "analytics": ("privacy", "tracking", 0.85),
    "cross_site_tracking": ("privacy", "tracking", 1.0),
    "email_tracking": ("privacy", "tracking", 0.9),
    "social_tracking": ("privacy", "tracking", 0.8),
    "tracker": ("privacy", "tracking", 0.85),
    "non_tracking": ("privacy", "non_tracking", 0.9),
    "privacy_safe": ("privacy", "non_tracking", 1.0),
}

_OPPOSING_STANCES = {
    ("harmful", "safe"),
    ("safe", "harmful"),
    ("tracking", "non_tracking"),
    ("non_tracking", "tracking"),
}


@dataclass(frozen=True, slots=True)
class EvidenceQualityScore:
    source_kind: str
    source_score: float
    evidence_score: float
    tier: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_kind": self.source_kind,
            "source_score": round(self.source_score, 3),
            "evidence_score": round(self.evidence_score, 3),
            "tier": self.tier,
        }


@dataclass(frozen=True, slots=True)
class EvidenceContradiction:
    dimension: str
    left_provider: str
    left_verdict: str
    right_provider: str
    right_verdict: str
    severity: str
    confidence: float
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "dimension": self.dimension,
            "left_provider": self.left_provider,
            "left_verdict": self.left_verdict,
            "right_provider": self.right_provider,
            "right_verdict": self.right_verdict,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "reason": self.reason,
        }


def annotate_source_kind(finding: ResearchFinding, source_kind: str) -> ResearchFinding:
    normalized = source_kind.strip().lower()
    if not normalized:
        return finding
    raw_data = dict(finding.raw_data)
    raw_data.setdefault("wormhole_source_kind", normalized)
    return replace(finding, raw_data=raw_data)


def source_kind_for(finding: ResearchFinding | Mapping[str, Any]) -> str:
    raw_data = _raw_data(finding)
    explicit = str(raw_data.get("wormhole_source_kind") or "").strip().lower()
    if explicit:
        return explicit
    kind = str(_value(finding, "kind", "") or "").strip().lower()
    return _EVIDENCE_KIND_TO_SOURCE_KIND.get(kind, kind or "unknown")


def score_finding(
    finding: ResearchFinding | Mapping[str, Any],
    *,
    now: int | None = None,
) -> EvidenceQualityScore:
    source_kind = source_kind_for(finding)
    source_score = _SOURCE_BASE_SCORES.get(source_kind, 0.65)
    confidence = _clamp(_as_float(_value(finding, "confidence", 0.0)))
    evidence_score = source_score * 0.65 + confidence * 0.35
    expires_at = _as_int(_value(finding, "expires_at", 0))
    current = int(time.time()) if now is None else int(now)
    if expires_at > 0 and expires_at < current:
        evidence_score *= 0.75
    evidence_score = _clamp(evidence_score)
    return EvidenceQualityScore(
        source_kind=source_kind,
        source_score=source_score,
        evidence_score=evidence_score,
        tier=_quality_tier(evidence_score),
    )


def detect_contradictions(
    findings: Sequence[ResearchFinding | Mapping[str, Any]],
) -> list[EvidenceContradiction]:
    candidates: list[tuple[ResearchFinding | Mapping[str, Any], str, str, float]] = []
    for finding in findings:
        verdict = str(_value(finding, "verdict", "") or "").strip().lower()
        stance = _VERDICT_STANCES.get(verdict)
        if stance is None:
            continue
        dimension, side, strength = stance
        signal_type = str(_value(finding, "signal_type", "") or "").strip().lower()
        if signal_type and signal_type not in {dimension, "behavior"}:
            continue
        candidates.append((finding, dimension, side, strength))

    contradictions: list[EvidenceContradiction] = []
    seen: set[tuple[str, str, str]] = set()
    for index, (left, dimension, left_side, left_strength) in enumerate(candidates):
        for right, right_dimension, right_side, right_strength in candidates[index + 1 :]:
            if dimension != right_dimension or (left_side, right_side) not in _OPPOSING_STANCES:
                continue
            left_provider = str(_value(left, "provider", "Unknown source") or "Unknown source")
            right_provider = str(_value(right, "provider", "Unknown source") or "Unknown source")
            left_verdict = str(_value(left, "verdict", "unknown") or "unknown").strip().lower()
            right_verdict = str(_value(right, "verdict", "unknown") or "unknown").strip().lower()
            key = (
                dimension,
                *sorted(
                    (
                        f"{left_provider.casefold()}\0{left_verdict}",
                        f"{right_provider.casefold()}\0{right_verdict}",
                    )
                ),
            )
            if key in seen:
                continue
            seen.add(key)
            left_quality = score_finding(left).evidence_score
            right_quality = score_finding(right).evidence_score
            confidence = min(left_quality, right_quality, left_strength, right_strength)
            severity = _contradiction_severity(confidence)
            contradictions.append(
                EvidenceContradiction(
                    dimension=dimension,
                    left_provider=left_provider,
                    left_verdict=left_verdict,
                    right_provider=right_provider,
                    right_verdict=right_verdict,
                    severity=severity,
                    confidence=confidence,
                    reason=(
                        f"{left_provider} reports {left_verdict}, while {right_provider} "
                        f"reports {right_verdict}."
                    ),
                )
            )
    order = {"high": 0, "medium": 1, "low": 2}
    contradictions.sort(
        key=lambda item: (
            order[item.severity],
            -item.confidence,
            item.dimension,
            item.left_provider.casefold(),
            item.right_provider.casefold(),
        )
    )
    return contradictions


def quality_summary(
    findings: Sequence[ResearchFinding | Mapping[str, Any]],
    contradictions: Sequence[EvidenceContradiction] | None = None,
) -> dict[str, Any]:
    scores = [score_finding(item) for item in findings]
    detected = (
        list(contradictions)
        if contradictions is not None
        else detect_contradictions(findings)
    )
    if scores:
        average_source = sum(item.source_score for item in scores) / len(scores)
        average_evidence = sum(item.evidence_score for item in scores) / len(scores)
    else:
        average_source = 0.0
        average_evidence = 0.0
    return {
        "average_source_score": round(average_source, 3),
        "average_evidence_score": round(average_evidence, 3),
        "high_quality_count": sum(1 for item in scores if item.evidence_score >= 0.8),
        "contradiction_count": len(detected),
        "high_severity_contradiction_count": sum(
            1 for item in detected if item.severity == "high"
        ),
    }


def _quality_tier(score: float) -> str:
    if score >= 0.9:
        return "very_high"
    if score >= 0.8:
        return "high"
    if score >= 0.65:
        return "medium"
    return "low"


def _contradiction_severity(confidence: float) -> str:
    if confidence >= 0.8:
        return "high"
    if confidence >= 0.6:
        return "medium"
    return "low"


def _value(finding: ResearchFinding | Mapping[str, Any], key: str, default: Any) -> Any:
    if isinstance(finding, Mapping):
        return finding.get(key, default)
    return getattr(finding, key, default)


def _raw_data(finding: ResearchFinding | Mapping[str, Any]) -> Mapping[str, Any]:
    raw_data = _value(finding, "raw_data", {})
    return raw_data if isinstance(raw_data, Mapping) else {}


def _as_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))
