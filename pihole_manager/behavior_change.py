from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any

from pihole_manager.database_core import _DB_LOCK, _connection, _normalize_domain
from pihole_manager.models import Classification

_HISTORY_LIMIT = 6
_REVIEW_SCORE = 35
_HIGH_SCORE = 50
_CRITICAL_SCORE = 75


@dataclass(frozen=True, slots=True)
class BehaviorChangeSignal:
    field: str
    previous: Any
    current: Any
    score: int
    severity: str
    summary: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "field": self.field,
            "previous": self.previous,
            "current": self.current,
            "score": self.score,
            "severity": self.severity,
            "summary": self.summary,
        }


@dataclass(frozen=True, slots=True)
class BehaviorChangeReport:
    domain: str
    has_history: bool
    score: int = 0
    severity: str = "none"
    requires_review: bool = False
    previous_run_id: int = 0
    previous_created_at: int = 0
    previous_provider: str = ""
    previous_model: str = ""
    previous_profile: str = ""
    baseline_consistency: float = 0.0
    signals: tuple[BehaviorChangeSignal, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "has_history": self.has_history,
            "score": self.score,
            "severity": self.severity,
            "requires_review": self.requires_review,
            "previous_run_id": self.previous_run_id,
            "previous_created_at": self.previous_created_at,
            "previous_provider": self.previous_provider,
            "previous_model": self.previous_model,
            "previous_profile": self.previous_profile,
            "baseline_consistency": round(self.baseline_consistency, 3),
            "signals": [signal.as_dict() for signal in self.signals],
            "metadata": dict(self.metadata),
        }

    def prompt_context(self, *, max_signals: int = 6) -> dict[str, Any]:
        return {
            "has_history": self.has_history,
            "score": self.score,
            "severity": self.severity,
            "requires_review": self.requires_review,
            "baseline_consistency": round(self.baseline_consistency, 3),
            "signals": [
                {
                    "field": signal.field,
                    "severity": signal.severity,
                    "summary": signal.summary,
                }
                for signal in self.signals[: max(0, int(max_signals))]
            ],
        }

    @property
    def review_reason(self) -> str:
        if not self.requires_review:
            return ""
        summaries = "; ".join(signal.summary for signal in self.signals[:3])
        suffix = f" Key changes: {summaries}." if summaries else ""
        return (
            f"Historical behavior-change signal ({self.severity}, score {self.score}/100)."
            f"{suffix} Review before applying an automatic Pi-hole change."
        )


def behavior_change_for_classification(
    classification: Classification,
) -> BehaviorChangeReport:
    domain = _normalize_domain(classification.domain)
    rows = _primary_history(domain, limit=_HISTORY_LIMIT)
    if not rows:
        return BehaviorChangeReport(domain=domain, has_history=False)
    previous = rows[0]
    current = _classification_snapshot(classification)
    return _compare_snapshots(domain, previous, current, history=rows)


def historical_behavior_change(domain: str) -> BehaviorChangeReport:
    normalized = _normalize_domain(domain)
    rows = _primary_history(normalized, limit=_HISTORY_LIMIT + 1)
    if len(rows) < 2:
        return BehaviorChangeReport(
            domain=normalized,
            has_history=bool(rows),
            previous_run_id=int(rows[0].get("id") or 0) if rows else 0,
            previous_created_at=int(rows[0].get("created_at") or 0) if rows else 0,
        )
    current = rows[0]
    previous = rows[1]
    return _compare_snapshots(normalized, previous, current, history=rows[1:])


def apply_behavior_change_guard(
    classification: Classification,
    report: BehaviorChangeReport | None = None,
) -> Classification:
    selected = report or behavior_change_for_classification(classification)
    if not selected.requires_review:
        return classification
    reason = selected.review_reason
    if classification.review_reason:
        if reason in classification.review_reason:
            combined = classification.review_reason
        else:
            combined = f"{classification.review_reason} {reason}"
    else:
        combined = reason
    return replace(classification, needs_review=True, review_reason=combined)


def _compare_snapshots(
    domain: str,
    previous: Mapping[str, Any],
    current: Mapping[str, Any],
    *,
    history: Sequence[Mapping[str, Any]],
) -> BehaviorChangeReport:
    signals: list[BehaviorChangeSignal] = []

    previous_policy = str(previous.get("policy") or "unknown").lower()
    current_policy = str(current.get("policy") or "unknown").lower()
    if previous_policy != current_policy:
        decisive = {previous_policy, current_policy} <= {"allow", "deny"}
        score = 45 if decisive else 22
        severity = "high" if decisive else "medium"
        signals.append(
            BehaviorChangeSignal(
                "policy",
                previous_policy,
                current_policy,
                score,
                severity,
                f"policy changed from {previous_policy} to {current_policy}",
            )
        )

    previous_service = _service_name(previous.get("service"))
    current_service = _service_name(current.get("service"))
    if previous_service and current_service and previous_service != current_service:
        signals.append(
            BehaviorChangeSignal(
                "service",
                str(previous.get("service") or ""),
                str(current.get("service") or ""),
                25,
                "high",
                "classified service identity changed",
            )
        )

    previous_role = str(previous.get("service_role") or "unknown").lower()
    current_role = str(current.get("service_role") or "unknown").lower()
    if previous_role != current_role:
        critical_boundary = _role_class(previous_role) != _role_class(current_role)
        score = 30 if critical_boundary else 12
        signals.append(
            BehaviorChangeSignal(
                "service_role",
                previous_role,
                current_role,
                score,
                "high" if critical_boundary else "medium",
                f"service role changed from {previous_role} to {current_role}",
            )
        )

    _risk_signal(signals, "security_risk", previous, current, high_delta=25, medium_delta=12)
    _risk_signal(signals, "privacy_risk", previous, current, high_delta=30, medium_delta=15)
    _risk_signal(signals, "breakage_risk", previous, current, high_delta=30, medium_delta=15)

    previous_tag = str(previous.get("primary_tag") or previous.get("category") or "unknown")
    current_tag = str(current.get("primary_tag") or current.get("category") or "unknown")
    if previous_tag != current_tag:
        signals.append(
            BehaviorChangeSignal(
                "primary_tag",
                previous_tag,
                current_tag,
                10,
                "medium",
                f"primary tag changed from {previous_tag} to {current_tag}",
            )
        )

    previous_tags = set(_tags(previous))
    current_tags = set(_tags(current))
    if previous_tags and current_tags and previous_tags != current_tags:
        overlap = len(previous_tags & current_tags) / len(previous_tags | current_tags)
        if overlap < 0.25:
            signals.append(
                BehaviorChangeSignal(
                    "tags",
                    sorted(previous_tags),
                    sorted(current_tags),
                    18,
                    "high",
                    "tag set changed substantially",
                )
            )
        elif overlap < 0.6:
            signals.append(
                BehaviorChangeSignal(
                    "tags",
                    sorted(previous_tags),
                    sorted(current_tags),
                    8,
                    "medium",
                    "tag set changed materially",
                )
            )

    score = min(100, sum(signal.score for signal in signals))
    severity = _severity(score)
    hard_review = any(
        signal.field == "policy" and signal.severity == "high" for signal in signals
    ) or any(
        signal.field == "service_role" and signal.severity == "high" for signal in signals
    ) or any(
        signal.field == "security_risk"
        and int(signal.current) - int(signal.previous) >= 25
        for signal in signals
    )
    requires_review = hard_review or score >= _REVIEW_SCORE
    consistency = _baseline_consistency(previous, history)
    return BehaviorChangeReport(
        domain=domain,
        has_history=True,
        score=score,
        severity=severity,
        requires_review=requires_review,
        previous_run_id=int(previous.get("id") or 0),
        previous_created_at=int(previous.get("created_at") or 0),
        previous_provider=str(previous.get("provider") or ""),
        previous_model=str(previous.get("model") or ""),
        previous_profile=str(previous.get("profile") or ""),
        baseline_consistency=consistency,
        signals=tuple(sorted(signals, key=lambda item: (-item.score, item.field))),
        metadata={
            "comparison": "latest_primary_classification",
            "secondary_runs_ignored": True,
        },
    )


def _risk_signal(
    signals: list[BehaviorChangeSignal],
    field: str,
    previous: Mapping[str, Any],
    current: Mapping[str, Any],
    *,
    high_delta: int,
    medium_delta: int,
) -> None:
    before = _integer(previous.get(field))
    after = _integer(current.get(field))
    delta = abs(after - before)
    if delta < medium_delta:
        return
    high = delta >= high_delta
    score = 22 if high else 10
    direction = "increased" if after > before else "decreased"
    signals.append(
        BehaviorChangeSignal(
            field,
            before,
            after,
            score,
            "high" if high else "medium",
            f"{field.replace('_', ' ')} {direction} from {before} to {after}",
        )
    )


def _primary_history(domain: str, *, limit: int) -> list[dict[str, Any]]:
    if not domain:
        return []
    try:
        with _DB_LOCK, _connection() as connection:
            rows = connection.execute(
                """
                SELECT * FROM classification_runs
                WHERE domain = ? AND is_primary = 1
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (domain, max(1, int(limit))),
            ).fetchall()
    except sqlite3.OperationalError:
        return []
    output: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        try:
            item["tags"] = json.loads(str(item.get("tags_json") or "[]"))
        except (json.JSONDecodeError, TypeError):
            item["tags"] = []
        output.append(item)
    return output


def _classification_snapshot(classification: Classification) -> dict[str, Any]:
    tags = list(dict.fromkeys(classification.tags or (classification.category,)))
    return {
        "policy": classification.policy.value,
        "primary_tag": classification.category,
        "tags": tags,
        "service": classification.service,
        "service_role": classification.service_role.value,
        "privacy_risk": classification.privacy_risk,
        "security_risk": classification.security_risk,
        "breakage_risk": classification.breakage_risk,
        "confidence": classification.confidence,
    }


def _baseline_consistency(
    baseline: Mapping[str, Any], history: Sequence[Mapping[str, Any]]
) -> float:
    selected = list(history[:5])
    if not selected:
        return 0.0
    signature = _stable_signature(baseline)
    matches = sum(1 for item in selected if _stable_signature(item) == signature)
    return matches / len(selected)


def _stable_signature(item: Mapping[str, Any]) -> tuple[str, str, str, tuple[str, ...]]:
    return (
        str(item.get("policy") or "unknown").lower(),
        _service_name(item.get("service")),
        str(item.get("service_role") or "unknown").lower(),
        tuple(sorted(_tags(item))),
    )


def _tags(item: Mapping[str, Any]) -> tuple[str, ...]:
    value = item.get("tags")
    if isinstance(value, (list, tuple, set)):
        return tuple(
            dict.fromkeys(
                str(tag).strip().lower().replace(" ", "_")
                for tag in value
                if str(tag).strip()
            )
        )
    raw = item.get("tags_json")
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = []
        if isinstance(parsed, list):
            return tuple(str(tag).strip().lower() for tag in parsed if str(tag).strip())
    return ()


def _role_class(role: str) -> str:
    return "protected" if role in {"core", "shared"} else "non_protected"


def _service_name(value: object) -> str:
    return " ".join(str(value or "").strip().casefold().split())


def _integer(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _severity(score: int) -> str:
    if score >= _CRITICAL_SCORE:
        return "critical"
    if score >= _HIGH_SCORE:
        return "high"
    if score >= _REVIEW_SCORE:
        return "medium"
    if score > 0:
        return "low"
    return "none"
