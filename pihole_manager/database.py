from __future__ import annotations

import time
from collections.abc import Iterable
from typing import Any

from pihole_manager import database_analysis as _database_analysis
from pihole_manager import database_features as _database_features
from pihole_manager import database_review as _database_review
from pihole_manager import manual_tag_overrides as _manual_tag_overrides
from pihole_manager import review_preferences as _review_preferences
from pihole_manager.behavior_change import historical_behavior_change
from pihole_manager.database_analysis import *  # noqa: F403
from pihole_manager.database_core import *  # noqa: F403
from pihole_manager.database_features import *  # noqa: F403
from pihole_manager.database_review import *  # noqa: F403
from pihole_manager.evidence_citations import attach_evidence_citations
from pihole_manager.evidence_freshness import (
    apply_freshness_policies,
    build_freshness_context,
    row_is_fresh,
)
from pihole_manager.manual_tag_overrides import (  # noqa: F401
    domain_browser_search,
    effective_tags,
    manual_tags,
    set_manual_tags,
)
from pihole_manager.models import Classification, ResearchFinding, ReviewPriority
from pihole_manager.review_preferences import (  # noqa: F401
    clear_review_preference,
    preference_blocks_review,
    review_preference_get,
    set_review_preference,
)


def save_research_findings(
    findings: Iterable[ResearchFinding],
    *,
    default_max_age_days: int = 30,
) -> int:
    adjusted = apply_freshness_policies(
        findings,
        default_max_age_days=default_max_age_days,
    )
    return _database_features.save_research_findings(
        adjusted,
        default_max_age_days=default_max_age_days,
    )


def research_findings_get(
    domain: str,
    *,
    fresh_only: bool = False,
    limit: int = 100,
) -> list[dict[str, Any]]:
    safe_limit = max(1, int(limit))
    if not fresh_only:
        return _database_features.research_findings_get(
            domain,
            fresh_only=False,
            limit=safe_limit,
        )
    rows = _database_features.research_findings_get(
        domain,
        fresh_only=False,
        limit=max(500, safe_limit),
    )
    context = build_freshness_context(domain)
    now = int(time.time())
    return [row for row in rows if row_is_fresh(row, context, now=now)][:safe_limit]


def _with_saved_evidence_citations(classification: Classification) -> Classification:
    findings = research_findings_get(
        classification.domain,
        fresh_only=True,
        limit=12,
    )
    if not findings:
        return classification
    return attach_evidence_citations(
        [classification],
        [{"domain": classification.domain, "findings": findings}],
    )[0]


def save_classification_run(classification: Classification, **kwargs: Any) -> int:
    return _database_review.save_classification_run(
        _with_saved_evidence_citations(classification),
        **kwargs,
    )


def review_save_classification(
    classification: Classification,
    status: str = "classified",
    **kwargs: Any,
) -> None:
    _database_review.review_save_classification(
        _with_saved_evidence_citations(classification),
        status=status,
        **kwargs,
    )


def benchmark_result_save(run_id: str, **kwargs: Any) -> None:
    classification = kwargs.get("classification")
    if isinstance(classification, Classification):
        kwargs["classification"] = _with_saved_evidence_citations(classification)
    _database_analysis.benchmark_result_save(run_id, **kwargs)


def domain_details(domain: str) -> dict[str, Any]:
    data = dict(_database_features.domain_details(domain) or {})
    data["behavior_change"] = historical_behavior_change(domain).as_dict()
    return data


def review_get(
    limit: int = 200,
    status: str | None = None,
    needs_review: bool | None = None,
) -> list[dict[str, Any]]:
    rows = _manual_tag_overrides.review_get(
        limit=limit,
        status=status,
        needs_review=needs_review,
    )
    return _review_preferences.apply_review_preferences(
        rows,
        hide_blocked=needs_review is True,
    )


def review_queue_get(limit: int = 2_000) -> list[dict[str, Any]]:
    rows = _database_review.review_queue_get(limit=limit)
    filtered = _review_preferences.apply_review_preferences(rows, hide_blocked=True)
    return filtered[: max(1, int(limit))]


def review_queue_items(limit: int = 500) -> list[dict[str, Any]]:
    rows = _manual_tag_overrides.review_queue_items(limit=limit)
    filtered = _review_preferences.apply_review_preferences(rows, hide_blocked=True)
    return filtered[: max(1, int(limit))]


def create_review_task(
    domain: str,
    reason: str,
    *,
    priority: ReviewPriority | str = ReviewPriority.NORMAL,
    source: str = "",
) -> int:
    if _review_preferences.preference_blocks_review(domain):
        return 0
    return _database_features.create_review_task(
        domain,
        reason,
        priority=priority,
        source=source,
    )
