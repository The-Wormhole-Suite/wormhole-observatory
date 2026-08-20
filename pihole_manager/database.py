from __future__ import annotations

from typing import Any

from pihole_manager import database_analysis as _database_analysis
from pihole_manager import database_review as _database_review
from pihole_manager.database_analysis import *  # noqa: F403
from pihole_manager.database_core import *  # noqa: F403
from pihole_manager.database_features import *  # noqa: F403
from pihole_manager.database_features import research_findings_get as _research_findings_get
from pihole_manager.database_review import *  # noqa: F403
from pihole_manager.evidence_citations import attach_evidence_citations
from pihole_manager.manual_tag_overrides import (
    domain_browser_search,
    effective_tags,
    manual_tags,
    review_get,
    review_queue_items,
    set_manual_tags,
)
from pihole_manager.models import Classification


def _with_saved_evidence_citations(classification: Classification) -> Classification:
    findings = _research_findings_get(
        classification.domain,
        fresh_only=True,
        limit=12,
    )
    if not findings:
        # Keep legacy/manual classification writes unchanged when no evidence
        # was collected. Normal analysis runs collect evidence before LLM use.
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
