from __future__ import annotations

import time
from typing import Any

from pihole_manager.application.review_decisions import (
    VALID_REVIEW_DECISIONS,
    InvalidReviewDecision,
    ReviewDecisionApplicationService,
    ReviewDecisionCommand,
    ReviewDecisionConflict,
    ReviewDecisionPorts,
    ReviewDecisionResult,
)
from pihole_manager.database_core import _DB_LOCK, _connection, staging_remove
from pihole_manager.database_review import mark_action_applied, review_resolve
from pihole_manager.pihole_service import add_exact_domain, delete_exact_domain, fetch_exact_domains
from pihole_manager.review_preferences import set_review_preference

# Backward-compatible private name retained for callers/tests that imported the old module contract.
_VALID_DECISIONS = VALID_REVIEW_DECISIONS


def _resolve_open_review_tasks(domain: str, decision: str) -> None:
    now = int(time.time())
    with _DB_LOCK, _connection() as connection:
        connection.execute(
            """
            UPDATE review_tasks
            SET status = 'resolved', decision = ?, updated_at = ?
            WHERE status = 'open' AND domain = ?
            """,
            (decision, now, domain),
        )


def _application_service() -> ReviewDecisionApplicationService:
    """Wire infrastructure ports without leaking them into frontend code.

    Ports are assembled per call so existing tests and integrations can safely
    substitute module operations while all decision behavior stays in the
    frontend-neutral application service.
    """

    return ReviewDecisionApplicationService(
        ReviewDecisionPorts(
            fetch_exact_domains=fetch_exact_domains,
            add_exact_domain=add_exact_domain,
            delete_exact_domain=delete_exact_domain,
            mark_action_applied=mark_action_applied,
            staging_remove=staging_remove,
            resolve_review=review_resolve,
            set_review_preference=set_review_preference,
            resolve_open_review_tasks=_resolve_open_review_tasks,
            clock=time.time,
        )
    )


def execute_review_decision(command: ReviewDecisionCommand) -> ReviewDecisionResult:
    """Execute a typed review command through the canonical application service."""

    return _application_service().execute(command)


def apply_review_decision(
    domain: str,
    decision: str,
    *,
    postpone_until: int | None = None,
    comment: str = "",
) -> dict[str, Any]:
    """Compatibility adapter for primitive callers.

    New frontend code should prefer ``execute_review_decision`` with a
    ``ReviewDecisionCommand``. Existing integrations retain the legacy dict
    response while sharing the exact same application behavior.
    """

    return execute_review_decision(
        ReviewDecisionCommand(
            domain=domain,
            decision=decision,
            postpone_until=postpone_until,
            comment=comment,
        )
    ).to_dict()


__all__ = [
    "InvalidReviewDecision",
    "ReviewDecisionCommand",
    "ReviewDecisionConflict",
    "ReviewDecisionResult",
    "apply_review_decision",
    "execute_review_decision",
]
