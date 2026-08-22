from __future__ import annotations

import time
from typing import Any

from pihole_manager.database_core import _DB_LOCK, _connection, _normalize_domain, staging_remove
from pihole_manager.database_review import mark_action_applied, review_resolve
from pihole_manager.models import Policy
from pihole_manager.pihole_service import add_exact_domain, delete_exact_domain, fetch_exact_domains
from pihole_manager.review_preferences import set_review_preference

_VALID_DECISIONS = {"allow", "deny", "postpone", "ignore", "never_ask"}


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


def _exact_rule_exists(domain: str, policy: str) -> bool:
    return any(str(row.get("domain") or "") == domain for row in fetch_exact_domains(policy))


def apply_review_decision(
    domain: str,
    decision: str,
    *,
    postpone_until: int | None = None,
    comment: str = "",
) -> dict[str, Any]:
    normalized = _normalize_domain(domain)
    selected = str(decision or "").strip().lower()
    if not normalized:
        raise ValueError("domain must not be empty")
    if selected not in _VALID_DECISIONS:
        raise ValueError("decision must be allow, deny, postpone, ignore, or never_ask")

    if selected in {"allow", "deny"}:
        policy = Policy.ALLOW if selected == "allow" else Policy.DENY
        opposite = "deny" if selected == "allow" else "allow"
        desired_exists = _exact_rule_exists(normalized, selected)
        opposite_exists = _exact_rule_exists(normalized, opposite)
        if not desired_exists:
            add_exact_domain(
                normalized,
                policy,
                comment=comment.strip() or f"Review decision: {selected}",
            )
        if opposite_exists:
            delete_exact_domain(normalized, opposite)
        mark_action_applied(normalized, selected)
        staging_remove([normalized])
        preference = set_review_preference(normalized, last_decision=selected)
        return {
            "domain": normalized,
            "decision": selected,
            "applied": True,
            "preference": preference,
        }

    if selected == "ignore":
        staging_remove([normalized])
        review_resolve([normalized], decision="ignored")
        preference = set_review_preference(normalized, last_decision="ignore")
        return {
            "domain": normalized,
            "decision": selected,
            "applied": True,
            "preference": preference,
        }

    if selected == "postpone":
        if postpone_until is None:
            raise ValueError("postpone_until is required for postpone")
        postponed = int(postpone_until)
        if postponed <= int(time.time()):
            raise ValueError("postpone_until must be in the future")
        staging_remove([normalized])
        _resolve_open_review_tasks(normalized, "postponed")
        preference = set_review_preference(
            normalized,
            postponed_until=postponed,
            last_decision="postpone",
        )
        return {
            "domain": normalized,
            "decision": selected,
            "applied": True,
            "postpone_until": postponed,
            "preference": preference,
        }

    staging_remove([normalized])
    _resolve_open_review_tasks(normalized, "never_ask")
    preference = set_review_preference(
        normalized,
        never_ask=True,
        last_decision="never_ask",
    )
    return {
        "domain": normalized,
        "decision": selected,
        "applied": True,
        "preference": preference,
    }
