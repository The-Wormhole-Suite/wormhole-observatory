from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterable
from typing import Any

from pihole_manager.database_core import (
    _DB_LOCK,
    _connection,
    _ensure_domain,
    _normalize_domain,
    _normalize_tags,
    staging_list,
)
from pihole_manager.models import Classification

# ---------- Current review and classification history ----------


def review_save(
    domain: str,
    categories: object,
    details: str,
    status: str = "edited",
    *,
    policy: str = "unknown",
    short: str = "",
    provider: str = "",
    service: str = "",
    service_role: str = "unknown",
    privacy_risk: int = 0,
    security_risk: int = 0,
    breakage_risk: int = 50,
    confidence: float = 0.0,
    needs_review: bool = True,
    review_reason: str = "",
    next_recheck_at: int | None = None,
    planned_action: str = "",
    action_status: str = "none",
) -> None:
    now = int(time.time())
    with _DB_LOCK, _connection() as connection:
        _review_save(
            connection,
            domain,
            categories,
            details,
            status,
            policy=policy,
            short=short,
            provider=provider,
            service=service,
            service_role=service_role,
            privacy_risk=privacy_risk,
            security_risk=security_risk,
            breakage_risk=breakage_risk,
            confidence=confidence,
            needs_review=needs_review,
            review_reason=review_reason,
            next_recheck_at=next_recheck_at,
            planned_action=planned_action,
            action_status=action_status,
            now=now,
        )


def _review_save(
    connection: sqlite3.Connection,
    domain: str,
    categories: object,
    details: str,
    status: str,
    *,
    policy: str,
    short: str,
    provider: str,
    service: str,
    service_role: str,
    privacy_risk: int,
    security_risk: int,
    breakage_risk: int,
    confidence: float,
    needs_review: bool,
    review_reason: str,
    next_recheck_at: int | None,
    planned_action: str,
    action_status: str,
    now: int,
) -> None:
    tags = _normalize_tags(categories)
    normalized = _ensure_domain(connection, domain, seen_at=now)
    connection.execute(
        """
        INSERT INTO review(
            domain, categories, policy, short, details, provider, status,
            service, service_role, privacy_risk, security_risk, breakage_risk,
            confidence, needs_review, review_reason, next_recheck_at,
            planned_action, action_status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(domain) DO UPDATE SET
            categories = excluded.categories,
            policy = excluded.policy,
            short = excluded.short,
            details = excluded.details,
            provider = excluded.provider,
            status = excluded.status,
            service = excluded.service,
            service_role = excluded.service_role,
            privacy_risk = excluded.privacy_risk,
            security_risk = excluded.security_risk,
            breakage_risk = excluded.breakage_risk,
            confidence = excluded.confidence,
            needs_review = excluded.needs_review,
            review_reason = excluded.review_reason,
            next_recheck_at = excluded.next_recheck_at,
            planned_action = excluded.planned_action,
            action_status = excluded.action_status,
            updated_at = excluded.updated_at
        """,
        (
            normalized,
            ",".join(tags),
            policy.strip().lower() or "unknown",
            short.strip(),
            details.strip(),
            provider.strip(),
            status.strip() or "edited",
            service.strip(),
            service_role.strip().lower() or "unknown",
            _risk(privacy_risk),
            _risk(security_risk),
            _risk(breakage_risk),
            _confidence(confidence),
            int(bool(needs_review)),
            review_reason.strip(),
            next_recheck_at,
            _normalize_planned_action(planned_action),
            _normalize_action_status(action_status),
            now,
            now,
        ),
    )
    connection.execute(
        """
        UPDATE domains SET
            current_policy = ?, current_service = ?, current_service_role = ?,
            next_recheck_at = COALESCE(?, next_recheck_at)
        WHERE domain = ?
        """,
        (
            policy.strip().lower() or "unknown",
            service.strip(),
            service_role.strip().lower() or "unknown",
            next_recheck_at,
            normalized,
        ),
    )
    _replace_source_tags(connection, normalized, tags, "current", confidence, now)


def save_classification_run(
    classification: Classification,
    *,
    model: str = "",
    profile: str = "",
    prompt_hash: str = "",
    status: str = "classified",
    planned_action: str = "",
    action_status: str = "none",
) -> int:
    now = int(time.time())
    expires_at = now + max(1, int(classification.recheck_after_days)) * 86400
    tags = _normalize_tags(classification.tags or (classification.category,))
    if classification.category and classification.category not in tags:
        tags.insert(0, classification.category)
    normalized_action_status = _normalize_action_status(action_status)

    with _DB_LOCK, _connection() as connection:
        domain = _ensure_domain(connection, classification.domain, seen_at=now)
        cursor = connection.execute(
            """
            INSERT INTO classification_runs(
                domain, provider, model, profile, prompt_hash, policy, primary_tag,
                tags_json, service, service_role, privacy_risk, security_risk,
                breakage_risk, confidence, needs_review, review_reason, short,
                details, raw_text, planned_action, action_status, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                domain,
                classification.provider,
                model,
                profile,
                prompt_hash,
                classification.policy.value,
                classification.category,
                json.dumps(tags, ensure_ascii=False),
                classification.service,
                classification.service_role.value,
                _risk(classification.privacy_risk),
                _risk(classification.security_risk),
                _risk(classification.breakage_risk),
                _confidence(classification.confidence),
                int(classification.needs_review),
                classification.review_reason,
                classification.short,
                classification.details,
                classification.raw_text,
                _normalize_planned_action(planned_action),
                _normalize_action_status(action_status),
                now,
                expires_at,
            ),
        )
        connection.execute(
            """
            UPDATE domains SET
                last_classified_at = ?, next_recheck_at = ?, current_policy = ?,
                current_service = ?, current_service_role = ?
            WHERE domain = ?
            """,
            (
                now,
                expires_at,
                classification.policy.value,
                classification.service,
                classification.service_role.value,
                domain,
            ),
        )
        _replace_source_tags(
            connection,
            domain,
            tags,
            "llm",
            classification.confidence,
            now,
        )
        _review_save(
            connection,
            classification.domain,
            tags,
            classification.details,
            status,
            policy=classification.policy.value,
            short=classification.short,
            provider=classification.provider,
            service=classification.service,
            service_role=classification.service_role.value,
            privacy_risk=classification.privacy_risk,
            security_risk=classification.security_risk,
            breakage_risk=classification.breakage_risk,
            confidence=classification.confidence,
            needs_review=classification.needs_review or normalized_action_status == "simulated",
            review_reason=(
                f"Simulation mode prevented automatic {planned_action}."
                if normalized_action_status == "simulated"
                else classification.review_reason
            ),
            next_recheck_at=expires_at,
            planned_action=planned_action,
            action_status=action_status,
            now=now,
        )
        run_id = cursor.lastrowid
    if run_id is None:
        raise RuntimeError("Classification run was saved without an identifier")
    return run_id


def review_save_classification(
    classification: Classification,
    status: str = "classified",
    *,
    model: str = "",
    profile: str = "",
    prompt_hash: str = "",
    planned_action: str = "",
    action_status: str = "none",
) -> None:
    save_classification_run(
        classification,
        model=model,
        profile=profile,
        prompt_hash=prompt_hash,
        status=status,
        planned_action=planned_action,
        action_status=action_status,
    )


def review_queue_get(limit: int = 2_000) -> list[dict[str, Any]]:
    """Return pending review rows together with durable analysis-queue items."""
    review_rows = review_get(limit=limit, needs_review=True)
    combined = {str(row["domain"]): dict(row) for row in review_rows}
    staging_rows = staging_list(limit=limit)

    for queued in staging_rows:
        domain = str(queued.get("domain") or "")
        state = str(queued.get("state") or "queued")
        source = str(queued.get("source") or "")
        error = str(queued.get("last_error") or "")
        existing = combined.get(domain)
        if existing is None:
            existing = {
                "domain": domain,
                "categories": [],
                "tags": [],
                "policy": "unknown",
                "short": error or _queue_summary(state, source),
                "details": error,
                "provider": "",
                "status": state,
                "service": "",
                "service_role": "unknown",
                "privacy_risk": 0,
                "security_risk": 0,
                "breakage_risk": None,
                "confidence": 0.0,
                "needs_review": True,
                "review_reason": "",
                "planned_action": "",
                "action_status": "none",
                "locked": False,
            }
            combined[domain] = existing
        else:
            existing["status"] = state
            if error:
                existing["short"] = error
                existing["details"] = error
        existing["queue_source"] = source
        existing["queue_state"] = state
        existing["queue_error"] = error
        existing["queue_priority"] = int(queued.get("priority") or 0)
        existing["queue_created_at"] = int(queued.get("created_at") or 0)

    def sort_key(row: dict[str, Any]) -> tuple[int, int, int, str]:
        state = str(row.get("queue_state") or "")
        state_rank = {"failed": 0, "processing": 1, "queued": 2}.get(state, 3)
        priority = -int(row.get("queue_priority") or 0)
        created_at = int(row.get("queue_created_at") or row.get("updated_at") or 0)
        return (state_rank, priority, created_at, str(row.get("domain") or ""))

    return sorted(combined.values(), key=sort_key)[: max(1, int(limit))]


def _queue_summary(state: str, _source: str) -> str:
    if state == "processing":
        return "Analysis in progress."
    if state == "failed":
        return "Analysis failed. Queue the domain again after correcting the error."
    return "Not analyzed."


def review_get(
    limit: int = 200,
    status: str | None = None,
    needs_review: bool | None = None,
) -> list[dict[str, Any]]:
    query = """
        SELECT r.*, l.list_type AS lock_type, l.reason AS lock_reason
        FROM review r
        LEFT JOIN domain_locks l ON l.domain = r.domain
    """
    clauses: list[str] = []
    parameters: list[Any] = []
    if status:
        clauses.append("r.status = ?")
        parameters.append(status)
    if needs_review is not None:
        clauses.append("r.needs_review = ?")
        parameters.append(int(needs_review))
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY r.updated_at DESC LIMIT ?"
    parameters.append(max(1, int(limit)))
    with _DB_LOCK, _connection() as connection:
        rows = connection.execute(query, parameters).fetchall()
    output: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["categories"] = _normalize_tags(item.get("categories") or "")
        item["tags"] = list(item["categories"])
        item["needs_review"] = bool(item.get("needs_review", 1))
        item["locked"] = bool(item.get("lock_type"))
        output.append(item)
    return output


def mark_action_applied(domain: str, action: str) -> None:
    normalized = _normalize_domain(domain)
    normalized_action = _normalize_planned_action(action)
    if not normalized or not normalized_action:
        raise ValueError("domain and action must be valid")
    now = int(time.time())
    with _DB_LOCK, _connection() as connection:
        connection.execute(
            """
            UPDATE review
            SET planned_action = ?, action_status = 'applied', needs_review = 0,
                review_reason = '', status = 'manually_applied', updated_at = ?
            WHERE domain = ?
            """,
            (normalized_action, now, normalized),
        )
        connection.execute(
            """
            UPDATE review_tasks
            SET status = 'resolved', decision = ?, updated_at = ?
            WHERE status = 'open' AND domain = ?
            """,
            (f"applied_{normalized_action}", now, normalized),
        )


def _normalize_planned_action(value: str) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in {"allow", "deny"} else ""


def _normalize_action_status(value: str) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in {"none", "simulated", "applied", "dismissed"} else "none"


def review_resolve(domains: Iterable[str], decision: str = "dismissed") -> int:
    normalized = [_normalize_domain(domain) for domain in domains if _normalize_domain(domain)]
    if not normalized:
        return 0
    placeholders = ",".join("?" for _ in normalized)
    now = int(time.time())
    with _DB_LOCK, _connection() as connection:
        cursor = connection.execute(
            f"""
            UPDATE review
            SET needs_review = 0, review_reason = '', status = 'reviewed',
                action_status = CASE
                    WHEN action_status = 'simulated' THEN 'dismissed'
                    ELSE action_status
                END,
                updated_at = ?
            WHERE domain IN ({placeholders})
            """,
            (now, *normalized),
        )
        connection.execute(
            f"""
            UPDATE review_tasks
            SET status = 'resolved', decision = ?, updated_at = ?
            WHERE status = 'open' AND domain IN ({placeholders})
            """,
            (decision.strip() or "dismissed", now, *normalized),
        )
    return cursor.rowcount


def review_delete(domains: Iterable[str]) -> int:
    normalized = [_normalize_domain(domain) for domain in domains if _normalize_domain(domain)]
    if not normalized:
        return 0
    placeholders = ",".join("?" for _ in normalized)
    with _DB_LOCK, _connection() as connection:
        cursor = connection.execute(
            f"DELETE FROM review WHERE domain IN ({placeholders})", normalized
        )
    return cursor.rowcount


def classification_history(domain: str, limit: int = 50) -> list[dict[str, Any]]:
    with _DB_LOCK, _connection() as connection:
        rows = connection.execute(
            """
            SELECT * FROM classification_runs
            WHERE domain = ? ORDER BY created_at DESC LIMIT ?
            """,
            (_normalize_domain(domain), max(1, int(limit))),
        ).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        try:
            item["tags"] = json.loads(item.pop("tags_json"))
        except (json.JSONDecodeError, TypeError):
            item["tags"] = []
        output.append(item)
    return output


def _replace_source_tags(
    connection: sqlite3.Connection,
    domain: str,
    tags: Iterable[str],
    source: str,
    confidence: float,
    now: int,
) -> None:
    normalized_tags = _normalize_tags(tags)
    connection.execute("DELETE FROM domain_tags WHERE domain = ? AND source = ?", (domain, source))
    connection.executemany(
        """
        INSERT INTO domain_tags(domain, tag, source, confidence, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        [(domain, tag, source, _confidence(confidence), now, now) for tag in normalized_tags],
    )


def set_manual_tags(domain: str, tags: Iterable[str]) -> None:
    now = int(time.time())
    with _DB_LOCK, _connection() as connection:
        normalized = _ensure_domain(connection, domain, seen_at=now)
        _replace_source_tags(connection, normalized, tags, "manual", 1.0, now)


def domain_tags(domain: str) -> list[dict[str, Any]]:
    with _DB_LOCK, _connection() as connection:
        rows = connection.execute(
            """
            SELECT tag, source, confidence, created_at, updated_at
            FROM domain_tags WHERE domain = ?
            ORDER BY CASE source WHEN 'manual' THEN 0 WHEN 'llm' THEN 1 ELSE 2 END, tag
            """,
            (_normalize_domain(domain),),
        ).fetchall()
    return [dict(row) for row in rows]


def _risk(value: int | float) -> int:
    try:
        return min(100, max(0, int(value)))
    except (TypeError, ValueError):
        return 0


def _confidence(value: int | float) -> float:
    try:
        return min(1.0, max(0.0, float(value)))
    except (TypeError, ValueError):
        return 0.0
