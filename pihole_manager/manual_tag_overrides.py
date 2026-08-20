from __future__ import annotations

import json
import time
from collections.abc import Iterable
from typing import Any

from pihole_manager import database_review as _database_review
from pihole_manager.database_core import _DB_LOCK, _connection, _normalize_domain, _normalize_tags


def set_manual_tags(domain: str, tags: Iterable[str]) -> None:
    _database_review.set_manual_tags(domain, tags)


def manual_tags(domain: str) -> list[str]:
    with _DB_LOCK, _connection() as connection:
        rows = connection.execute(
            """
            SELECT tag FROM domain_tags
            WHERE domain = ? AND source = 'manual'
            ORDER BY tag
            """,
            (_normalize_domain(domain),),
        ).fetchall()
    return [str(row["tag"]) for row in rows]


def effective_tags(domain: str, fallback: Iterable[str]) -> list[str]:
    override = manual_tags(domain)
    return override if override else _normalize_tags(fallback)


def review_get(
    limit: int = 200,
    status: str | None = None,
    needs_review: bool | None = None,
) -> list[dict[str, Any]]:
    rows = _database_review.review_get(
        limit=limit,
        status=status,
        needs_review=needs_review,
    )
    return [_with_effective_tags(row) for row in rows]


def review_queue_items(limit: int = 500) -> list[dict[str, Any]]:
    rows = _database_review.review_queue_items(limit=limit)
    return [_with_effective_tags(row) for row in rows]


def domain_browser_search(
    *,
    search: str = "",
    policy: str = "all",
    tag: str = "",
    service_role: str = "all",
    review_state: str = "all",
    limit: int = 500,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    clauses: list[str] = ["(c.id IS NOT NULL OR r.domain IS NOT NULL)"]
    parameters: list[Any] = []

    policy_expression = "LOWER(COALESCE(r.policy, c.policy))"
    role_expression = "LOWER(COALESCE(r.service_role, c.service_role))"
    review_expression = "COALESCE(r.needs_review, c.needs_review)"
    recheck_expression = "COALESCE(r.next_recheck_at, d.next_recheck_at, c.expires_at)"
    manual_tags_expression = """
        (
            SELECT GROUP_CONCAT(mt.tag, ',')
            FROM domain_tags mt
            WHERE mt.domain = d.domain AND mt.source = 'manual'
        )
    """
    tags_expression = (
        f"COALESCE({manual_tags_expression}, NULLIF(r.categories, ''), c.tags_json)"
    )

    normalized_search = search.strip().lower()
    if normalized_search:
        clauses.append(
            f"""
            (
                LOWER(d.domain) LIKE ? OR LOWER({tags_expression}) LIKE ? OR
                LOWER(COALESCE(r.service, c.service)) LIKE ? OR
                LOWER(COALESCE(r.short, c.short)) LIKE ? OR
                LOWER(COALESCE(r.details, c.details)) LIKE ?
            )
            """
        )
        pattern = f"%{normalized_search}%"
        parameters.extend([pattern] * 5)

    normalized_policy = policy.strip().lower()
    if normalized_policy and normalized_policy != "all":
        clauses.append(f"{policy_expression} = ?")
        parameters.append(normalized_policy)

    normalized_tag = tag.strip().lower().replace(" ", "_")
    if normalized_tag:
        clauses.append(
            """
            (
                (
                    EXISTS (
                        SELECT 1 FROM domain_tags mt
                        WHERE mt.domain = d.domain AND mt.source = 'manual'
                    )
                    AND EXISTS (
                        SELECT 1 FROM domain_tags mt
                        WHERE mt.domain = d.domain AND mt.source = 'manual'
                          AND LOWER(mt.tag) = ?
                    )
                )
                OR (
                    NOT EXISTS (
                        SELECT 1 FROM domain_tags mt
                        WHERE mt.domain = d.domain AND mt.source = 'manual'
                    )
                    AND (
                        INSTR(',' || LOWER(COALESCE(r.categories, '')) || ',',
                              ',' || ? || ',') > 0
                        OR LOWER(c.tags_json) LIKE ?
                    )
                )
            )
            """
        )
        parameters.extend([normalized_tag, normalized_tag, f'%"{normalized_tag}"%'])

    normalized_role = service_role.strip().lower()
    if normalized_role and normalized_role != "all":
        clauses.append(f"{role_expression} = ?")
        parameters.append(normalized_role)

    normalized_review = review_state.strip().lower()
    if normalized_review == "required":
        clauses.append(f"{review_expression} = 1")
    elif normalized_review == "not_required":
        clauses.append(f"{review_expression} = 0")
    elif normalized_review == "overdue":
        clauses.append(f"{recheck_expression} IS NOT NULL AND {recheck_expression} <= ?")
        parameters.append(int(time.time()))

    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    base = """
        FROM domains d
        LEFT JOIN classification_runs c ON c.id = (
            SELECT c2.id
            FROM classification_runs c2
            WHERE c2.domain = d.domain AND c2.is_primary = 1
            ORDER BY c2.created_at DESC, c2.id DESC
            LIMIT 1
        )
        LEFT JOIN review r ON r.domain = d.domain
        LEFT JOIN domain_locks l ON l.domain = d.domain
    """
    safe_limit = min(5_000, max(1, int(limit)))
    safe_offset = max(0, int(offset))

    with _DB_LOCK, _connection() as connection:
        total_row = connection.execute(
            "SELECT COUNT(*) AS total " + base + where,
            parameters,
        ).fetchone()
        rows = connection.execute(
            f"""
            SELECT
                d.domain, d.first_seen, d.last_seen, d.query_count,
                d.last_classified_at, d.last_researched_at,
                {recheck_expression} AS next_recheck_at,
                {tags_expression} AS categories,
                CASE
                    WHEN EXISTS (
                        SELECT 1 FROM domain_tags mt
                        WHERE mt.domain = d.domain AND mt.source = 'manual'
                    ) THEN 'manual'
                    ELSE 'classification'
                END AS tags_source,
                COALESCE(r.policy, c.policy) AS policy,
                COALESCE(r.planned_action, c.planned_action, '') AS planned_action,
                COALESCE(r.action_status, c.action_status, 'none') AS action_status,
                COALESCE(r.short, c.short) AS short,
                COALESCE(r.details, c.details) AS details,
                COALESCE(r.provider, c.provider) AS provider,
                COALESCE(r.status, 'classified') AS status,
                COALESCE(r.service, c.service) AS service,
                COALESCE(r.service_role, c.service_role) AS service_role,
                COALESCE(r.privacy_risk, c.privacy_risk) AS privacy_risk,
                COALESCE(r.security_risk, c.security_risk) AS security_risk,
                COALESCE(r.breakage_risk, c.breakage_risk) AS breakage_risk,
                COALESCE(r.confidence, c.confidence) AS confidence,
                {review_expression} AS needs_review,
                COALESCE(r.review_reason, c.review_reason) AS review_reason,
                COALESCE(r.updated_at, c.created_at) AS updated_at,
                l.list_type AS lock_type, l.reason AS lock_reason,
                (SELECT COUNT(*) FROM classification_runs cx WHERE cx.domain = d.domain)
                    AS classification_count,
                (SELECT COUNT(*) FROM research_findings f WHERE f.domain = d.domain)
                    AS research_count
            """
            + base
            + where
            + " ORDER BY updated_at DESC, d.domain LIMIT ? OFFSET ?",
            [*parameters, safe_limit, safe_offset],
        ).fetchall()

    output: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        raw_tags = str(item.pop("categories", "") or "")
        if raw_tags.lstrip().startswith("["):
            try:
                parsed_tags = json.loads(raw_tags)
            except json.JSONDecodeError:
                parsed_tags = []
            item["tags"] = [str(value) for value in parsed_tags if str(value).strip()]
        else:
            item["tags"] = _normalize_tags(raw_tags)
        item["needs_review"] = bool(item.get("needs_review"))
        output.append(item)
    return output, int(total_row["total"] if total_row else 0)


def _with_effective_tags(row: dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    override = manual_tags(str(item.get("domain") or ""))
    if override:
        item["categories"] = list(override)
        item["tags"] = list(override)
        item["tags_source"] = "manual"
    else:
        current = item.get("tags") or item.get("categories") or []
        normalized = _normalize_tags(current)
        item["categories"] = list(normalized)
        item["tags"] = list(normalized)
        item["tags_source"] = "classification"
    return item
