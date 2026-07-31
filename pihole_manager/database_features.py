from __future__ import annotations

import json
import time
from collections.abc import Iterable
from typing import Any

from pihole_manager.database_core import (
    _DB_LOCK,
    _connection,
    _ensure_domain,
    _normalize_domain,
    domain_observation_summary,
)
from pihole_manager.database_review import classification_history, domain_tags
from pihole_manager.models import ResearchFinding, ReviewPriority

# ---------- Research ----------


def save_research_findings(
    findings: Iterable[ResearchFinding],
    *,
    default_max_age_days: int = 30,
) -> int:
    items = list(findings)
    if not items:
        return 0

    count = 0
    with _DB_LOCK, _connection() as connection:
        normalized_by_item: list[tuple[str, ResearchFinding]] = []
        provider_keys: set[tuple[str, str]] = set()
        for finding in items:
            domain = _ensure_domain(
                connection,
                finding.domain,
                seen_at=finding.retrieved_at or int(time.time()),
            )
            normalized_by_item.append((domain, finding))
            provider_keys.add((domain, finding.provider))

        connection.executemany(
            "DELETE FROM research_findings WHERE domain = ? AND provider = ?",
            sorted(provider_keys),
        )

        for domain, finding in normalized_by_item:
            retrieved_at = finding.retrieved_at or int(time.time())
            expires_at = finding.expires_at or (
                retrieved_at + max(1, int(default_max_age_days)) * 86400
            )
            connection.execute(
                """
                INSERT INTO research_findings(
                    domain, provider, kind, title, summary, source_url,
                    confidence, signal_type, verdict, decision_relevant,
                    raw_json, retrieved_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    domain,
                    finding.provider,
                    finding.kind,
                    finding.title,
                    finding.summary,
                    finding.source_url,
                    _confidence(finding.confidence),
                    finding.signal_type.strip() or "context",
                    finding.verdict.strip() or "unknown",
                    int(bool(finding.decision_relevant)),
                    json.dumps(finding.raw_data, ensure_ascii=False, default=str),
                    retrieved_at,
                    expires_at,
                ),
            )
            connection.execute(
                "UPDATE domains SET last_researched_at = ? WHERE domain = ?",
                (retrieved_at, domain),
            )
            count += 1
    return count


def research_findings_get(
    domain: str,
    *,
    fresh_only: bool = False,
    limit: int = 100,
) -> list[dict[str, Any]]:
    query = "SELECT * FROM research_findings WHERE domain = ?"
    parameters: list[Any] = [_normalize_domain(domain)]
    if fresh_only:
        query += " AND expires_at > ?"
        parameters.append(int(time.time()))
    query += " ORDER BY retrieved_at DESC, id DESC LIMIT ?"
    parameters.append(max(1, int(limit)))
    with _DB_LOCK, _connection() as connection:
        rows = connection.execute(query, parameters).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        try:
            item["raw_data"] = json.loads(item.pop("raw_json"))
        except (json.JSONDecodeError, TypeError):
            item["raw_data"] = {}
        output.append(item)
    return output


def clear_research_findings(domain: str) -> int:
    with _DB_LOCK, _connection() as connection:
        cursor = connection.execute(
            "DELETE FROM research_findings WHERE domain = ?", (_normalize_domain(domain),)
        )
    return cursor.rowcount


# ---------- Lock protection ----------


def set_domain_lock(domain: str, list_type: str, reason: str = "") -> None:
    if list_type not in {"allow", "deny"}:
        raise ValueError("list_type must be allow or deny")
    now = int(time.time())
    with _DB_LOCK, _connection() as connection:
        normalized = _ensure_domain(connection, domain, seen_at=now)
        connection.execute(
            """
            INSERT INTO domain_locks(domain, list_type, reason, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                list_type = excluded.list_type,
                reason = excluded.reason,
                updated_at = excluded.updated_at
            """,
            (normalized, list_type, reason.strip(), now, now),
        )
        connection.execute(
            "DELETE FROM staging_domains WHERE domain = ?",
            (normalized,),
        )


def remove_domain_lock(domain: str) -> int:
    with _DB_LOCK, _connection() as connection:
        cursor = connection.execute(
            "DELETE FROM domain_locks WHERE domain = ?", (_normalize_domain(domain),)
        )
    return cursor.rowcount


def get_domain_lock(domain: str) -> dict[str, Any] | None:
    with _DB_LOCK, _connection() as connection:
        row = connection.execute(
            "SELECT * FROM domain_locks WHERE domain = ?", (_normalize_domain(domain),)
        ).fetchone()
    return dict(row) if row else None


def list_domain_locks(list_type: str | None = None) -> list[dict[str, Any]]:
    with _DB_LOCK, _connection() as connection:
        if list_type:
            rows = connection.execute(
                "SELECT * FROM domain_locks WHERE list_type = ? ORDER BY domain",
                (list_type,),
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM domain_locks ORDER BY list_type, domain"
            ).fetchall()
    return [dict(row) for row in rows]


def is_domain_locked(domain: str, list_type: str | None = None) -> bool:
    lock = get_domain_lock(domain)
    if lock is None:
        return False
    return list_type is None or lock["list_type"] == list_type


# ---------- Review tasks ----------


def create_review_task(
    domain: str,
    reason: str,
    *,
    priority: ReviewPriority | str = ReviewPriority.NORMAL,
    source: str = "",
) -> int:
    now = int(time.time())
    priority_value = priority.value if isinstance(priority, ReviewPriority) else str(priority)
    if priority_value not in {item.value for item in ReviewPriority}:
        priority_value = ReviewPriority.NORMAL.value
    with _DB_LOCK, _connection() as connection:
        normalized = _ensure_domain(connection, domain, seen_at=now)
        existing = connection.execute(
            """
            SELECT id FROM review_tasks
            WHERE domain = ? AND reason = ? AND status = 'open'
            """,
            (normalized, reason.strip()),
        ).fetchone()
        if existing:
            return int(existing["id"])
        cursor = connection.execute(
            """
            INSERT INTO review_tasks(
                domain, reason, priority, status, source, decision, created_at, updated_at
            ) VALUES (?, ?, ?, 'open', ?, '', ?, ?)
            """,
            (normalized, reason.strip(), priority_value, source.strip(), now, now),
        )
    return int(cursor.lastrowid)


def review_tasks_get(status: str = "open", limit: int = 200) -> list[dict[str, Any]]:
    with _DB_LOCK, _connection() as connection:
        rows = connection.execute(
            """
            SELECT * FROM review_tasks WHERE status = ?
            ORDER BY CASE priority
                WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                WHEN 'normal' THEN 2 ELSE 3 END,
                created_at
            LIMIT ?
            """,
            (status, max(1, int(limit))),
        ).fetchall()
    return [dict(row) for row in rows]


def resolve_review_task(task_id: int, decision: str) -> None:
    with _DB_LOCK, _connection() as connection:
        connection.execute(
            """
            UPDATE review_tasks SET status = 'resolved', decision = ?, updated_at = ?
            WHERE id = ?
            """,
            (decision.strip(), int(time.time()), int(task_id)),
        )


# ---------- Domain browser ----------


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
    tags_expression = "COALESCE(NULLIF(r.categories, ''), c.tags_json)"

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
                INSTR(',' || LOWER(COALESCE(r.categories, '')) || ',', ',' || ? || ',') > 0
                OR LOWER(c.tags_json) LIKE ?
            )
            """
        )
        parameters.extend([normalized_tag, f'%"{normalized_tag}"%'])

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
            WHERE c2.domain = d.domain
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
            item["tags"] = [
                value.strip() for value in raw_tags.replace(";", ",").split(",") if value.strip()
            ]
        item["needs_review"] = bool(item.get("needs_review"))
        output.append(item)
    return output, int(total_row["total"] if total_row else 0)


# ---------- State and details ----------


def get_state(key: str, default: str = "") -> str:
    with _DB_LOCK, _connection() as connection:
        row = connection.execute("SELECT value FROM app_state WHERE key = ?", (key,)).fetchone()
    return str(row["value"]) if row else default


def set_state(key: str, value: str) -> None:
    now = int(time.time())
    with _DB_LOCK, _connection() as connection:
        connection.execute(
            """
            INSERT INTO app_state(key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (key, value, now),
        )


def domain_details(domain: str) -> dict[str, Any]:
    normalized = _normalize_domain(domain)
    with _DB_LOCK, _connection() as connection:
        row = connection.execute("SELECT * FROM domains WHERE domain = ?", (normalized,)).fetchone()
    return {
        "domain": dict(row) if row else {"domain": normalized},
        "tags": domain_tags(normalized),
        "lock": get_domain_lock(normalized),
        "observations": domain_observation_summary(normalized),
        "classifications": classification_history(normalized),
        "research": research_findings_get(normalized),
    }


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
