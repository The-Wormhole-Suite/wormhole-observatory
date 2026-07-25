from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Iterable
from contextlib import contextmanager
from typing import Any

from pihole_manager.config import database_path
from pihole_manager.models import Classification

_DB_LOCK = threading.RLock()


@contextmanager
def _connection():
    connection = sqlite3.connect(database_path(), timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db() -> None:
    with _DB_LOCK, _connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS staging_domains (
                domain TEXT PRIMARY KEY,
                state TEXT NOT NULL DEFAULT 'queued',
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                last_error TEXT NOT NULL DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_staging_state_created
                ON staging_domains(state, created_at);

            CREATE TABLE IF NOT EXISTS review (
                domain TEXT PRIMARY KEY,
                categories TEXT NOT NULL DEFAULT '',
                policy TEXT NOT NULL DEFAULT 'unknown',
                short TEXT NOT NULL DEFAULT '',
                details TEXT NOT NULL DEFAULT '',
                provider TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'new',
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            """
        )
        _migrate_review_table(connection)


def _migrate_review_table(connection: sqlite3.Connection) -> None:
    columns = {
        str(row["name"]): row for row in connection.execute("PRAGMA table_info(review)")
    }
    additions = {
        "policy": "TEXT NOT NULL DEFAULT 'unknown'",
        "short": "TEXT NOT NULL DEFAULT ''",
        "provider": "TEXT NOT NULL DEFAULT ''",
        "status": "TEXT NOT NULL DEFAULT 'new'",
    }
    for name, definition in additions.items():
        if name not in columns:
            connection.execute(f"ALTER TABLE review ADD COLUMN {name} {definition}")

    if "comment" in columns:
        connection.execute(
            """
            UPDATE review
            SET categories = COALESCE(NULLIF(categories, ''), comment, '')
            WHERE COALESCE(categories, '') = ''
            """
        )


def _normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def _normalize_categories(categories: object) -> str:
    if isinstance(categories, str):
        values = categories.replace(";", ",").split(",")
    elif isinstance(categories, Iterable):
        values = [str(value) for value in categories]
    else:
        values = []
    return ",".join(
        dict.fromkeys(value.strip().lower() for value in values if value.strip())
    )


def staging_enqueue(domains: Iterable[str]) -> int:
    now = int(time.time())
    added = 0
    with _DB_LOCK, _connection() as connection:
        for value in domains:
            domain = _normalize_domain(value)
            if not domain:
                continue
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO staging_domains(
                    domain, state, attempts, created_at, updated_at, last_error
                ) VALUES (?, 'queued', 0, ?, ?, '')
                """,
                (domain, now, now),
            )
            added += int(cursor.rowcount > 0)
    return added


def staging_claim(limit: int = 100) -> list[str]:
    limit = max(1, int(limit))
    now = int(time.time())
    with _DB_LOCK, _connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        rows = connection.execute(
            """
            SELECT domain
            FROM staging_domains
            WHERE state = 'queued'
            ORDER BY created_at, domain
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        domains = [str(row["domain"]) for row in rows]
        if domains:
            placeholders = ",".join("?" for _ in domains)
            connection.execute(
                f"""
                UPDATE staging_domains
                SET state = 'processing', attempts = attempts + 1, updated_at = ?
                WHERE domain IN ({placeholders})
                """,
                (now, *domains),
            )
    return domains


def staging_ack(domain: str) -> None:
    with _DB_LOCK, _connection() as connection:
        connection.execute(
            "DELETE FROM staging_domains WHERE domain = ?", (_normalize_domain(domain),)
        )


def staging_fail(domain: str, error: str, max_attempts: int = 3) -> None:
    normalized = _normalize_domain(domain)
    now = int(time.time())
    with _DB_LOCK, _connection() as connection:
        row = connection.execute(
            "SELECT attempts FROM staging_domains WHERE domain = ?", (normalized,)
        ).fetchone()
        attempts = int(row["attempts"]) if row else max_attempts
        state = "failed" if attempts >= max_attempts else "queued"
        connection.execute(
            """
            UPDATE staging_domains
            SET state = ?, updated_at = ?, last_error = ?
            WHERE domain = ?
            """,
            (state, now, error[:1000], normalized),
        )


def staging_requeue_processing() -> int:
    now = int(time.time())
    with _DB_LOCK, _connection() as connection:
        cursor = connection.execute(
            """
            UPDATE staging_domains
            SET state = 'queued', updated_at = ?
            WHERE state = 'processing'
            """,
            (now,),
        )
    return cursor.rowcount


def staging_list(limit: int = 200) -> list[dict[str, Any]]:
    with _DB_LOCK, _connection() as connection:
        rows = connection.execute(
            """
            SELECT domain, state, attempts, created_at, updated_at, last_error
            FROM staging_domains
            ORDER BY created_at, domain
            LIMIT ?
            """,
            (max(1, int(limit)),),
        ).fetchall()
    return [dict(row) for row in rows]


def review_save(
    domain: str,
    categories: object,
    details: str,
    status: str = "edited",
    *,
    policy: str = "unknown",
    short: str = "",
    provider: str = "",
) -> None:
    normalized = _normalize_domain(domain)
    if not normalized:
        raise ValueError("domain must not be empty")
    now = int(time.time())
    with _DB_LOCK, _connection() as connection:
        connection.execute(
            """
            INSERT INTO review(
                domain, categories, policy, short, details, provider,
                status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                categories = excluded.categories,
                policy = excluded.policy,
                short = excluded.short,
                details = excluded.details,
                provider = excluded.provider,
                status = excluded.status,
                updated_at = excluded.updated_at
            """,
            (
                normalized,
                _normalize_categories(categories),
                policy.strip().lower() or "unknown",
                short.strip(),
                details.strip(),
                provider.strip(),
                status.strip() or "edited",
                now,
                now,
            ),
        )


def review_save_classification(classification: Classification, status: str = "classified") -> None:
    review_save(
        classification.domain,
        [classification.category] if classification.category else [],
        classification.details,
        status,
        policy=classification.policy.value,
        short=classification.short,
        provider=classification.provider,
    )


def review_get(limit: int = 500, status: str | None = None) -> list[dict[str, Any]]:
    with _DB_LOCK, _connection() as connection:
        if status:
            rows = connection.execute(
                """
                SELECT * FROM review
                WHERE status = ?
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (status, max(1, int(limit))),
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM review ORDER BY updated_at DESC LIMIT ?",
                (max(1, int(limit)),),
            ).fetchall()
    output: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        categories = str(item.get("categories") or "")
        item["categories"] = [value for value in categories.split(",") if value]
        item["comment"] = categories
        output.append(item)
    return output


def review_delete(domains: Iterable[str]) -> int:
    normalized = [_normalize_domain(domain) for domain in domains]
    normalized = [domain for domain in normalized if domain]
    if not normalized:
        return 0
    placeholders = ",".join("?" for _ in normalized)
    with _DB_LOCK, _connection() as connection:
        cursor = connection.execute(
            f"DELETE FROM review WHERE domain IN ({placeholders})", normalized
        )
    return cursor.rowcount
