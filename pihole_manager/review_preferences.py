from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Iterable
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from pihole_manager.config import app_directory

PREFERENCE_SCHEMA_VERSION = 1
_LOCK = threading.RLock()


def preference_database_path() -> Path:
    return app_directory() / "review_preferences.sqlite3"


@contextmanager
def _connection():
    path = preference_database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA busy_timeout = 30000")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _init_db() -> None:
    with _LOCK, _connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        row = connection.execute(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'"
        ).fetchone()
        try:
            version = int(row["value"]) if row else 0
        except (TypeError, ValueError):
            version = 0
        if version > PREFERENCE_SCHEMA_VERSION:
            raise RuntimeError(
                "The review-preference database was created by a newer application version "
                f"(schema {version}; supported up to {PREFERENCE_SCHEMA_VERSION})."
            )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS review_preferences (
                domain TEXT PRIMARY KEY,
                never_ask INTEGER NOT NULL DEFAULT 0,
                postponed_until INTEGER,
                last_decision TEXT NOT NULL DEFAULT '',
                updated_at INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_review_preferences_visibility
            ON review_preferences(never_ask, postponed_until)
            """
        )
        connection.execute(
            """
            INSERT INTO schema_meta(key, value) VALUES ('schema_version', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (str(PREFERENCE_SCHEMA_VERSION),),
        )


def _normalize_domain(domain: str) -> str:
    return str(domain or "").strip().lower().rstrip(".")


def review_preference_get(domain: str) -> dict[str, Any] | None:
    normalized = _normalize_domain(domain)
    if not normalized:
        return None
    _init_db()
    with _LOCK, _connection() as connection:
        row = connection.execute(
            "SELECT * FROM review_preferences WHERE domain = ?",
            (normalized,),
        ).fetchone()
    if row is None:
        return None
    item = dict(row)
    item["never_ask"] = bool(item.get("never_ask"))
    return item


def review_preferences_for_domains(domains: Iterable[str]) -> dict[str, dict[str, Any]]:
    normalized = sorted(
        {
            normalized_domain
            for domain in domains
            if (normalized_domain := _normalize_domain(domain))
        }
    )
    if not normalized:
        return {}
    _init_db()
    placeholders = ",".join("?" for _ in normalized)
    with _LOCK, _connection() as connection:
        rows = connection.execute(
            f"SELECT * FROM review_preferences WHERE domain IN ({placeholders})",
            normalized,
        ).fetchall()
    output: dict[str, dict[str, Any]] = {}
    for row in rows:
        item = dict(row)
        item["never_ask"] = bool(item.get("never_ask"))
        output[str(item["domain"])] = item
    return output


def set_review_preference(
    domain: str,
    *,
    never_ask: bool = False,
    postponed_until: int | None = None,
    last_decision: str = "",
) -> dict[str, Any]:
    normalized = _normalize_domain(domain)
    if not normalized:
        raise ValueError("domain must not be empty")
    postponed = int(postponed_until) if postponed_until is not None else None
    now = int(time.time())
    _init_db()
    with _LOCK, _connection() as connection:
        connection.execute(
            """
            INSERT INTO review_preferences(
                domain, never_ask, postponed_until, last_decision, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                never_ask = excluded.never_ask,
                postponed_until = excluded.postponed_until,
                last_decision = excluded.last_decision,
                updated_at = excluded.updated_at
            """,
            (
                normalized,
                int(bool(never_ask)),
                postponed,
                str(last_decision or "").strip().lower(),
                now,
            ),
        )
    return review_preference_get(normalized) or {
        "domain": normalized,
        "never_ask": bool(never_ask),
        "postponed_until": postponed,
        "last_decision": str(last_decision or "").strip().lower(),
        "updated_at": now,
    }


def clear_review_preference(domain: str) -> bool:
    normalized = _normalize_domain(domain)
    if not normalized:
        return False
    _init_db()
    with _LOCK, _connection() as connection:
        cursor = connection.execute(
            "DELETE FROM review_preferences WHERE domain = ?",
            (normalized,),
        )
    return cursor.rowcount > 0


def preference_blocks_review(domain: str, *, now: int | None = None) -> bool:
    item = review_preference_get(domain)
    if item is None:
        return False
    if bool(item.get("never_ask")):
        return True
    postponed = item.get("postponed_until")
    return postponed is not None and int(postponed) > int(now if now is not None else time.time())


def apply_review_preferences(
    rows: Iterable[dict[str, Any]],
    *,
    hide_blocked: bool,
    now: int | None = None,
) -> list[dict[str, Any]]:
    items = [dict(row) for row in rows]
    preferences = review_preferences_for_domains(str(item.get("domain") or "") for item in items)
    current = int(now if now is not None else time.time())
    output: list[dict[str, Any]] = []
    for item in items:
        domain = _normalize_domain(str(item.get("domain") or ""))
        preference = preferences.get(domain)
        never_ask = bool(preference and preference.get("never_ask"))
        postponed_until = preference.get("postponed_until") if preference else None
        blocked = never_ask or (
            postponed_until is not None and int(postponed_until) > current
        )
        item["never_ask"] = never_ask
        item["postponed_until"] = postponed_until
        item["last_decision"] = str(preference.get("last_decision") or "") if preference else ""
        if hide_blocked and blocked:
            continue
        output.append(item)
    return output
