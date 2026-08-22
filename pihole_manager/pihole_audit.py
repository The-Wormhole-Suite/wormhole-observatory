from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pihole_manager.config import app_directory, load_options
from pihole_manager.pihole_instances import registry_path

_LOG = logging.getLogger(__name__)
_SUPPORTED_KINDS = {"exact_domain", "regex_domain", "subscribed_list"}
_AUDIT_DB_LOCK = threading.RLock()
AUDIT_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class PiHoleAuditEntry:
    id: int
    instance_id: str
    instance_name: str
    instance_url: str
    operation: str
    resource_kind: str
    resource_type: str
    resource_key: str
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    reversible: bool
    related_entry_id: int | None
    rolled_back_at: int | None
    rollback_error: str
    created_at: int


def audit_database_path() -> Path:
    return app_directory() / "pihole_audit.sqlite3"


@contextmanager
def _audit_connection():
    path = audit_database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
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


def _init_audit_db() -> None:
    with _AUDIT_DB_LOCK, _audit_connection() as connection:
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
            existing_version = int(row["value"]) if row else 0
        except (TypeError, ValueError):
            existing_version = 0
        if existing_version > AUDIT_SCHEMA_VERSION:
            raise RuntimeError(
                "The Pi-hole audit database was created by a newer application version "
                f"(schema {existing_version}; supported up to {AUDIT_SCHEMA_VERSION})."
            )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS pihole_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                instance_id TEXT NOT NULL DEFAULT '',
                instance_name TEXT NOT NULL DEFAULT '',
                instance_url TEXT NOT NULL DEFAULT '',
                operation TEXT NOT NULL,
                resource_kind TEXT NOT NULL,
                resource_type TEXT NOT NULL DEFAULT '',
                resource_key TEXT NOT NULL,
                before_json TEXT NOT NULL DEFAULT 'null',
                after_json TEXT NOT NULL DEFAULT 'null',
                reversible INTEGER NOT NULL DEFAULT 1,
                related_entry_id INTEGER REFERENCES pihole_audit_log(id) ON DELETE SET NULL,
                rolled_back_at INTEGER,
                rollback_error TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_pihole_audit_created
            ON pihole_audit_log(created_at DESC, id DESC)
            """
        )
        connection.execute(
            """
            INSERT INTO schema_meta(key, value) VALUES ('schema_version', ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (str(AUDIT_SCHEMA_VERSION),),
        )


def _normalize_groups(groups: Any) -> list[int]:
    values: set[int] = set()
    for item in groups or []:
        try:
            values.add(int(item))
        except (TypeError, ValueError):
            continue
    return sorted(values)


def normalize_snapshot(
    resource_kind: str,
    resource_type: str,
    resource_key: str,
    snapshot: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if snapshot is None:
        return None
    key_name = "address" if resource_kind == "subscribed_list" else "domain"
    groups = snapshot.get("groups")
    return {
        key_name: str(snapshot.get(key_name) or resource_key),
        "type": str(snapshot.get("type") or resource_type),
        "comment": str(snapshot.get("comment") or ""),
        "enabled": bool(snapshot.get("enabled", True)),
        "groups": None if groups is None else _normalize_groups(groups),
    }


def _instance_context() -> tuple[str, str, str]:
    options = load_options().pihole
    active_url = str(options.base_url or "").strip().rstrip("/")
    active_id = ""
    active_name = active_url or "Pi-hole"
    path: Path = registry_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except (OSError, json.JSONDecodeError):
        raw = {}
    instances = raw.get("instances") if isinstance(raw, dict) else []
    if isinstance(instances, list):
        matches = [
            item
            for item in instances
            if isinstance(item, dict)
            and str(item.get("base_url") or "").strip().rstrip("/") == active_url
        ]
        configured_active = (
            str(raw.get("active_instance_id") or "") if isinstance(raw, dict) else ""
        )
        selected = next(
            (item for item in matches if str(item.get("instance_id") or "") == configured_active),
            matches[0] if len(matches) == 1 else None,
        )
        if selected is not None:
            active_id = str(selected.get("instance_id") or "")
            active_name = str(selected.get("name") or active_name)
    return active_id, active_name, active_url


def _decode_snapshot(value: str) -> dict[str, Any] | None:
    try:
        decoded = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return None
    return decoded if isinstance(decoded, dict) else None


def _row_to_entry(row: Any) -> PiHoleAuditEntry:
    return PiHoleAuditEntry(
        id=int(row["id"]),
        instance_id=str(row["instance_id"] or ""),
        instance_name=str(row["instance_name"] or ""),
        instance_url=str(row["instance_url"] or ""),
        operation=str(row["operation"]),
        resource_kind=str(row["resource_kind"]),
        resource_type=str(row["resource_type"] or ""),
        resource_key=str(row["resource_key"]),
        before=_decode_snapshot(row["before_json"]),
        after=_decode_snapshot(row["after_json"]),
        reversible=bool(row["reversible"]),
        related_entry_id=(int(row["related_entry_id"]) if row["related_entry_id"] else None),
        rolled_back_at=(int(row["rolled_back_at"]) if row["rolled_back_at"] else None),
        rollback_error=str(row["rollback_error"] or ""),
        created_at=int(row["created_at"]),
    )


def record_pihole_change(
    operation: str,
    resource_kind: str,
    resource_type: str,
    resource_key: str,
    *,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    reversible: bool | None = None,
    related_entry_id: int | None = None,
) -> int | None:
    if resource_kind not in _SUPPORTED_KINDS:
        return None
    before = normalize_snapshot(resource_kind, resource_type, resource_key, before)
    after = normalize_snapshot(resource_kind, resource_type, resource_key, after)
    if reversible is None:
        reversible = operation == "add" or (
            operation in {"update", "delete"} and before is not None
        )
    instance_id, instance_name, instance_url = _instance_context()
    try:
        _init_audit_db()
        with _AUDIT_DB_LOCK, _audit_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO pihole_audit_log(
                    instance_id, instance_name, instance_url, operation,
                    resource_kind, resource_type, resource_key, before_json,
                    after_json, reversible, related_entry_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    instance_id,
                    instance_name,
                    instance_url,
                    operation,
                    resource_kind,
                    resource_type,
                    resource_key,
                    json.dumps(before, ensure_ascii=False),
                    json.dumps(after, ensure_ascii=False),
                    int(bool(reversible)),
                    related_entry_id,
                    int(time.time()),
                ),
            )
            return int(cursor.lastrowid)
    except Exception as exc:
        _LOG.warning("Could not write Pi-hole audit entry: %s", exc)
        return None


def list_pihole_audit(limit: int = 300) -> list[PiHoleAuditEntry]:
    _init_audit_db()
    with _AUDIT_DB_LOCK, _audit_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM pihole_audit_log ORDER BY created_at DESC, id DESC LIMIT ?",
            (max(1, min(5000, int(limit))),),
        ).fetchall()
    return [_row_to_entry(row) for row in rows]


def get_pihole_audit_entry(entry_id: int) -> PiHoleAuditEntry | None:
    _init_audit_db()
    with _AUDIT_DB_LOCK, _audit_connection() as connection:
        row = connection.execute(
            "SELECT * FROM pihole_audit_log WHERE id = ?",
            (int(entry_id),),
        ).fetchone()
    return _row_to_entry(row) if row else None


def capture_pihole_snapshot(
    resource_kind: str,
    resource_type: str,
    resource_key: str,
) -> dict[str, Any] | None:
    try:
        if resource_kind == "exact_domain":
            from pihole_manager.pihole_service import fetch_exact_domains

            rows = fetch_exact_domains(resource_type)
            key_name = "domain"
        elif resource_kind == "regex_domain":
            from pihole_manager.pihole_rules import fetch_regex_domains

            rows = fetch_regex_domains(resource_type)
            key_name = "domain"
        elif resource_kind == "subscribed_list":
            from pihole_manager.pihole_rules import fetch_subscribed_lists

            rows = fetch_subscribed_lists(resource_type)
            key_name = "address"
        else:
            return None
    except Exception:
        return None
    for row in rows:
        if str(row.get(key_name) or "") == resource_key:
            return normalize_snapshot(resource_kind, resource_type, resource_key, row)
    return None


def _snapshot_matches(
    current: dict[str, Any] | None,
    expected: dict[str, Any] | None,
) -> bool:
    if current is None or expected is None:
        return current is expected
    for key in ("domain", "address", "type", "comment", "enabled", "groups"):
        if key not in expected or expected[key] is None:
            continue
        if current.get(key) != expected[key]:
            return False
    return True


def _apply_rollback(entry: PiHoleAuditEntry) -> None:
    from pihole_manager.pihole_service import get_client

    client = get_client()
    snapshot = entry.before
    if entry.operation == "add":
        if entry.resource_kind in {"exact_domain", "regex_domain"}:
            kind = "exact" if entry.resource_kind == "exact_domain" else "regex"
            client.domain_management.delete_domain(entry.resource_key, entry.resource_type, kind)
        else:
            client.list_management.delete_list(entry.resource_key, entry.resource_type)
        return
    if snapshot is None:
        raise RuntimeError("The audit entry has no previous state to restore.")
    comment = str(snapshot.get("comment") or "") or None
    groups = snapshot.get("groups")
    normalized_groups = [] if groups is None else _normalize_groups(groups)
    enabled = bool(snapshot.get("enabled", True))
    if entry.resource_kind in {"exact_domain", "regex_domain"}:
        kind = "exact" if entry.resource_kind == "exact_domain" else "regex"
        if entry.operation == "delete":
            client.domain_management.add_domain(
                entry.resource_key,
                entry.resource_type,
                kind,
                comment=comment,
                groups=normalized_groups,
                enabled=enabled,
            )
        else:
            client.domain_management.update_domain(
                entry.resource_key,
                entry.resource_type,
                kind,
                comment=comment,
                groups=normalized_groups,
                enabled=enabled,
            )
        return
    if entry.operation == "delete":
        client.list_management.add_list(
            entry.resource_key,
            entry.resource_type,
            comment=comment,
            groups=normalized_groups,
            enabled=enabled,
        )
    else:
        client.list_management.update_list(
            entry.resource_key,
            entry.resource_type,
            comment=comment,
            groups=normalized_groups,
            enabled=enabled,
        )


def _mark_rollback_error(entry_id: int, error: str) -> None:
    _init_audit_db()
    with _AUDIT_DB_LOCK, _audit_connection() as connection:
        connection.execute(
            "UPDATE pihole_audit_log SET rollback_error = ? WHERE id = ?",
            (error[:2000], int(entry_id)),
        )


def rollback_pihole_audit(entry_id: int) -> int:
    entry = get_pihole_audit_entry(entry_id)
    if entry is None:
        raise ValueError("Audit entry was not found.")
    if not entry.reversible or entry.operation not in {"add", "update", "delete"}:
        raise RuntimeError("This audit entry cannot be rolled back.")
    if entry.rolled_back_at is not None:
        raise RuntimeError("This change has already been rolled back.")
    current_id, _current_name, current_url = _instance_context()
    if entry.instance_id and current_id and entry.instance_id != current_id:
        raise RuntimeError(
            f"Switch to Pi-hole instance '{entry.instance_name}' before rolling this change back."
        )
    if entry.instance_url.rstrip("/") != current_url.rstrip("/"):
        raise RuntimeError(
            f"Switch to Pi-hole instance '{entry.instance_name}' before rolling this change back."
        )
    current = capture_pihole_snapshot(
        entry.resource_kind,
        entry.resource_type,
        entry.resource_key,
    )
    expected = None if entry.operation == "delete" else entry.after
    if not _snapshot_matches(current, expected):
        raise RuntimeError(
            "The Pi-hole resource changed after this audit entry. Rollback was refused "
            "to avoid overwriting a newer change."
        )
    try:
        _apply_rollback(entry)
    except Exception as exc:
        _mark_rollback_error(entry.id, str(exc))
        raise
    now = int(time.time())
    with _AUDIT_DB_LOCK, _audit_connection() as connection:
        connection.execute(
            """
            UPDATE pihole_audit_log
            SET rolled_back_at = ?, rollback_error = ''
            WHERE id = ?
            """,
            (now, entry.id),
        )
        cursor = connection.execute(
            """
            INSERT INTO pihole_audit_log(
                instance_id, instance_name, instance_url, operation,
                resource_kind, resource_type, resource_key, before_json,
                after_json, reversible, related_entry_id, created_at
            ) VALUES (?, ?, ?, 'rollback', ?, ?, ?, ?, ?, 0, ?, ?)
            """,
            (
                entry.instance_id,
                entry.instance_name,
                entry.instance_url,
                entry.resource_kind,
                entry.resource_type,
                entry.resource_key,
                json.dumps(entry.after, ensure_ascii=False),
                json.dumps(entry.before, ensure_ascii=False),
                entry.id,
                now,
            ),
        )
        return int(cursor.lastrowid)
