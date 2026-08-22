from __future__ import annotations

from types import SimpleNamespace

import pytest

from pihole_manager import pihole_service
from pihole_manager.database import init_db
from pihole_manager.pihole_audit import (
    AUDIT_SCHEMA_VERSION,
    audit_database_path,
    get_pihole_audit_entry,
    list_pihole_audit,
    record_pihole_change,
    rollback_pihole_audit,
)


def test_audit_entry_round_trip(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()

    entry_id = record_pihole_change(
        "add",
        "regex_domain",
        "deny",
        r"(^|\\.)tracker\\.example$",
        after={
            "domain": r"(^|\\.)tracker\\.example$",
            "type": "deny",
            "comment": "tracking",
            "groups": [2, 1, 2],
            "enabled": True,
        },
    )

    assert entry_id is not None
    entries = list_pihole_audit()
    assert len(entries) == 1
    assert entries[0].id == entry_id
    assert entries[0].after == {
        "domain": r"(^|\\.)tracker\\.example$",
        "type": "deny",
        "comment": "tracking",
        "enabled": True,
        "groups": [1, 2],
    }
    assert entries[0].reversible is True


def test_rollback_added_exact_domain_and_records_rollback(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    state = [
        {
            "domain": "ads.example",
            "type": "deny",
            "comment": "manual",
            "groups": [0],
            "enabled": True,
        }
    ]
    deleted: list[tuple[str, str, str]] = []

    def fetch_exact(domain_type: str):
        return [item.copy() for item in state if item["type"] == domain_type]

    def delete_domain(domain: str, domain_type: str, kind: str):
        deleted.append((domain, domain_type, kind))
        state.clear()
        return {"ok": True}

    monkeypatch.setattr(pihole_service, "fetch_exact_domains", fetch_exact)
    monkeypatch.setattr(
        pihole_service,
        "get_client",
        lambda: SimpleNamespace(
            domain_management=SimpleNamespace(delete_domain=delete_domain),
        ),
    )
    entry_id = record_pihole_change(
        "add",
        "exact_domain",
        "deny",
        "ads.example",
        after=state[0],
    )
    assert entry_id is not None

    rollback_id = rollback_pihole_audit(entry_id)

    assert deleted == [("ads.example", "deny", "exact")]
    assert state == []
    original = get_pihole_audit_entry(entry_id)
    assert original is not None and original.rolled_back_at is not None
    rollback = get_pihole_audit_entry(rollback_id)
    assert rollback is not None
    assert rollback.operation == "rollback"
    assert rollback.related_entry_id == entry_id
    assert rollback.reversible is False


def test_rollback_refuses_to_overwrite_newer_resource_state(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    current = {
        "domain": "ads.example",
        "type": "deny",
        "comment": "newer change",
        "groups": [0],
        "enabled": True,
    }
    monkeypatch.setattr(
        pihole_service,
        "fetch_exact_domains",
        lambda _domain_type: [current.copy()],
    )
    entry_id = record_pihole_change(
        "update",
        "exact_domain",
        "deny",
        "ads.example",
        before={
            "domain": "ads.example",
            "type": "deny",
            "comment": "before",
            "groups": [0],
            "enabled": True,
        },
        after={
            "domain": "ads.example",
            "type": "deny",
            "comment": "after",
            "groups": [0],
            "enabled": True,
        },
    )
    assert entry_id is not None

    with pytest.raises(RuntimeError, match="newer change"):
        rollback_pihole_audit(entry_id)


def test_audit_database_is_versioned_and_contains_log_table(monkeypatch, tmp_path) -> None:
    import sqlite3

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    list_pihole_audit()
    connection = sqlite3.connect(audit_database_path())
    version = connection.execute(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
    ).fetchone()[0]
    table = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'pihole_audit_log'"
    ).fetchone()
    connection.close()

    assert version == str(AUDIT_SCHEMA_VERSION)
    assert table == ("pihole_audit_log",)
