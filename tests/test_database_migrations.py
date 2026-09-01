from __future__ import annotations

import sqlite3

import pytest

import pihole_manager.database_migrations as migrations
from pihole_manager.database import init_db


def test_versioned_migration_is_recorded_once(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    path = tmp_path / "pihole_manager.sqlite3"

    init_db()
    init_db()

    connection = sqlite3.connect(path)
    version = connection.execute(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
    ).fetchone()[0]
    history = connection.execute(
        "SELECT version, name, applied_at FROM schema_migrations ORDER BY version"
    ).fetchall()
    connection.close()

    assert migrations.LEGACY_SCHEMA_VERSION == 12
    assert migrations.DATABASE_SCHEMA_VERSION == 13
    assert version == str(migrations.DATABASE_SCHEMA_VERSION)
    assert history[0] == (12, "legacy schema baseline (pre-history)", 0)
    assert history[1][0:2] == (13, "add migration history")
    assert history[1][2] > 0
    assert len(history) == 2


def test_failed_versioned_migration_rolls_back(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    path = tmp_path / "pihole_manager.sqlite3"

    def fail_after_schema_change(connection: sqlite3.Connection) -> None:
        connection.execute("CREATE TABLE rollback_probe (id INTEGER PRIMARY KEY)")
        raise ValueError("simulated migration failure")

    monkeypatch.setitem(
        migrations._SCHEMA_MIGRATIONS,
        13,
        migrations.SchemaMigration(
            version=13,
            name="rollback probe",
            apply=fail_after_schema_change,
        ),
    )

    with pytest.raises(RuntimeError, match="migration 13 .* rolled back"):
        init_db()

    connection = sqlite3.connect(path)
    version = connection.execute(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
    ).fetchone()[0]
    probe = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'rollback_probe'"
    ).fetchone()
    history = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
    ).fetchone()
    connection.close()

    assert version == str(migrations.LEGACY_SCHEMA_VERSION)
    assert probe is None
    assert history is None


def test_newer_schema_is_rejected_before_legacy_init(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    path = tmp_path / "pihole_manager.sqlite3"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE schema_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        INSERT INTO schema_meta(key, value) VALUES ('schema_version', '999');
        """
    )
    connection.commit()
    connection.close()

    with pytest.raises(RuntimeError, match="newer Pi-hole Manager"):
        init_db()

    connection = sqlite3.connect(path)
    version = connection.execute(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
    ).fetchone()[0]
    connection.close()
    assert version == "999"
