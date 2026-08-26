from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass

from pihole_manager import database_core
from pihole_manager.config import database_path

LEGACY_SCHEMA_VERSION = database_core.DATABASE_SCHEMA_VERSION
DATABASE_SCHEMA_VERSION = 12


@dataclass(frozen=True, slots=True)
class SchemaMigration:
    version: int
    name: str
    apply: Callable[[sqlite3.Connection], None]


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(database_path(), timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.execute("PRAGMA busy_timeout = 30000")
    return connection


def _existing_schema_version(connection: sqlite3.Connection) -> int:
    table = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_meta'"
    ).fetchone()
    if table is None:
        return 0

    row = connection.execute(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
    ).fetchone()
    if row is None:
        return 0
    try:
        version = int(row["value"])
    except (TypeError, ValueError) as exc:
        raise RuntimeError("The database schema version is invalid.") from exc
    if version < 0:
        raise RuntimeError("The database schema version is invalid.")
    return version


def _set_schema_version(connection: sqlite3.Connection, version: int) -> None:
    connection.execute(
        """
        INSERT INTO schema_meta(key, value) VALUES ('schema_version', ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (str(version),),
    )


def _migration_12_add_migration_history(connection: sqlite3.Connection) -> None:
    connection.execute(
        """
        CREATE TABLE schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at INTEGER NOT NULL
        )
        """
    )


_SCHEMA_MIGRATIONS: dict[int, SchemaMigration] = {
    12: SchemaMigration(
        version=12,
        name="add migration history",
        apply=_migration_12_add_migration_history,
    ),
}


def _apply_pending_migrations(current_version: int) -> None:
    for version in range(current_version + 1, DATABASE_SCHEMA_VERSION + 1):
        migration = _SCHEMA_MIGRATIONS.get(version)
        if migration is None:
            raise RuntimeError(f"Database migration {version} is not registered.")

        connection = _connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            actual_version = _existing_schema_version(connection)
            if actual_version >= version:
                connection.rollback()
                continue
            if actual_version != version - 1:
                raise RuntimeError(
                    "Database schema changed while migrations were running "
                    f"(expected {version - 1}, found {actual_version})."
                )
            migration.apply(connection)
            connection.execute(
                """
                INSERT INTO schema_migrations(version, name, applied_at)
                VALUES (?, ?, ?)
                """,
                (migration.version, migration.name, int(time.time())),
            )
            _set_schema_version(connection, migration.version)
            connection.commit()
        except Exception as exc:
            connection.rollback()
            raise RuntimeError(
                f"Database migration {migration.version} ({migration.name}) failed; "
                "all changes from this migration were rolled back."
            ) from exc
        finally:
            connection.close()


def init_db() -> None:
    with database_core._DB_LOCK:
        connection = _connect()
        try:
            existing_version = _existing_schema_version(connection)
        finally:
            connection.close()

        if existing_version > DATABASE_SCHEMA_VERSION:
            raise RuntimeError(
                "The database was created by a newer Pi-hole Manager version "
                f"(schema {existing_version}; supported up to {DATABASE_SCHEMA_VERSION})."
            )

        if existing_version <= LEGACY_SCHEMA_VERSION:
            database_core.init_db()
            existing_version = LEGACY_SCHEMA_VERSION

        _apply_pending_migrations(existing_version)
