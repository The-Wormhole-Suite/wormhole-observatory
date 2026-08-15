from __future__ import annotations

import sqlite3
import threading
import time
from collections import Counter
from collections.abc import Iterable, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from pihole_manager.config import database_path, load_options

_DB_LOCK = threading.RLock()
DATABASE_SCHEMA_VERSION = 11
LEGACY_SCHEMA_BASELINE_VERSION = 7


@contextmanager
def _connection():
    connection = sqlite3.connect(database_path(), timeout=30)
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


def init_db() -> None:
    with _DB_LOCK, _connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        existing_version = _existing_schema_version(connection)
        if existing_version > DATABASE_SCHEMA_VERSION:
            raise RuntimeError(
                "The database was created by a newer Pi-hole Manager version "
                f"(schema {existing_version}; supported up to {DATABASE_SCHEMA_VERSION})."
            )
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS staging_domains (
                domain TEXT PRIMARY KEY,
                state TEXT NOT NULL DEFAULT 'queued',
                attempts INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                last_error TEXT NOT NULL DEFAULT '',
                priority INTEGER NOT NULL DEFAULT 0,
                source TEXT NOT NULL DEFAULT '',
                pool_id TEXT NOT NULL DEFAULT 'background',
                available_at INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_staging_state_created
                ON staging_domains(state, created_at);

            CREATE TABLE IF NOT EXISTS domains (
                domain TEXT PRIMARY KEY,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                query_count INTEGER NOT NULL DEFAULT 0,
                last_classified_at INTEGER,
                next_recheck_at INTEGER,
                last_researched_at INTEGER,
                current_policy TEXT NOT NULL DEFAULT 'unknown',
                current_service TEXT NOT NULL DEFAULT '',
                current_service_role TEXT NOT NULL DEFAULT 'unknown'
            );

            CREATE INDEX IF NOT EXISTS idx_domains_recheck
                ON domains(next_recheck_at, last_seen);

            CREATE TABLE IF NOT EXISTS query_observations (
                domain TEXT NOT NULL REFERENCES domains(domain) ON DELETE CASCADE,
                client TEXT NOT NULL DEFAULT '',
                query_type TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT '',
                bucket_start INTEGER NOT NULL,
                query_count INTEGER NOT NULL DEFAULT 0,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                PRIMARY KEY(domain, client, query_type, status, bucket_start)
            );

            CREATE TABLE IF NOT EXISTS domain_tags (
                domain TEXT NOT NULL REFERENCES domains(domain) ON DELETE CASCADE,
                tag TEXT NOT NULL,
                source TEXT NOT NULL,
                confidence REAL NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY(domain, tag, source)
            );

            CREATE TABLE IF NOT EXISTS review (
                domain TEXT PRIMARY KEY,
                categories TEXT NOT NULL DEFAULT '',
                policy TEXT NOT NULL DEFAULT 'unknown',
                short TEXT NOT NULL DEFAULT '',
                details TEXT NOT NULL DEFAULT '',
                provider TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'new',
                service TEXT NOT NULL DEFAULT '',
                service_role TEXT NOT NULL DEFAULT 'unknown',
                privacy_risk INTEGER NOT NULL DEFAULT 0,
                security_risk INTEGER NOT NULL DEFAULT 0,
                breakage_risk INTEGER NOT NULL DEFAULT 50,
                confidence REAL NOT NULL DEFAULT 0,
                needs_review INTEGER NOT NULL DEFAULT 1,
                review_reason TEXT NOT NULL DEFAULT '',
                next_recheck_at INTEGER,
                planned_action TEXT NOT NULL DEFAULT '',
                action_status TEXT NOT NULL DEFAULT 'none',
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS classification_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL REFERENCES domains(domain) ON DELETE CASCADE,
                provider TEXT NOT NULL,
                provider_id TEXT NOT NULL DEFAULT '',
                model TEXT NOT NULL DEFAULT '',
                profile TEXT NOT NULL DEFAULT '',
                prompt_hash TEXT NOT NULL DEFAULT '',
                policy TEXT NOT NULL,
                primary_tag TEXT NOT NULL DEFAULT 'unknown',
                tags_json TEXT NOT NULL DEFAULT '[]',
                service TEXT NOT NULL DEFAULT '',
                service_role TEXT NOT NULL DEFAULT 'unknown',
                privacy_risk INTEGER NOT NULL DEFAULT 0,
                security_risk INTEGER NOT NULL DEFAULT 0,
                breakage_risk INTEGER NOT NULL DEFAULT 50,
                confidence REAL NOT NULL DEFAULT 0,
                needs_review INTEGER NOT NULL DEFAULT 1,
                review_reason TEXT NOT NULL DEFAULT '',
                short TEXT NOT NULL DEFAULT '',
                details TEXT NOT NULL DEFAULT '',
                raw_text TEXT NOT NULL DEFAULT '',
                planned_action TEXT NOT NULL DEFAULT '',
                action_status TEXT NOT NULL DEFAULT 'none',
                analysis_run_id TEXT NOT NULL DEFAULT '',
                pool_id TEXT NOT NULL DEFAULT '',
                pool_mode TEXT NOT NULL DEFAULT '',
                is_primary INTEGER NOT NULL DEFAULT 1,
                latency_ms INTEGER NOT NULL DEFAULT 0,
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_classification_domain_created
                ON classification_runs(domain, created_at DESC);

            CREATE TABLE IF NOT EXISTS research_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL REFERENCES domains(domain) ON DELETE CASCADE,
                provider TEXT NOT NULL,
                kind TEXT NOT NULL,
                title TEXT NOT NULL DEFAULT '',
                summary TEXT NOT NULL DEFAULT '',
                source_url TEXT NOT NULL DEFAULT '',
                confidence REAL NOT NULL DEFAULT 0,
                signal_type TEXT NOT NULL DEFAULT 'context',
                verdict TEXT NOT NULL DEFAULT 'unknown',
                decision_relevant INTEGER NOT NULL DEFAULT 0,
                raw_json TEXT NOT NULL DEFAULT '{}',
                retrieved_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_research_domain_expiry
                ON research_findings(domain, expires_at, retrieved_at DESC);

            CREATE TABLE IF NOT EXISTS domain_locks (
                domain TEXT PRIMARY KEY REFERENCES domains(domain) ON DELETE CASCADE,
                list_type TEXT NOT NULL CHECK(list_type IN ('allow', 'deny')),
                reason TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS review_tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL REFERENCES domains(domain) ON DELETE CASCADE,
                reason TEXT NOT NULL,
                priority TEXT NOT NULL DEFAULT 'normal',
                status TEXT NOT NULL DEFAULT 'open',
                source TEXT NOT NULL DEFAULT '',
                decision TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_review_tasks_status_priority
                ON review_tasks(status, priority, created_at);

            CREATE TABLE IF NOT EXISTS app_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS analysis_runs (
                id TEXT PRIMARY KEY,
                pool_id TEXT NOT NULL,
                mode TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT '',
                dossier_hash TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'running',
                error TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                completed_at INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_analysis_runs_created
                ON analysis_runs(created_at DESC);

            CREATE TABLE IF NOT EXISTS provider_health (
                provider_id TEXT PRIMARY KEY,
                state TEXT NOT NULL DEFAULT 'unknown',
                cooldown_until REAL NOT NULL DEFAULT 0,
                consecutive_failures INTEGER NOT NULL DEFAULT 0,
                last_error TEXT NOT NULL DEFAULT '',
                last_status_code INTEGER NOT NULL DEFAULT 0,
                last_latency_ms INTEGER NOT NULL DEFAULT 0,
                last_seen_at REAL NOT NULL DEFAULT 0,
                updated_at REAL NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS quota_usage (
                scope_key TEXT NOT NULL,
                metric TEXT NOT NULL,
                bucket_start INTEGER NOT NULL,
                amount REAL NOT NULL DEFAULT 0,
                PRIMARY KEY(scope_key, metric, bucket_start)
            );

            CREATE TABLE IF NOT EXISTS quota_reservations (
                id TEXT PRIMARY KEY,
                scope_key TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                model TEXT NOT NULL DEFAULT '',
                request_units REAL NOT NULL DEFAULT 0,
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                domain_count INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_quota_reservations_expiry
                ON quota_reservations(expires_at);

            CREATE TABLE IF NOT EXISTS runtime_quota_state (
                scope_key TEXT NOT NULL,
                metric TEXT NOT NULL,
                window_seconds INTEGER NOT NULL,
                limit_amount REAL NOT NULL DEFAULT 0,
                remaining_amount REAL NOT NULL DEFAULT 0,
                reset_at REAL NOT NULL DEFAULT 0,
                observed_at REAL NOT NULL DEFAULT 0,
                source TEXT NOT NULL DEFAULT 'live_header',
                PRIMARY KEY(scope_key, metric, window_seconds)
            );

            CREATE TABLE IF NOT EXISTS model_benchmark_runs (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                profile TEXT NOT NULL DEFAULT '',
                prompt_hash TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'running',
                error TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                completed_at INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_benchmark_runs_created
                ON model_benchmark_runs(created_at DESC);

            CREATE TABLE IF NOT EXISTS model_benchmark_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES model_benchmark_runs(id) ON DELETE CASCADE,
                provider_id TEXT NOT NULL,
                provider_name TEXT NOT NULL,
                model TEXT NOT NULL,
                status TEXT NOT NULL,
                error TEXT NOT NULL DEFAULT '',
                latency_ms INTEGER NOT NULL DEFAULT 0,
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                classification_json TEXT NOT NULL DEFAULT '{}',
                raw_text TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_benchmark_results_run
                ON model_benchmark_results(run_id, id);
            """
        )
        _run_schema_migrations(connection, existing_version)


def _existing_schema_version(connection: sqlite3.Connection) -> int:
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


def _run_schema_migrations(
    connection: sqlite3.Connection,
    existing_version: int,
) -> None:
    # Schema versions up to 7 predate the explicit migration registry.  Treat
    # them as one compatibility baseline and migrate forward from version 8.
    current_version = max(existing_version, LEGACY_SCHEMA_BASELINE_VERSION)
    if current_version >= DATABASE_SCHEMA_VERSION:
        if existing_version == 0:
            _set_schema_version(connection, DATABASE_SCHEMA_VERSION)
        return

    for target_version in range(current_version + 1, DATABASE_SCHEMA_VERSION + 1):
        migration = SCHEMA_MIGRATIONS.get(target_version)
        if migration is None:
            raise RuntimeError(
                f"Missing database migration for schema version {target_version}."
            )

        savepoint = f"schema_migration_{target_version}"
        connection.execute(f"SAVEPOINT {savepoint}")
        try:
            migration(connection)
            _set_schema_version(connection, target_version)
            connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        except Exception:
            connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
            connection.execute(f"RELEASE SAVEPOINT {savepoint}")
            raise


def _migrate_staging_table(connection: sqlite3.Connection) -> None:
    columns = {
        str(row["name"]): row for row in connection.execute("PRAGMA table_info(staging_domains)")
    }
    additions = {
        "priority": "INTEGER NOT NULL DEFAULT 0",
        "source": "TEXT NOT NULL DEFAULT ''",
        "pool_id": "TEXT NOT NULL DEFAULT 'background'",
        "available_at": "INTEGER NOT NULL DEFAULT 0",
    }
    for name, definition in additions.items():
        if name not in columns:
            connection.execute(f"ALTER TABLE staging_domains ADD COLUMN {name} {definition}")
    connection.execute(
        """
        UPDATE staging_domains
        SET pool_id = 'realtime'
        WHERE priority >= 100 OR source LIKE 'manual_%'
        """
    )
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_staging_pool_state_created
        ON staging_domains(pool_id, state, priority DESC, created_at)
        """
    )


def _migrate_classification_table(connection: sqlite3.Connection) -> None:
    columns = {
        str(row["name"]): row
        for row in connection.execute("PRAGMA table_info(classification_runs)")
    }
    additions = {
        "planned_action": "TEXT NOT NULL DEFAULT ''",
        "action_status": "TEXT NOT NULL DEFAULT 'none'",
        "provider_id": "TEXT NOT NULL DEFAULT ''",
        "analysis_run_id": "TEXT NOT NULL DEFAULT ''",
        "pool_id": "TEXT NOT NULL DEFAULT ''",
        "pool_mode": "TEXT NOT NULL DEFAULT ''",
        "is_primary": "INTEGER NOT NULL DEFAULT 1",
        "latency_ms": "INTEGER NOT NULL DEFAULT 0",
        "input_tokens": "INTEGER NOT NULL DEFAULT 0",
        "output_tokens": "INTEGER NOT NULL DEFAULT 0",
    }
    for name, definition in additions.items():
        if name not in columns:
            connection.execute(f"ALTER TABLE classification_runs ADD COLUMN {name} {definition}")


def _migrate_research_table(connection: sqlite3.Connection) -> None:
    columns = {
        str(row["name"]): row for row in connection.execute("PRAGMA table_info(research_findings)")
    }
    additions = {
        "signal_type": "TEXT NOT NULL DEFAULT 'context'",
        "verdict": "TEXT NOT NULL DEFAULT 'unknown'",
        "decision_relevant": "INTEGER NOT NULL DEFAULT 0",
        "raw_json": "TEXT NOT NULL DEFAULT '{}'",
    }
    for name, definition in additions.items():
        if name not in columns:
            connection.execute(f"ALTER TABLE research_findings ADD COLUMN {name} {definition}")
    if "raw_data" in columns:
        connection.execute(
            """
            UPDATE research_findings
            SET raw_json = CAST(raw_data AS TEXT)
            WHERE COALESCE(raw_json, '{}') = '{}'
              AND raw_data IS NOT NULL
              AND CAST(raw_data AS TEXT) != ''
            """
        )


def _migrate_quota_tables(connection: sqlite3.Connection) -> None:
    columns = {
        str(row["name"]): row for row in connection.execute("PRAGMA table_info(quota_reservations)")
    }
    if "domain_count" not in columns:
        connection.execute(
            "ALTER TABLE quota_reservations ADD COLUMN domain_count INTEGER NOT NULL DEFAULT 1"
        )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS runtime_quota_state (
            scope_key TEXT NOT NULL,
            metric TEXT NOT NULL,
            window_seconds INTEGER NOT NULL,
            limit_amount REAL NOT NULL DEFAULT 0,
            remaining_amount REAL NOT NULL DEFAULT 0,
            reset_at REAL NOT NULL DEFAULT 0,
            observed_at REAL NOT NULL DEFAULT 0,
            source TEXT NOT NULL DEFAULT 'live_header',
            PRIMARY KEY(scope_key, metric, window_seconds)
        )
        """
    )


def _migrate_review_table(connection: sqlite3.Connection) -> None:
    columns = {str(row["name"]): row for row in connection.execute("PRAGMA table_info(review)")}
    additions = {
        "policy": "TEXT NOT NULL DEFAULT 'unknown'",
        "short": "TEXT NOT NULL DEFAULT ''",
        "provider": "TEXT NOT NULL DEFAULT ''",
        "status": "TEXT NOT NULL DEFAULT 'new'",
        "service": "TEXT NOT NULL DEFAULT ''",
        "service_role": "TEXT NOT NULL DEFAULT 'unknown'",
        "privacy_risk": "INTEGER NOT NULL DEFAULT 0",
        "security_risk": "INTEGER NOT NULL DEFAULT 0",
        "breakage_risk": "INTEGER NOT NULL DEFAULT 50",
        "confidence": "REAL NOT NULL DEFAULT 0",
        "needs_review": "INTEGER NOT NULL DEFAULT 1",
        "review_reason": "TEXT NOT NULL DEFAULT ''",
        "next_recheck_at": "INTEGER",
        "planned_action": "TEXT NOT NULL DEFAULT ''",
        "action_status": "TEXT NOT NULL DEFAULT 'none'",
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


def _migration_8(connection: sqlite3.Connection) -> None:
    _migrate_staging_table(connection)


def _migration_9(connection: sqlite3.Connection) -> None:
    _migrate_review_table(connection)


def _migration_10(connection: sqlite3.Connection) -> None:
    _migrate_classification_table(connection)
    _migrate_research_table(connection)


def _migration_11(connection: sqlite3.Connection) -> None:
    _migrate_quota_tables(connection)


SCHEMA_MIGRATIONS = {
    8: _migration_8,
    9: _migration_9,
    10: _migration_10,
    11: _migration_11,
}


def _normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def _normalize_tags(tags: object) -> list[str]:
    if isinstance(tags, str):
        values = tags.replace(";", ",").split(",")
    elif isinstance(tags, Iterable):
        values = [str(value) for value in tags]
    else:
        return []
    normalized = []
    seen = set()
    for value in values:
        tag = value.strip().lower()
        if not tag or tag in seen:
            continue
        seen.add(tag)
        normalized.append(tag)
    return normalized


def _ensure_domain(
    connection: sqlite3.Connection,
    domain: str,
    *,
    seen_at: int | None = None,
    query_increment: int = 0,
) -> str:
    normalized = _normalize_domain(domain)
    if not normalized:
        raise ValueError("domain must not be empty")
    now = seen_at or int(time.time())
    connection.execute(
        """
        INSERT INTO domains(domain, first_seen, last_seen, query_count)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(domain) DO UPDATE SET
            first_seen = MIN(first_seen, excluded.first_seen),
            last_seen = MAX(last_seen, excluded.last_seen),
            query_count = query_count + excluded.query_count
        """,
        (normalized, now, now, max(0, int(query_increment))),
    )
    return normalized


# ---------- Queue ----------


@dataclass(frozen=True, slots=True)
class QueueEnqueueResult:
    requested: int = 0
    queued: int = 0
    requeued: int = 0
    already_pending: int = 0
    skipped_locked: int = 0
    skipped_filtered: int = 0

    @property
    def accepted(self) -> int:
        return self.queued + self.requeued + self.already_pending


def _queue_pool_id(pool_id: str, priority: int, source: str) -> str:
    normalized = pool_id.strip().lower()
    if normalized in {"realtime", "background"}:
        return normalized
    if priority >= 100 or source.strip().lower().startswith("manual_"):
        return "realtime"
    return "background"


def _domain_matches_suffix(domain: str, suffixes: tuple[str, ...]) -> bool:
    for suffix in suffixes:
        normalized = suffix.strip().lower().lstrip(".").rstrip(".")
        if not normalized:
            continue
        if domain == normalized or domain.endswith(f".{normalized}"):
            return True
    return False


def _queue_filters() -> tuple[tuple[str, ...], tuple[str, ...]]:
    options = load_options().queue
    return options.include_suffixes, options.exclude_suffixes


def _queue_domain_allowed(domain: str) -> bool:
    include_suffixes, exclude_suffixes = _queue_filters()
    if exclude_suffixes and _domain_matches_suffix(domain, exclude_suffixes):
        return False
    if include_suffixes and not _domain_matches_suffix(domain, include_suffixes):
        return False
    return True


def staging_enqueue_detailed(
    domains: Sequence[str],
    *,
    priority: int = 0,
    source: str = "",
    pool_id: str = "",
    preserve_existing: bool = True,
) -> QueueEnqueueResult:
    now = int(time.time())
    requested = queued = requeued = already_pending = skipped_locked = skipped_filtered = 0
    with _DB_LOCK, _connection() as connection:
        for raw_domain in domains:
            domain = _normalize_domain(raw_domain)
            if not domain:
                continue
            requested += 1
            if not _queue_domain_allowed(domain):
                skipped_filtered += 1
                continue
            if connection.execute(
                "SELECT 1 FROM domain_locks WHERE domain = ?", (domain,)
            ).fetchone():
                skipped_locked += 1
                continue
            _ensure_domain(connection, domain)
            effective_pool = _queue_pool_id(pool_id, priority, source)
            existing = connection.execute(
                "SELECT state, priority, pool_id FROM staging_domains WHERE domain = ?",
                (domain,),
            ).fetchone()
            if existing is None:
                connection.execute(
                    """
                    INSERT INTO staging_domains(
                        domain, state, attempts, created_at, updated_at, last_error,
                        priority, source, pool_id, available_at
                    ) VALUES (?, 'queued', 0, ?, ?, '', ?, ?, ?, 0)
                    """,
                    (domain, now, now, int(priority), source, effective_pool),
                )
                queued += 1
                continue
            if preserve_existing and str(existing["state"]) in {"queued", "processing"}:
                connection.execute(
                    """
                    UPDATE staging_domains
                    SET priority = MAX(priority, ?),
                        pool_id = CASE
                            WHEN ? = 'realtime' THEN 'realtime'
                            ELSE pool_id
                        END,
                        updated_at = ?
                    WHERE domain = ?
                    """,
                    (int(priority), effective_pool, now, domain),
                )
                already_pending += 1
                continue
            connection.execute(
                """
                UPDATE staging_domains
                SET state = 'queued', attempts = 0, updated_at = ?, last_error = '',
                    priority = ?, source = ?, pool_id = ?, available_at = 0
                WHERE domain = ?
                """,
                (now, int(priority), source, effective_pool, domain),
            )
            requeued += 1
    return QueueEnqueueResult(
        requested=requested,
        queued=queued,
        requeued=requeued,
        already_pending=already_pending,
        skipped_locked=skipped_locked,
        skipped_filtered=skipped_filtered,
    )


def staging_enqueue(
    domains: Sequence[str],
    *,
    priority: int = 0,
    source: str = "",
    pool_id: str = "",
    preserve_existing: bool = True,
) -> int:
    result = staging_enqueue_detailed(
        domains,
        priority=priority,
        source=source,
        pool_id=pool_id,
        preserve_existing=preserve_existing,
    )
    return result.queued + result.requeued


def staging_claim(limit: int, *, pool_id: str = "") -> list[str]:
    if limit <= 0:
        return []
    now = int(time.time())
    with _DB_LOCK, _connection() as connection:
        params: list[object] = [now]
        pool_clause = ""
        if pool_id:
            pool_clause = " AND pool_id = ?"
            params.append(pool_id.strip().lower())
        params.append(int(limit))
        rows = connection.execute(
            f"""
            SELECT domain
            FROM staging_domains
            WHERE state = 'queued'
              AND available_at <= ?
              {pool_clause}
            ORDER BY priority DESC, created_at, domain
            LIMIT ?
            """,
            tuple(params),
        ).fetchall()
        domains = [str(row["domain"]) for row in rows]
        if domains:
            placeholders = ",".join("?" for _ in domains)
            connection.execute(
                f"""
                UPDATE staging_domains
                SET state = 'processing', updated_at = ?
                WHERE domain IN ({placeholders})
                  AND state = 'queued'
                """,
                (now, *domains),
            )
        return domains


def staging_ack(domain: str) -> None:
    normalized = _normalize_domain(domain)
    if not normalized:
        return
    with _DB_LOCK, _connection() as connection:
        connection.execute("DELETE FROM staging_domains WHERE domain = ?", (normalized,))


def staging_fail(
    domain: str,
    error: str,
    *,
    max_attempts: int = 3,
) -> str:
    normalized = _normalize_domain(domain)
    if not normalized:
        return "ignored"
    now = int(time.time())
    with _DB_LOCK, _connection() as connection:
        row = connection.execute(
            "SELECT attempts FROM staging_domains WHERE domain = ?", (normalized,)
        ).fetchone()
        if row is None:
            return "missing"
        attempts = int(row["attempts"]) + 1
        if attempts >= max(1, int(max_attempts)):
            connection.execute("DELETE FROM staging_domains WHERE domain = ?", (normalized,))
            return "dropped"
        connection.execute(
            """
            UPDATE staging_domains
            SET state = 'queued', attempts = ?, updated_at = ?, last_error = ?, available_at = 0
            WHERE domain = ?
            """,
            (attempts, now, error[:1000], normalized),
        )
        return "requeued"


def staging_defer(domain: str, reason: str, retry_at: float) -> bool:
    normalized = _normalize_domain(domain)
    if not normalized:
        return False
    now = int(time.time())
    available_at = max(now, int(retry_at))
    with _DB_LOCK, _connection() as connection:
        cursor = connection.execute(
            """
            UPDATE staging_domains
            SET state = 'queued', updated_at = ?, last_error = ?, available_at = ?
            WHERE domain = ?
            """,
            (now, reason[:1000], available_at, normalized),
        )
        return cursor.rowcount > 0


def staging_requeue_processing() -> int:
    now = int(time.time())
    with _DB_LOCK, _connection() as connection:
        cursor = connection.execute(
            """
            UPDATE staging_domains
            SET state = 'queued', updated_at = ?, available_at = 0
            WHERE state = 'processing'
            """,
            (now,),
        )
        return cursor.rowcount


def staging_list(*, pool_id: str = "") -> list[dict[str, Any]]:
    with _DB_LOCK, _connection() as connection:
        params: tuple[object, ...] = ()
        where = ""
        if pool_id:
            where = "WHERE pool_id = ?"
            params = (pool_id.strip().lower(),)
        rows = connection.execute(
            f"""
            SELECT domain, state, attempts, created_at, updated_at, last_error,
                   priority, source, pool_id, available_at
            FROM staging_domains
            {where}
            ORDER BY priority DESC, created_at, domain
            """,
            params,
        ).fetchall()
    return [dict(row) for row in rows]


def staging_ready(
    trigger_size: int,
    max_wait_sec: int,
    *,
    pool_id: str = "",
) -> bool:
    now = int(time.time())
    with _DB_LOCK, _connection() as connection:
        params: list[object] = [now]
        pool_clause = ""
        if pool_id:
            pool_clause = " AND pool_id = ?"
            params.append(pool_id.strip().lower())
        row = connection.execute(
            f"""
            SELECT COUNT(*) AS queued_count,
                   MIN(created_at) AS oldest_created,
                   MAX(priority) AS max_priority
            FROM staging_domains
            WHERE state = 'queued'
              AND available_at <= ?
              {pool_clause}
            """,
            tuple(params),
        ).fetchone()
    queued_count = int(row["queued_count"] or 0)
    if queued_count <= 0:
        return False
    if int(row["max_priority"] or 0) >= 100:
        return True
    if queued_count >= max(1, int(trigger_size)):
        return True
    oldest_created = int(row["oldest_created"] or now)
    return now - oldest_created >= max(1, int(max_wait_sec))


def queue_domains_needing_analysis(domains: Sequence[str], *, source: str = "") -> int:
    candidates = []
    with _DB_LOCK, _connection() as connection:
        for raw_domain in domains:
            domain = _normalize_domain(raw_domain)
            if not domain:
                continue
            _ensure_domain(connection, domain)
            locked = connection.execute(
                "SELECT 1 FROM domain_locks WHERE domain = ?", (domain,)
            ).fetchone()
            if locked:
                continue
            classified = connection.execute(
                "SELECT last_classified_at FROM domains WHERE domain = ?", (domain,)
            ).fetchone()
            if classified and classified["last_classified_at"]:
                continue
            pending = connection.execute(
                "SELECT 1 FROM staging_domains WHERE domain = ?", (domain,)
            ).fetchone()
            if pending:
                continue
            candidates.append(domain)
    return staging_enqueue(candidates, source=source)


def record_query_observations(rows: Sequence[dict[str, Any]]) -> int:
    bucket_seconds = 300
    recorded = 0
    with _DB_LOCK, _connection() as connection:
        for row in rows:
            domain = _normalize_domain(str(row.get("domain") or row.get("query") or ""))
            if not domain:
                continue
            timestamp = int(float(row.get("time") or row.get("timestamp") or time.time()))
            bucket_start = timestamp - (timestamp % bucket_seconds)
            client = str(row.get("client") or row.get("client_ip") or "")
            query_type = str(row.get("type") or row.get("query_type") or "")
            status = str(row.get("status") or row.get("reply") or "")
            _ensure_domain(connection, domain, seen_at=timestamp, query_increment=1)
            connection.execute(
                """
                INSERT INTO query_observations(
                    domain, client, query_type, status, bucket_start,
                    query_count, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                ON CONFLICT(domain, client, query_type, status, bucket_start)
                DO UPDATE SET
                    query_count = query_count + 1,
                    first_seen = MIN(first_seen, excluded.first_seen),
                    last_seen = MAX(last_seen, excluded.last_seen)
                """,
                (domain, client, query_type, status, bucket_start, timestamp, timestamp),
            )
            recorded += 1
    return recorded


def domain_activity_context(domain: str) -> dict[str, Any]:
    normalized = _normalize_domain(domain)
    if not normalized:
        return {}
    with _DB_LOCK, _connection() as connection:
        domain_row = connection.execute(
            "SELECT * FROM domains WHERE domain = ?", (normalized,)
        ).fetchone()
        if domain_row is None:
            return {}
        observation_rows = connection.execute(
            """
            SELECT client, query_type, status, SUM(query_count) AS query_count,
                   MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen
            FROM query_observations
            WHERE domain = ?
            GROUP BY client, query_type, status
            ORDER BY query_count DESC, client, query_type, status
            """,
            (normalized,),
        ).fetchall()
    clients = Counter()
    query_types = Counter()
    statuses = Counter()
    first_seen = int(domain_row["first_seen"])
    last_seen = int(domain_row["last_seen"])
    for row in observation_rows:
        count = int(row["query_count"] or 0)
        if row["client"]:
            clients[str(row["client"])] += count
        if row["query_type"]:
            query_types[str(row["query_type"])] += count
        if row["status"]:
            statuses[str(row["status"])] += count
        first_seen = min(first_seen, int(row["first_seen"] or first_seen))
        last_seen = max(last_seen, int(row["last_seen"] or last_seen))
    return {
        "domain": normalized,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "query_count": int(domain_row["query_count"] or 0),
        "clients": dict(clients),
        "query_types": dict(query_types),
        "statuses": dict(statuses),
        "current_policy": str(domain_row["current_policy"]),
        "current_service": str(domain_row["current_service"]),
        "current_service_role": str(domain_row["current_service_role"]),
    }


def domain_browser_search(
    *,
    search: str = "",
    tag: str = "",
    policy: str = "",
    service_role: str = "",
    review_state: str = "",
    limit: int = 200,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    filters: list[str] = []
    params: list[object] = []
    if search.strip():
        value = f"%{search.strip().lower()}%"
        filters.append(
            "(LOWER(d.domain) LIKE ? OR LOWER(COALESCE(r.service, '')) LIKE ? "
            "OR LOWER(COALESCE(r.short, '')) LIKE ?)"
        )
        params.extend([value, value, value])
    if tag.strip():
        filters.append(
            "EXISTS (SELECT 1 FROM domain_tags t WHERE t.domain = d.domain AND t.tag = ?)"
        )
        params.append(tag.strip().lower())
    if policy.strip():
        filters.append("COALESCE(r.policy, d.current_policy, 'unknown') = ?")
        params.append(policy.strip().lower())
    if service_role.strip():
        filters.append("COALESCE(r.service_role, d.current_service_role, 'unknown') = ?")
        params.append(service_role.strip().lower())
    if review_state == "required":
        filters.append("COALESCE(r.needs_review, 0) = 1")
    elif review_state == "resolved":
        filters.append("COALESCE(r.needs_review, 0) = 0")
    where = f"WHERE {' AND '.join(filters)}" if filters else ""

    query = f"""
        WITH latest AS (
            SELECT c.*
            FROM classification_runs c
            JOIN (
                SELECT domain, MAX(id) AS max_id
                FROM classification_runs
                GROUP BY domain
            ) newest ON newest.max_id = c.id
        ),
        review_fallback AS (
            SELECT
                rv.domain,
                rv.policy,
                'unknown' AS primary_tag,
                rv.categories AS tags_json,
                rv.service,
                rv.service_role,
                rv.privacy_risk,
                rv.security_risk,
                rv.breakage_risk,
                rv.confidence,
                rv.needs_review,
                rv.review_reason,
                rv.short,
                rv.details,
                rv.provider,
                '' AS model,
                '' AS profile,
                rv.updated_at AS created_at
            FROM review rv
            WHERE NOT EXISTS (
                SELECT 1 FROM classification_runs c WHERE c.domain = rv.domain
            )
        ),
        combined AS (
            SELECT
                domain, policy, primary_tag, tags_json, service, service_role,
                privacy_risk, security_risk, breakage_risk, confidence,
                needs_review, review_reason, short, details, provider, model,
                profile, created_at
            FROM latest
            UNION ALL
            SELECT * FROM review_fallback
        )
        SELECT d.domain, d.first_seen, d.last_seen, d.query_count,
               d.last_classified_at, d.next_recheck_at, d.last_researched_at,
               COALESCE(r.policy, d.current_policy, 'unknown') AS policy,
               COALESCE(r.primary_tag, 'unknown') AS primary_tag,
               COALESCE(r.tags_json, '[]') AS tags_json,
               COALESCE(r.service, d.current_service, '') AS service,
               COALESCE(r.service_role, d.current_service_role, 'unknown') AS service_role,
               COALESCE(r.privacy_risk, 0) AS privacy_risk,
               COALESCE(r.security_risk, 0) AS security_risk,
               COALESCE(r.breakage_risk, 50) AS breakage_risk,
               COALESCE(r.confidence, 0) AS confidence,
               COALESCE(r.needs_review, 0) AS needs_review,
               COALESCE(r.review_reason, '') AS review_reason,
               COALESCE(r.short, '') AS short,
               COALESCE(r.details, '') AS details,
               COALESCE(r.provider, '') AS provider,
               COALESCE(r.model, '') AS model,
               COALESCE(r.profile, '') AS profile,
               r.created_at AS classified_at,
               CASE WHEN l.domain IS NULL THEN '' ELSE l.list_type END AS lock_type,
               CASE WHEN l.domain IS NULL THEN '' ELSE l.reason END AS lock_reason
        FROM domains d
        LEFT JOIN combined r ON r.domain = d.domain
        LEFT JOIN domain_locks l ON l.domain = d.domain
        {where}
        ORDER BY d.last_seen DESC, d.domain ASC
    """
    with _DB_LOCK, _connection() as connection:
        rows = connection.execute(
            f"SELECT * FROM ({query}) LIMIT ? OFFSET ?",
            (*params, max(1, int(limit)), max(0, int(offset))),
        ).fetchall()
        count_row = connection.execute(
            f"SELECT COUNT(*) AS count FROM ({query})",
            tuple(params),
        ).fetchone()
    results = []
    for row in rows:
        item = dict(row)
        item["tags"] = _decode_tags(item.pop("tags_json", "[]"))
        results.append(item)
    return results, int(count_row["count"] or 0)


def _decode_tags(value: object) -> list[str]:
    import json

    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        if stripped.startswith("["):
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError:
                parsed = stripped
            if isinstance(parsed, list):
                return _normalize_tags(parsed)
        return _normalize_tags(stripped)
    return _normalize_tags(value)


def save_classification_run(
    classification,
    *,
    model: str = "",
    profile: str = "",
    prompt_hash: str = "",
    expires_at: int | None = None,
    planned_action: str = "",
    action_status: str = "none",
    provider_id: str = "",
    analysis_run_id: str = "",
    pool_id: str = "",
    pool_mode: str = "",
    is_primary: bool = True,
    latency_ms: int = 0,
    input_tokens: int = 0,
    output_tokens: int = 0,
) -> int:
    import json

    now = int(time.time())
    expires = expires_at or (now + max(1, int(classification.recheck_after_days)) * 86400)
    tags = _normalize_tags(classification.tags or (classification.category,))
    primary_tag = classification.category or (tags[0] if tags else "unknown")
    with _DB_LOCK, _connection() as connection:
        domain = _ensure_domain(connection, classification.domain)
        cursor = connection.execute(
            """
            INSERT INTO classification_runs(
                domain, provider, provider_id, model, profile, prompt_hash, policy,
                primary_tag, tags_json, service, service_role, privacy_risk,
                security_risk, breakage_risk, confidence, needs_review,
                review_reason, short, details, raw_text, planned_action,
                action_status, analysis_run_id, pool_id, pool_mode, is_primary,
                latency_ms, input_tokens, output_tokens, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                domain,
                classification.provider,
                provider_id,
                model,
                profile,
                prompt_hash,
                classification.policy.value,
                primary_tag,
                json.dumps(tags, ensure_ascii=False),
                classification.service,
                classification.service_role.value,
                int(classification.privacy_risk),
                int(classification.security_risk),
                int(classification.breakage_risk),
                float(classification.confidence),
                1 if classification.needs_review else 0,
                classification.review_reason,
                classification.short,
                classification.details,
                classification.raw_text,
                planned_action,
                action_status,
                analysis_run_id,
                pool_id,
                pool_mode,
                1 if is_primary else 0,
                max(0, int(latency_ms)),
                max(0, int(input_tokens)),
                max(0, int(output_tokens)),
                now,
                expires,
            ),
        )
        connection.execute("DELETE FROM domain_tags WHERE domain = ?", (domain,))
        for tag in tags:
            connection.execute(
                """
                INSERT INTO domain_tags(domain, tag, source, confidence, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (domain, tag, classification.provider, float(classification.confidence), now, now),
            )
        connection.execute(
            """
            UPDATE domains
            SET last_classified_at = ?, next_recheck_at = ?, current_policy = ?,
                current_service = ?, current_service_role = ?
            WHERE domain = ?
            """,
            (
                now,
                expires,
                classification.policy.value,
                classification.service,
                classification.service_role.value,
                domain,
            ),
        )
        return int(cursor.lastrowid)


def classification_history(domain: str, *, limit: int = 20) -> list[dict[str, Any]]:
    import json

    normalized = _normalize_domain(domain)
    if not normalized:
        return []
    with _DB_LOCK, _connection() as connection:
        rows = connection.execute(
            """
            SELECT * FROM classification_runs
            WHERE domain = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (normalized, max(1, int(limit))),
        ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        try:
            item["tags"] = json.loads(item.pop("tags_json", "[]"))
        except (TypeError, json.JSONDecodeError):
            item["tags"] = []
        result.append(item)
    return result


def set_domain_lock(domain: str, list_type: str, reason: str = "") -> None:
    normalized = _normalize_domain(domain)
    normalized_type = list_type.strip().lower()
    if normalized_type not in {"allow", "deny"}:
        raise ValueError("list_type must be 'allow' or 'deny'")
    now = int(time.time())
    with _DB_LOCK, _connection() as connection:
        _ensure_domain(connection, normalized)
        connection.execute(
            """
            INSERT INTO domain_locks(domain, list_type, reason, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(domain) DO UPDATE SET
                list_type = excluded.list_type,
                reason = excluded.reason,
                updated_at = excluded.updated_at
            """,
            (normalized, normalized_type, reason, now, now),
        )
        connection.execute("DELETE FROM staging_domains WHERE domain = ?", (normalized,))


def remove_domain_lock(domain: str) -> int:
    normalized = _normalize_domain(domain)
    if not normalized:
        return 0
    with _DB_LOCK, _connection() as connection:
        cursor = connection.execute("DELETE FROM domain_locks WHERE domain = ?", (normalized,))
        return cursor.rowcount


def get_domain_lock(domain: str) -> dict[str, Any] | None:
    normalized = _normalize_domain(domain)
    if not normalized:
        return None
    with _DB_LOCK, _connection() as connection:
        row = connection.execute(
            "SELECT * FROM domain_locks WHERE domain = ?", (normalized,)
        ).fetchone()
    return dict(row) if row else None


def save_research_findings(findings: Sequence[object]) -> None:
    import json

    with _DB_LOCK, _connection() as connection:
        for finding in findings:
            domain = _ensure_domain(connection, finding.domain)
            raw = getattr(finding, "raw", {}) or {}
            connection.execute(
                """
                INSERT INTO research_findings(
                    domain, provider, kind, title, summary, source_url, confidence,
                    signal_type, verdict, decision_relevant, raw_json,
                    retrieved_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    domain,
                    finding.provider,
                    finding.kind,
                    finding.title,
                    finding.summary,
                    finding.source_url,
                    float(finding.confidence),
                    str(getattr(finding, "signal_type", "context") or "context"),
                    str(getattr(finding, "verdict", "unknown") or "unknown"),
                    1 if bool(getattr(finding, "decision_relevant", False)) else 0,
                    json.dumps(raw, ensure_ascii=False, sort_keys=True, default=str),
                    int(finding.retrieved_at),
                    int(finding.expires_at),
                ),
            )
        if findings:
            domains = sorted({_normalize_domain(finding.domain) for finding in findings})
            now = int(time.time())
            for domain in domains:
                if domain:
                    connection.execute(
                        "UPDATE domains SET last_researched_at = ? WHERE domain = ?",
                        (now, domain),
                    )


def research_findings_get(domain: str, *, include_expired: bool = True) -> list[dict[str, Any]]:
    import json

    normalized = _normalize_domain(domain)
    if not normalized:
        return []
    where = "domain = ?"
    params: list[object] = [normalized]
    if not include_expired:
        where += " AND expires_at >= ?"
        params.append(int(time.time()))
    with _DB_LOCK, _connection() as connection:
        rows = connection.execute(
            f"""
            SELECT * FROM research_findings
            WHERE {where}
            ORDER BY retrieved_at DESC, id DESC
            """,
            tuple(params),
        ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        raw_json = item.pop("raw_json", "{}")
        try:
            item["raw"] = json.loads(raw_json or "{}")
        except (TypeError, json.JSONDecodeError):
            item["raw"] = {}
        item["decision_relevant"] = bool(item.get("decision_relevant"))
        result.append(item)
    return result


def review_task_create(
    domain: str,
    reason: str,
    *,
    priority: str = "normal",
    source: str = "",
) -> int:
    now = int(time.time())
    with _DB_LOCK, _connection() as connection:
        normalized = _ensure_domain(connection, domain)
        cursor = connection.execute(
            """
            INSERT INTO review_tasks(domain, reason, priority, status, source, created_at, updated_at)
            VALUES (?, ?, ?, 'open', ?, ?, ?)
            """,
            (normalized, reason, priority, source, now, now),
        )
        return int(cursor.lastrowid)


def review_tasks(*, status: str = "open", limit: int = 200) -> list[dict[str, Any]]:
    with _DB_LOCK, _connection() as connection:
        if status:
            rows = connection.execute(
                """
                SELECT * FROM review_tasks
                WHERE status = ?
                ORDER BY CASE priority
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'normal' THEN 2
                    ELSE 3
                END, created_at, id
                LIMIT ?
                """,
                (status, max(1, int(limit))),
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM review_tasks ORDER BY created_at, id LIMIT ?",
                (max(1, int(limit)),),
            ).fetchall()
    return [dict(row) for row in rows]


def review_task_decide(task_id: int, decision: str) -> bool:
    now = int(time.time())
    with _DB_LOCK, _connection() as connection:
        cursor = connection.execute(
            """
            UPDATE review_tasks
            SET status = 'resolved', decision = ?, updated_at = ?
            WHERE id = ?
            """,
            (decision, now, int(task_id)),
        )
        return cursor.rowcount > 0


def app_state_get(key: str, default: str = "") -> str:
    with _DB_LOCK, _connection() as connection:
        row = connection.execute("SELECT value FROM app_state WHERE key = ?", (key,)).fetchone()
    return str(row["value"]) if row else default


def app_state_set(key: str, value: object) -> None:
    now = int(time.time())
    with _DB_LOCK, _connection() as connection:
        connection.execute(
            """
            INSERT INTO app_state(key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (key, str(value), now),
        )
