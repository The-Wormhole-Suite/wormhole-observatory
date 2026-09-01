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
DATABASE_SCHEMA_VERSION = 12
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


@contextmanager
def _schema_transaction(connection: sqlite3.Connection):
    """Keep schema creation and every migration in one rollback boundary."""

    savepoint = "schema_initialization"
    connection.execute(f"SAVEPOINT {savepoint}")
    try:
        yield
    except Exception:
        connection.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
        connection.execute(f"RELEASE SAVEPOINT {savepoint}")
        raise
    else:
        connection.execute(f"RELEASE SAVEPOINT {savepoint}")


def _execute_statements(connection: sqlite3.Connection, script: str) -> None:
    """Execute a static SQL script without sqlite3.executescript's implicit COMMIT."""

    pending: list[str] = []
    for line in script.splitlines():
        pending.append(line)
        statement = "\n".join(pending).strip()
        if statement and sqlite3.complete_statement(statement):
            connection.execute(statement)
            pending.clear()
    if "\n".join(pending).strip():
        raise RuntimeError("The database schema script contains an incomplete statement.")


def init_db() -> None:
    with _DB_LOCK, _connection() as connection, _schema_transaction(connection):
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
        _execute_statements(
            connection,
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
                last_success_at REAL NOT NULL DEFAULT 0,
                last_failure_at REAL NOT NULL DEFAULT 0,
                latency_ewma_ms REAL NOT NULL DEFAULT 0,
                updated_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS quota_reservations (
                id TEXT PRIMARY KEY,
                scope_key TEXT NOT NULL,
                provider_id TEXT NOT NULL,
                pool_id TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'reserved',
                domain_count INTEGER NOT NULL DEFAULT 1,
                request_count INTEGER NOT NULL DEFAULT 1,
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                units REAL NOT NULL DEFAULT 0,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                completed_at REAL
            );

            CREATE INDEX IF NOT EXISTS idx_quota_scope_created
                ON quota_reservations(scope_key, created_at);

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
                pool_id TEXT NOT NULL,
                dossier_json TEXT NOT NULL,
                dossier_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'running',
                error TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                completed_at INTEGER
            );

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
    # Schema versions up to 7 predate the explicit migration registry. Treat
    # them as one compatibility baseline and migrate forward from version 8.
    current_version = max(existing_version, LEGACY_SCHEMA_BASELINE_VERSION)
    if current_version >= DATABASE_SCHEMA_VERSION:
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


def _migration_12(connection: sqlite3.Connection) -> None:
    columns = {
        str(row["name"]): row
        for row in connection.execute("PRAGMA table_info(model_benchmark_runs)")
    }
    if "error" not in columns:
        connection.execute(
            "ALTER TABLE model_benchmark_runs ADD COLUMN error TEXT NOT NULL DEFAULT ''"
        )


SCHEMA_MIGRATIONS = {
    8: _migration_8,
    9: _migration_9,
    10: _migration_10,
    11: _migration_11,
    12: _migration_12,
}


def _normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def _normalize_tags(tags: object) -> list[str]:
    if isinstance(tags, str):
        values = tags.replace(";", ",").split(",")
    elif isinstance(tags, Iterable):
        values = [str(value) for value in tags]
    else:
        values = []
    return list(
        dict.fromkeys(value.strip().lower().replace(" ", "_") for value in values if value.strip())
    )


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
    normalized = _normalize_domain(domain)
    for suffix in suffixes:
        normalized_suffix = str(suffix).strip().lower().rstrip(".")
        if normalized_suffix.startswith("*"):
            normalized_suffix = normalized_suffix[1:]
        if not normalized_suffix:
            continue
        if not normalized_suffix.startswith("."):
            normalized_suffix = "." + normalized_suffix
        if normalized == normalized_suffix.lstrip(".") or normalized.endswith(normalized_suffix):
            return True
    return False


def filter_unclassified_domains(domains: Iterable[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in domains:
        domain = _normalize_domain(value)
        if domain and domain not in seen:
            seen.add(domain)
            normalized.append(domain)
    if not normalized:
        return []

    classified: set[str] = set()
    with _DB_LOCK, _connection() as connection:
        for start in range(0, len(normalized), 500):
            chunk = normalized[start : start + 500]
            placeholders = ",".join("?" for _ in chunk)
            rows = connection.execute(
                f"""
                SELECT d.domain
                FROM domains d
                LEFT JOIN review r ON r.domain = d.domain
                WHERE d.domain IN ({placeholders})
                  AND (
                    d.last_classified_at IS NOT NULL
                    OR (
                        r.domain IS NOT NULL
                        AND r.status NOT IN ('queued', 'processing', 'failed')
                        AND (
                            r.policy != 'unknown'
                            OR r.short != ''
                            OR r.details != ''
                            OR r.categories != ''
                        )
                    )
                  )
                """,
                chunk,
            ).fetchall()
            classified.update(str(row["domain"]) for row in rows)
    return [domain for domain in normalized if domain not in classified]


def staging_enqueue_detailed(
    domains: Iterable[str],
    *,
    priority: int = 0,
    source: str = "",
    pool_id: str = "",
    requeue_existing: bool = False,
) -> QueueEnqueueResult:
    now = int(time.time())
    normalized_priority = max(0, int(priority))
    normalized_source = source.strip()
    normalized_pool_id = _queue_pool_id(pool_id, normalized_priority, normalized_source)
    unique_domains: list[str] = []
    seen: set[str] = set()
    for value in domains:
        normalized = _normalize_domain(value)
        if normalized and normalized not in seen:
            seen.add(normalized)
            unique_domains.append(normalized)

    requested = len(unique_domains)
    excluded_suffixes = tuple(load_options().scans.excluded_domain_suffixes)
    filtered_domains = [
        domain for domain in unique_domains if _domain_matches_suffix(domain, excluded_suffixes)
    ]
    if filtered_domains:
        excluded = set(filtered_domains)
        unique_domains = [domain for domain in unique_domains if domain not in excluded]

    queued = 0
    requeued = 0
    already_pending = 0
    skipped_locked = 0
    skipped_filtered = len(filtered_domains)
    with _DB_LOCK, _connection() as connection:
        for value in unique_domains:
            domain = _ensure_domain(connection, value, seen_at=now)
            locked = connection.execute(
                "SELECT 1 FROM domain_locks WHERE domain = ?",
                (domain,),
            ).fetchone()
            if locked is not None:
                skipped_locked += 1
                continue

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
                    (
                        domain,
                        now,
                        now,
                        normalized_priority,
                        normalized_source,
                        normalized_pool_id,
                    ),
                )
                queued += 1
                continue

            state = str(existing["state"] or "queued")
            if state == "processing":
                already_pending += 1
                continue
            if state == "queued":
                connection.execute(
                    """
                    UPDATE staging_domains
                    SET priority = MAX(priority, ?),
                        source = CASE WHEN ? >= priority AND ? != '' THEN ? ELSE source END,
                        pool_id = CASE WHEN ? >= priority THEN ? ELSE pool_id END,
                        available_at = 0
                    WHERE domain = ?
                    """,
                    (
                        normalized_priority,
                        normalized_priority,
                        normalized_source,
                        normalized_source,
                        normalized_priority,
                        normalized_pool_id,
                        domain,
                    ),
                )
                already_pending += 1
                continue

            if state == "failed" or requeue_existing:
                connection.execute(
                    """
                    UPDATE staging_domains
                    SET state = 'queued', attempts = 0, updated_at = ?, last_error = '',
                        priority = MAX(priority, ?),
                        source = CASE WHEN ? != '' THEN ? ELSE source END,
                        pool_id = ?, available_at = 0
                    WHERE domain = ?
                    """,
                    (
                        now,
                        normalized_priority,
                        normalized_source,
                        normalized_source,
                        normalized_pool_id,
                        domain,
                    ),
                )
                requeued += 1
                continue

            already_pending += 1

    return QueueEnqueueResult(
        requested=requested,
        queued=queued,
        requeued=requeued,
        already_pending=already_pending,
        skipped_locked=skipped_locked,
        skipped_filtered=skipped_filtered,
    )


def staging_enqueue(
    domains: Iterable[str],
    *,
    priority: int = 0,
    source: str = "",
    pool_id: str = "",
) -> int:
    result = staging_enqueue_detailed(
        domains,
        priority=priority,
        source=source,
        pool_id=pool_id,
    )
    return result.queued + result.requeued


def queue_domains_for_review(domains: Iterable[str], *, source: str) -> QueueEnqueueResult:
    return staging_enqueue_detailed(
        domains,
        priority=100,
        source=source,
        pool_id="realtime",
        requeue_existing=True,
    )


def queue_domains_needing_analysis(domains: Iterable[str], *, force: bool = False) -> int:
    now = int(time.time())
    candidates: list[str] = []
    with _DB_LOCK, _connection() as connection:
        for value in domains:
            domain = _ensure_domain(connection, value, seen_at=now)
            if force:
                candidates.append(domain)
                continue
            lock = connection.execute(
                "SELECT 1 FROM domain_locks WHERE domain = ?",
                (domain,),
            ).fetchone()
            if lock is not None:
                continue
            row = connection.execute(
                """
                SELECT d.last_classified_at, d.next_recheck_at,
                       EXISTS(
                           SELECT 1
                           FROM classification_runs c
                           WHERE c.domain = d.domain
                             AND c.is_primary = 0
                             AND c.expires_at > ?
                       ) AS has_recent_comparison
                FROM domains d
                WHERE d.domain = ?
                """,
                (now, domain),
            ).fetchone()
            if row and int(row["has_recent_comparison"] or 0):
                continue
            if (
                not row
                or row["last_classified_at"] is None
                or (row["next_recheck_at"] is not None and int(row["next_recheck_at"]) <= now)
            ):
                candidates.append(domain)
    return staging_enqueue(
        candidates,
        priority=100 if force else 0,
        source="manual" if force else "live_query",
        pool_id="realtime" if force else "background",
    )


def queue_due_rechecks(limit: int = 500) -> int:
    now = int(time.time())
    with _DB_LOCK, _connection() as connection:
        rows = connection.execute(
            """
            SELECT d.domain FROM domains d
            LEFT JOIN domain_locks l ON l.domain = d.domain
            WHERE d.next_recheck_at IS NOT NULL AND d.next_recheck_at <= ?
              AND l.domain IS NULL
            ORDER BY d.next_recheck_at, d.last_seen DESC
            LIMIT ?
            """,
            (now, max(1, int(limit))),
        ).fetchall()
    return staging_enqueue(
        (str(row["domain"]) for row in rows),
        priority=10,
        source="scheduled_recheck",
        pool_id="background",
    )


def staging_ready(
    trigger_size: int,
    max_wait_sec: int,
    *,
    pool_id: str | None = None,
) -> bool:
    now = int(time.time())
    normalized_pool = str(pool_id or "").strip().lower()
    pool_clause = ""
    parameters: tuple[Any, ...] = ()
    if normalized_pool in {"realtime", "background"}:
        pool_clause = "AND pool_id = ?"
        parameters = (normalized_pool,)
    with _DB_LOCK, _connection() as connection:
        row = connection.execute(
            f"""
            SELECT COUNT(*) AS queued_count,
                   MIN(created_at) AS oldest_created_at,
                   MAX(priority) AS highest_priority
            FROM staging_domains
            WHERE state = 'queued' AND available_at <= ?
            {pool_clause}
            """,
            (now, *parameters),
        ).fetchone()
    queued_count = int(row["queued_count"] or 0)
    if queued_count == 0:
        return False
    if int(row["highest_priority"] or 0) >= 100:
        return True
    if queued_count >= max(1, int(trigger_size)):
        return True
    oldest = int(row["oldest_created_at"] or now)
    return now - oldest >= max(1, int(max_wait_sec))


def staging_claim_items(
    limit: int = 100,
    *,
    pool_id: str | None = None,
) -> list[dict[str, Any]]:
    limit = max(1, int(limit))
    now = int(time.time())
    normalized_pool = str(pool_id or "").strip().lower()
    pool_clause = ""
    parameters: list[Any] = [now]
    if normalized_pool in {"realtime", "background"}:
        pool_clause = "AND pool_id = ?"
        parameters.append(normalized_pool)
    parameters.append(limit)
    with _DB_LOCK, _connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        rows = connection.execute(
            f"""
            SELECT domain, source, priority, attempts, created_at, pool_id
            FROM staging_domains
            WHERE state = 'queued' AND available_at <= ?
            {pool_clause}
            ORDER BY priority DESC, created_at, domain
            LIMIT ?
            """,
            tuple(parameters),
        ).fetchall()
        items = [dict(row) for row in rows]
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
    return items


def staging_claim(limit: int = 100, *, pool_id: str | None = None) -> list[str]:
    return [str(item["domain"]) for item in staging_claim_items(limit, pool_id=pool_id)]


def staging_ack(domain: str) -> None:
    with _DB_LOCK, _connection() as connection:
        connection.execute(
            "DELETE FROM staging_domains WHERE domain = ?", (_normalize_domain(domain),)
        )


def staging_remove(domains: Iterable[str]) -> int:
    normalized = sorted({value for item in domains if (value := _normalize_domain(item))})
    if not normalized:
        return 0
    placeholders = ",".join("?" for _ in normalized)
    with _DB_LOCK, _connection() as connection:
        cursor = connection.execute(
            f"DELETE FROM staging_domains WHERE domain IN ({placeholders})",
            normalized,
        )
    return cursor.rowcount


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
            SET state = ?, updated_at = ?, last_error = ?, available_at = 0
            WHERE domain = ?
            """,
            (state, now, error[:1000], normalized),
        )


def staging_defer(domain: str, error: str, retry_at: float) -> None:
    normalized = _normalize_domain(domain)
    now = int(time.time())
    available_at = max(now + 1, int(retry_at))
    with _DB_LOCK, _connection() as connection:
        connection.execute(
            """
            UPDATE staging_domains
            SET state = 'queued', attempts = MAX(0, attempts - 1),
                updated_at = ?, last_error = ?, available_at = ?
            WHERE domain = ?
            """,
            (now, error[:1000], available_at, normalized),
        )


def staging_requeue_processing(*, pool_id: str | None = None) -> int:
    now = int(time.time())
    normalized_pool = str(pool_id or "").strip().lower()
    pool_clause = ""
    parameters: tuple[Any, ...] = (now,)
    if normalized_pool in {"realtime", "background"}:
        pool_clause = "AND pool_id = ?"
        parameters = (now, normalized_pool)
    with _DB_LOCK, _connection() as connection:
        cursor = connection.execute(
            f"""
            UPDATE staging_domains
            SET state = 'queued', updated_at = ?, available_at = 0
            WHERE state = 'processing'
            {pool_clause}
            """,
            parameters,
        )
    return cursor.rowcount


def staging_list(limit: int = 200) -> list[dict[str, Any]]:
    with _DB_LOCK, _connection() as connection:
        rows = connection.execute(
            """
            SELECT domain, state, attempts, created_at, updated_at, last_error,
                   priority, source, pool_id, available_at
            FROM staging_domains
            ORDER BY priority DESC, created_at, domain
            LIMIT ?
            """,
            (max(1, int(limit)),),
        ).fetchall()
    return [dict(row) for row in rows]


def staging_summary() -> dict[str, int]:
    with _DB_LOCK, _connection() as connection:
        rows = connection.execute(
            "SELECT state, COUNT(*) AS count FROM staging_domains GROUP BY state"
        ).fetchall()
    summary = {"queued": 0, "processing": 0, "failed": 0}
    for row in rows:
        summary[str(row["state"])] = int(row["count"] or 0)
    return summary


def domains_without_classification(domains: Iterable[str]) -> set[str]:
    normalized = {value for item in domains if (value := _normalize_domain(item))}
    if not normalized:
        return set()
    placeholders = ",".join("?" for _ in normalized)
    with _DB_LOCK, _connection() as connection:
        rows = connection.execute(
            f"""
            SELECT DISTINCT domain
            FROM classification_runs
            WHERE is_primary = 1 AND domain IN ({placeholders})
            """,
            tuple(sorted(normalized)),
        ).fetchall()
    classified = {str(row["domain"]) for row in rows}
    return normalized - classified


def record_discovered_domains(rows: Sequence[dict[str, Any]]) -> int:
    discovered: dict[str, int] = {}
    for row in rows:
        domain = _normalize_domain(str(row.get("domain") or ""))
        if not domain:
            continue
        try:
            timestamp = int(float(row.get("time") or time.time()))
        except (TypeError, ValueError):
            timestamp = int(time.time())
        discovered[domain] = max(discovered.get(domain, 0), timestamp)
    with _DB_LOCK, _connection() as connection:
        for domain, timestamp in discovered.items():
            _ensure_domain(connection, domain, seen_at=timestamp)
    return len(discovered)


# ---------- Query observations ----------


def record_query_observations(rows: Sequence[dict[str, Any]]) -> int:
    grouped: Counter[tuple[str, str, str, str, int]] = Counter()
    first_last: dict[tuple[str, str, str, str, int], tuple[int, int]] = {}
    for row in rows:
        domain = _normalize_domain(str(row.get("domain") or ""))
        if not domain:
            continue
        try:
            timestamp = int(row.get("time") or time.time())
        except (TypeError, ValueError):
            timestamp = int(time.time())
        bucket = timestamp - (timestamp % 3600)
        key = (
            domain,
            str(row.get("client") or ""),
            str(row.get("type") or ""),
            str(row.get("status") or ""),
            bucket,
        )
        grouped[key] += 1
        previous = first_last.get(key, (timestamp, timestamp))
        first_last[key] = (min(previous[0], timestamp), max(previous[1], timestamp))

    with _DB_LOCK, _connection() as connection:
        for (domain, client, query_type, status, bucket), count in grouped.items():
            first_seen, last_seen = first_last[(domain, client, query_type, status, bucket)]
            _ensure_domain(
                connection,
                domain,
                seen_at=last_seen,
                query_increment=count,
            )
            connection.execute(
                """
                INSERT INTO query_observations(
                    domain, client, query_type, status, bucket_start,
                    query_count, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(domain, client, query_type, status, bucket_start)
                DO UPDATE SET
                    query_count = query_count + excluded.query_count,
                    first_seen = MIN(first_seen, excluded.first_seen),
                    last_seen = MAX(last_seen, excluded.last_seen)
                """,
                (
                    domain,
                    client,
                    query_type,
                    status,
                    bucket,
                    count,
                    first_seen,
                    last_seen,
                ),
            )
    return sum(grouped.values())


def domain_observation_summary(domain: str, days: int = 30) -> dict[str, Any]:
    normalized = _normalize_domain(domain)
    cutoff = int(time.time()) - max(1, int(days)) * 86400
    with _DB_LOCK, _connection() as connection:
        domain_row = connection.execute(
            "SELECT * FROM domains WHERE domain = ?", (normalized,)
        ).fetchone()
        aggregates = connection.execute(
            """
            SELECT client, query_type, status, SUM(query_count) AS count,
                   MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen
            FROM query_observations
            WHERE domain = ? AND last_seen >= ?
            GROUP BY client, query_type, status
            ORDER BY count DESC
            LIMIT 100
            """,
            (normalized, cutoff),
        ).fetchall()
    return {
        "domain": dict(domain_row) if domain_row else {"domain": normalized},
        "observations": [dict(row) for row in aggregates],
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
