from __future__ import annotations

import json
import time
from dataclasses import asdict
from typing import Any
from uuid import uuid4

from pihole_manager.database_core import _DB_LOCK, _connection, _normalize_domain
from pihole_manager.models import Classification, ProviderHealthState, ProviderUsage


def analysis_run_start(
    pool_id: str,
    mode: str,
    *,
    source: str = "",
    dossier_hash: str = "",
) -> str:
    run_id = uuid4().hex
    now = int(time.time())
    with _DB_LOCK, _connection() as connection:
        connection.execute(
            """
            INSERT INTO analysis_runs(
                id, pool_id, mode, source, dossier_hash, status, created_at
            ) VALUES (?, ?, ?, ?, ?, 'running', ?)
            """,
            (
                run_id,
                pool_id.strip().lower(),
                mode.strip().lower(),
                source.strip(),
                dossier_hash.strip(),
                now,
            ),
        )
    return run_id


def analysis_run_finish(
    run_id: str,
    *,
    error: str = "",
    status: str = "",
) -> None:
    now = int(time.time())
    selected_status = status.strip().lower()
    if selected_status not in {"completed", "completed_with_errors", "failed", "cancelled"}:
        selected_status = "failed" if error else "completed"
    with _DB_LOCK, _connection() as connection:
        connection.execute(
            """
            UPDATE analysis_runs
            SET status = ?, error = ?, completed_at = ?
            WHERE id = ?
            """,
            (selected_status, error[:2000], now, run_id),
        )


def analysis_run_get(run_id: str) -> dict[str, Any] | None:
    with _DB_LOCK, _connection() as connection:
        row = connection.execute(
            "SELECT * FROM analysis_runs WHERE id = ?",
            (run_id,),
        ).fetchone()
    return dict(row) if row is not None else None


def provider_health_get(provider_id: str) -> ProviderHealthState:
    with _DB_LOCK, _connection() as connection:
        row = connection.execute(
            "SELECT * FROM provider_health WHERE provider_id = ?",
            (provider_id,),
        ).fetchone()
    if row is None:
        return ProviderHealthState(provider_id=provider_id)
    return ProviderHealthState(
        provider_id=str(row["provider_id"]),
        state=str(row["state"]),
        cooldown_until=float(row["cooldown_until"] or 0),
        consecutive_failures=int(row["consecutive_failures"] or 0),
        last_error=str(row["last_error"] or ""),
        last_success_at=float(row["last_success_at"] or 0),
        last_failure_at=float(row["last_failure_at"] or 0),
        latency_ewma_ms=float(row["latency_ewma_ms"] or 0),
    )


def provider_health_list() -> list[ProviderHealthState]:
    with _DB_LOCK, _connection() as connection:
        rows = connection.execute("SELECT * FROM provider_health ORDER BY provider_id").fetchall()
    return [
        ProviderHealthState(
            provider_id=str(row["provider_id"]),
            state=str(row["state"]),
            cooldown_until=float(row["cooldown_until"] or 0),
            consecutive_failures=int(row["consecutive_failures"] or 0),
            last_error=str(row["last_error"] or ""),
            last_success_at=float(row["last_success_at"] or 0),
            last_failure_at=float(row["last_failure_at"] or 0),
            latency_ewma_ms=float(row["latency_ewma_ms"] or 0),
        )
        for row in rows
    ]


def provider_health_success(provider_id: str, latency_ms: int) -> ProviderHealthState:
    now = time.time()
    previous = provider_health_get(provider_id)
    latency = max(0.0, float(latency_ms))
    average = latency
    if previous.latency_ewma_ms > 0:
        average = previous.latency_ewma_ms * 0.8 + latency * 0.2
    with _DB_LOCK, _connection() as connection:
        connection.execute(
            """
            INSERT INTO provider_health(
                provider_id, state, cooldown_until, consecutive_failures,
                last_error, last_success_at, last_failure_at,
                latency_ewma_ms, updated_at
            ) VALUES (?, 'healthy', 0, 0, '', ?, ?, ?, ?)
            ON CONFLICT(provider_id) DO UPDATE SET
                state = 'healthy',
                cooldown_until = 0,
                consecutive_failures = 0,
                last_error = '',
                last_success_at = excluded.last_success_at,
                latency_ewma_ms = excluded.latency_ewma_ms,
                updated_at = excluded.updated_at
            """,
            (
                provider_id,
                now,
                previous.last_failure_at,
                average,
                now,
            ),
        )
    return provider_health_get(provider_id)


def provider_health_failure(
    provider_id: str,
    error: str,
    *,
    cooldown_until: float = 0.0,
) -> ProviderHealthState:
    now = time.time()
    previous = provider_health_get(provider_id)
    failures = previous.consecutive_failures + 1
    state = "cooldown" if cooldown_until > now else "unavailable"
    with _DB_LOCK, _connection() as connection:
        connection.execute(
            """
            INSERT INTO provider_health(
                provider_id, state, cooldown_until, consecutive_failures,
                last_error, last_success_at, last_failure_at,
                latency_ewma_ms, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(provider_id) DO UPDATE SET
                state = excluded.state,
                cooldown_until = excluded.cooldown_until,
                consecutive_failures = excluded.consecutive_failures,
                last_error = excluded.last_error,
                last_failure_at = excluded.last_failure_at,
                updated_at = excluded.updated_at
            """,
            (
                provider_id,
                state,
                max(0.0, cooldown_until),
                failures,
                error[:2000],
                previous.last_success_at,
                now,
                previous.latency_ewma_ms,
                now,
            ),
        )
    return provider_health_get(provider_id)


def benchmark_run_start(
    domain: str,
    pool_id: str,
    dossier: dict[str, Any],
    dossier_hash: str,
) -> str:
    run_id = uuid4().hex
    now = int(time.time())
    with _DB_LOCK, _connection() as connection:
        connection.execute(
            """
            INSERT INTO model_benchmark_runs(
                id, domain, pool_id, dossier_json, dossier_hash, status, created_at
            ) VALUES (?, ?, ?, ?, ?, 'running', ?)
            """,
            (
                run_id,
                _normalize_domain(domain),
                pool_id.strip().lower(),
                json.dumps(dossier, ensure_ascii=False, sort_keys=True, default=str),
                dossier_hash,
                now,
            ),
        )
    return run_id


def benchmark_result_save(
    run_id: str,
    *,
    provider_id: str,
    provider_name: str,
    model: str,
    status: str,
    error: str = "",
    latency_ms: int = 0,
    usage: ProviderUsage | None = None,
    classification: Classification | None = None,
) -> None:
    selected_usage = usage or ProviderUsage()
    payload = _classification_payload(classification) if classification is not None else {}
    raw_text = classification.raw_text if classification is not None else ""
    with _DB_LOCK, _connection() as connection:
        connection.execute(
            """
            INSERT INTO model_benchmark_results(
                run_id, provider_id, provider_name, model, status, error,
                latency_ms, input_tokens, output_tokens, classification_json,
                raw_text, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                provider_id,
                provider_name,
                model,
                status,
                error[:2000],
                max(0, int(latency_ms)),
                max(0, int(selected_usage.input_tokens)),
                max(0, int(selected_usage.output_tokens)),
                json.dumps(payload, ensure_ascii=False, sort_keys=True),
                raw_text,
                int(time.time()),
            ),
        )


def benchmark_run_finish(
    run_id: str,
    *,
    status: str = "",
    error: str = "",
) -> None:
    with _DB_LOCK, _connection() as connection:
        selected_status = status.strip().lower()
        if selected_status not in {"completed", "completed_with_errors", "failed", "cancelled"}:
            failed = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM model_benchmark_results
                WHERE run_id = ? AND status != 'completed'
                """,
                (run_id,),
            ).fetchone()
            selected_status = (
                "completed_with_errors" if int(failed["count"] or 0) else "completed"
            )
        connection.execute(
            """
            UPDATE model_benchmark_runs
            SET status = ?, error = ?, completed_at = ?
            WHERE id = ?
            """,
            (selected_status, error[:2000], int(time.time()), run_id),
        )


def benchmark_run_get(run_id: str) -> dict[str, Any] | None:
    with _DB_LOCK, _connection() as connection:
        run = connection.execute(
            "SELECT * FROM model_benchmark_runs WHERE id = ?",
            (run_id,),
        ).fetchone()
        rows = connection.execute(
            """
            SELECT * FROM model_benchmark_results
            WHERE run_id = ? ORDER BY id
            """,
            (run_id,),
        ).fetchall()
    if run is None:
        return None
    output = dict(run)
    output["dossier"] = json.loads(output.pop("dossier_json"))
    output["results"] = []
    for row in rows:
        item = dict(row)
        try:
            item["classification"] = json.loads(item.pop("classification_json"))
        except (json.JSONDecodeError, TypeError):
            item["classification"] = {}
        output["results"].append(item)
    return output


def _classification_payload(classification: Classification) -> dict[str, Any]:
    payload = asdict(classification)
    payload["policy"] = classification.policy.value
    payload["service_role"] = classification.service_role.value
    payload["tags"] = list(classification.tags)
    payload.pop("raw_text", None)
    return payload
