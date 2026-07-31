from __future__ import annotations

import hashlib
import json
import math
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from pihole_manager.config import LLMOptions, LLMProviderOptions, database_path
from pihole_manager.database_core import _DB_LOCK, _connection, init_db
from pihole_manager.http_retry import retry_delay_from_headers
from pihole_manager.models import ProviderUsage
from pihole_manager.provider_registry import ProviderLimit, ProviderLimitProfile

_INITIALIZATION_LOCK = threading.Lock()
_INITIALIZED_DATABASES: set[str] = set()
_METRIC_COLUMNS = {
    "requests": "request_count",
    "input_tokens": "input_tokens",
    "output_tokens": "output_tokens",
    "total_tokens": None,
    "units": "units",
}


class QuotaUnavailableError(RuntimeError):
    def __init__(self, message: str, *, retry_at: float) -> None:
        super().__init__(message)
        self.retry_at = max(0.0, float(retry_at))

    @property
    def wait_seconds(self) -> float:
        return max(0.0, self.retry_at - time.time())


@dataclass(frozen=True, slots=True)
class QuotaEstimate:
    domain_count: int = 1
    request_count: int = 1
    input_tokens: int = 0
    output_tokens: int = 0
    units: float = 0.0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


@dataclass(frozen=True, slots=True)
class QuotaReservation:
    reservation_id: str
    scope_key: str
    provider_id: str
    pool_id: str
    estimate: QuotaEstimate
    created_at: float
    expires_at: float


@dataclass(frozen=True, slots=True)
class RuntimeQuotaState:
    scope_key: str
    metric: str
    window_seconds: int
    limit_amount: float
    remaining_amount: float
    reset_at: float
    observed_at: float
    source: str = "live_header"


def estimate_message_tokens(messages: Sequence[Mapping[str, str]]) -> int:
    serialized = json.dumps(
        [dict(message) for message in messages],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return max(1, math.ceil(len(serialized) / 3.5))


def estimate_provider_usage(
    messages: Sequence[Mapping[str, str]],
    *,
    provider: LLMProviderOptions,
    profile: ProviderLimitProfile,
    domain_count: int,
) -> QuotaEstimate:
    selected_domain_count = max(1, int(domain_count))
    input_tokens = estimate_message_tokens(messages)
    output_per_domain = calibrated_output_tokens_per_domain(provider.provider_id)
    output_tokens = math.ceil(output_per_domain * selected_domain_count * 1.2)
    output_tokens = max(256, min(max(1, int(provider.max_output_tokens)), output_tokens))
    units = _units_for_usage(
        input_tokens,
        output_tokens,
        profile=profile,
    )
    return QuotaEstimate(
        domain_count=selected_domain_count,
        request_count=1,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        units=units,
    )


def batch_fits_context(
    estimate: QuotaEstimate,
    *,
    provider: LLMProviderOptions,
    profile: ProviderLimitProfile,
) -> bool:
    context_tokens = (
        int(provider.limits.context_tokens)
        if int(provider.limits.context_tokens) > 0
        else int(profile.capability.context_tokens)
    )
    if context_tokens <= 0:
        return True
    margin = min(50.0, max(0.0, float(profile.safety_margin_percent)))
    usable_context = math.floor(context_tokens * (1.0 - margin / 100.0))
    return estimate.total_tokens <= usable_context


def maximum_provider_batch_size(
    provider: LLMProviderOptions,
    profile: ProviderLimitProfile,
    llm_options: LLMOptions,
) -> int:
    configured = max(1, int(llm_options.domains_per_request))
    provider_maximum = int(profile.max_domains_per_request)
    if provider_maximum > 0:
        configured = min(configured, provider_maximum)
    if profile.source == "unknown" and not profile.capability.local:
        configured = min(
            configured,
            max(1, int(llm_options.unknown_remote_max_domains_per_request)),
        )
    return configured


def reserve_quota(
    provider: LLMProviderOptions,
    profile: ProviderLimitProfile,
    estimate: QuotaEstimate,
    *,
    pool_id: str,
    llm_options: LLMOptions,
    now: float | None = None,
) -> QuotaReservation:
    _ensure_database()
    current_time = time.time() if now is None else float(now)
    normalized_pool = pool_id.strip().lower() or "background"
    limits = _effective_limits(profile, llm_options)
    scope_key = quota_scope_key(provider, profile, limits)
    maximum_window = max((limit.window_seconds for limit in limits), default=300)
    expires_at = current_time + max(300, maximum_window)
    reservation = QuotaReservation(
        reservation_id=uuid4().hex,
        scope_key=scope_key,
        provider_id=provider.provider_id,
        pool_id=normalized_pool,
        estimate=estimate,
        created_at=current_time,
        expires_at=expires_at,
    )

    with _DB_LOCK, _connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            UPDATE quota_reservations
            SET state = 'cancelled', completed_at = ?
            WHERE state = 'reserved' AND expires_at <= ?
            """,
            (current_time, current_time),
        )
        rows = connection.execute(
            """
            SELECT *
            FROM quota_reservations
            WHERE scope_key = ?
              AND state IN ('reserved', 'completed')
            ORDER BY created_at, id
            """,
            (scope_key,),
        ).fetchall()
        active_limits = _limits_with_live_state(
            connection,
            scope_key,
            limits,
            profile=profile,
            now=current_time,
        )
        retry_at = _limit_retry_at(
            rows,
            active_limits,
            estimate,
            pool_id=normalized_pool,
            realtime_reserve_percent=llm_options.realtime_quota_reserve_percent,
            safety_margin_percent=profile.safety_margin_percent,
            now=current_time,
        )
        live_retry_at = _live_limit_retry_at(
            connection,
            rows,
            scope_key,
            estimate,
            now=current_time,
        )
        retry_at = max(retry_at, live_retry_at)
        if retry_at > current_time:
            raise QuotaUnavailableError(
                f"Provider quota is reserved until {_format_timestamp(retry_at)}.",
                retry_at=retry_at,
            )
        connection.execute(
            """
            INSERT INTO quota_reservations(
                id, scope_key, provider_id, pool_id, state, domain_count,
                request_count, input_tokens, output_tokens, units,
                created_at, expires_at
            ) VALUES (?, ?, ?, ?, 'reserved', ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                reservation.reservation_id,
                reservation.scope_key,
                reservation.provider_id,
                reservation.pool_id,
                max(1, int(estimate.domain_count)),
                max(0, int(estimate.request_count)),
                max(0, int(estimate.input_tokens)),
                max(0, int(estimate.output_tokens)),
                max(0.0, float(estimate.units)),
                current_time,
                expires_at,
            ),
        )
    return reservation


def wait_for_quota(
    provider: LLMProviderOptions,
    profile: ProviderLimitProfile,
    estimate: QuotaEstimate,
    *,
    pool_id: str,
    llm_options: LLMOptions,
) -> QuotaReservation:
    deadline = time.monotonic() + max(0.0, float(llm_options.quota_wait_timeout_sec))
    while True:
        try:
            return reserve_quota(
                provider,
                profile,
                estimate,
                pool_id=pool_id,
                llm_options=llm_options,
            )
        except QuotaUnavailableError as exc:
            remaining = deadline - time.monotonic()
            delay = min(exc.wait_seconds, remaining)
            if delay <= 0:
                raise
            time.sleep(delay)


def complete_quota(
    reservation: QuotaReservation,
    *,
    usage: ProviderUsage | None = None,
    profile: ProviderLimitProfile | None = None,
    response_headers: Mapping[str, object] | None = None,
    now: float | None = None,
) -> None:
    _ensure_database()
    current_time = time.time() if now is None else float(now)
    selected = _normalized_usage(usage, reservation.estimate, profile=profile)
    with _DB_LOCK, _connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            UPDATE quota_reservations
            SET state = 'completed', input_tokens = ?, output_tokens = ?,
                units = ?, completed_at = ?
            WHERE id = ? AND state = 'reserved'
            """,
            (
                selected.input_tokens,
                selected.output_tokens,
                selected.units,
                current_time,
                reservation.reservation_id,
            ),
        )
        if profile is not None and response_headers:
            for state in runtime_quota_states_from_headers(
                reservation.scope_key,
                profile,
                response_headers,
                now=current_time,
            ):
                _save_runtime_state(connection, state)


def cancel_quota(
    reservation: QuotaReservation,
    *,
    now: float | None = None,
) -> None:
    _ensure_database()
    current_time = time.time() if now is None else float(now)
    with _DB_LOCK, _connection() as connection:
        connection.execute(
            """
            UPDATE quota_reservations
            SET state = 'cancelled', completed_at = ?
            WHERE id = ? AND state = 'reserved'
            """,
            (current_time, reservation.reservation_id),
        )


def calibrated_output_tokens_per_domain(
    provider_id: str,
    *,
    default: float = 600.0,
) -> float:
    _ensure_database()
    with _DB_LOCK, _connection() as connection:
        row = connection.execute(
            """
            SELECT AVG(output_tokens * 1.0 / MAX(domain_count, 1)) AS average
            FROM (
                SELECT output_tokens, domain_count
                FROM quota_reservations
                WHERE provider_id = ?
                  AND state = 'completed'
                  AND output_tokens > 0
                ORDER BY completed_at DESC
                LIMIT 50
            )
            """,
            (provider_id,),
        ).fetchone()
    average = float(row["average"] or 0)
    return min(4096.0, max(128.0, average or float(default)))


def quota_scope_key(
    provider: LLMProviderOptions,
    profile: ProviderLimitProfile,
    limits: Sequence[ProviderLimit] | None = None,
) -> str:
    selected_limits = tuple(limits if limits is not None else profile.limits)
    scopes = {limit.scope.strip().lower() for limit in selected_limits}
    group = profile.quota_group.strip().lower()
    if not group:
        host = (urlparse(provider.base_url).hostname or provider.preset_id).lower()
        group = host or provider.provider_id
    account_fingerprint = hashlib.sha256(
        (provider.api_key or provider.provider_id).encode("utf-8")
    ).hexdigest()[:16]
    include_model = not scopes.intersection({"account", "organization", "project"})
    parts = [group, account_fingerprint]
    if include_model:
        parts.append(provider.model.strip().lower() or provider.provider_id)
    return ":".join(parts)


def runtime_quota_states_from_headers(
    scope_key: str,
    profile: ProviderLimitProfile,
    headers: Mapping[str, object],
    *,
    now: float | None = None,
) -> tuple[RuntimeQuotaState, ...]:
    current_time = time.time() if now is None else float(now)
    normalized = {str(key).lower(): str(value).strip() for key, value in headers.items()}
    definitions = (
        (
            "requests",
            "x-ratelimit-limit-requests",
            "x-ratelimit-remaining-requests",
            "x-ratelimit-reset-requests",
        ),
        (
            "total_tokens",
            "x-ratelimit-limit-tokens",
            "x-ratelimit-remaining-tokens",
            "x-ratelimit-reset-tokens",
        ),
    )
    states: list[RuntimeQuotaState] = []
    for metric, limit_name, remaining_name, reset_name in definitions:
        limit_amount = _positive_float(normalized.get(limit_name))
        remaining_amount = _nonnegative_float(normalized.get(remaining_name))
        if limit_amount is None or remaining_amount is None:
            continue
        window = _matching_window(profile, metric, limit_amount)
        reset_delay = retry_delay_from_headers(
            {reset_name: normalized.get(reset_name, "")},
            maximum=max(604800.0, float(window)),
            wall_time=current_time,
        )
        reset_at = current_time + (reset_delay if reset_delay is not None else max(1, window))
        states.append(
            RuntimeQuotaState(
                scope_key=scope_key,
                metric=metric,
                window_seconds=max(1, window),
                limit_amount=limit_amount,
                remaining_amount=min(limit_amount, remaining_amount),
                reset_at=reset_at,
                observed_at=current_time,
            )
        )
    return tuple(states)


def quota_runtime_states(scope_key: str, *, now: float | None = None) -> list[RuntimeQuotaState]:
    _ensure_database()
    current_time = time.time() if now is None else float(now)
    with _DB_LOCK, _connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM runtime_quota_state
            WHERE scope_key = ? AND reset_at > ?
            ORDER BY metric, window_seconds
            """,
            (scope_key, current_time),
        ).fetchall()
    return [
        RuntimeQuotaState(
            scope_key=str(row["scope_key"]),
            metric=str(row["metric"]),
            window_seconds=int(row["window_seconds"]),
            limit_amount=float(row["limit_amount"]),
            remaining_amount=float(row["remaining_amount"]),
            reset_at=float(row["reset_at"]),
            observed_at=float(row["observed_at"]),
            source=str(row["source"]),
        )
        for row in rows
    ]


def _effective_limits(
    profile: ProviderLimitProfile,
    llm_options: LLMOptions,
) -> tuple[ProviderLimit, ...]:
    if profile.limits or profile.capability.local or profile.source == "user":
        return profile.limits
    return (
        ProviderLimit(
            metric="requests",
            amount=max(1, int(llm_options.unknown_remote_requests_per_minute)),
            window_seconds=60,
            scope="provider_model",
            source="conservative_unknown",
        ),
    )


def _limits_with_live_state(
    connection: Any,
    scope_key: str,
    limits: Sequence[ProviderLimit],
    *,
    profile: ProviderLimitProfile,
    now: float,
) -> tuple[ProviderLimit, ...]:
    if profile.source == "user":
        return tuple(limits)
    combined = {(limit.metric, limit.window_seconds): limit for limit in limits}
    states = connection.execute(
        """
        SELECT *
        FROM runtime_quota_state
        WHERE scope_key = ? AND reset_at > ?
        """,
        (scope_key, now),
    ).fetchall()
    for state in states:
        key = (str(state["metric"]), int(state["window_seconds"]))
        existing = combined.get(key)
        amount = float(state["limit_amount"])
        if existing is not None and existing.user_cap > 0:
            amount = min(amount, existing.user_cap)
        combined[key] = ProviderLimit(
            metric=key[0],
            amount=amount,
            window_seconds=key[1],
            scope=existing.scope if existing is not None else "live",
            source="live_header",
            user_cap=existing.user_cap if existing is not None else 0.0,
            reset_policy=existing.reset_policy if existing is not None else "rolling",
        )
    return tuple(
        sorted(
            combined.values(),
            key=lambda item: (item.metric, item.window_seconds),
        )
    )


def _limit_retry_at(
    rows: Sequence[Mapping[str, Any]],
    limits: Sequence[ProviderLimit],
    estimate: QuotaEstimate,
    *,
    pool_id: str,
    realtime_reserve_percent: float,
    safety_margin_percent: float,
    now: float,
) -> float:
    retry_at = 0.0
    for limit in limits:
        candidate = _metric_value(estimate, limit.metric)
        if candidate <= 0:
            continue
        safety_factor = (
            1.0
            - min(
                50.0,
                max(0.0, float(safety_margin_percent)),
            )
            / 100.0
        )
        cap = float(limit.amount) * safety_factor
        if pool_id == "background":
            reserve = min(90.0, max(0.0, float(realtime_reserve_percent)))
            cap *= 1.0 - reserve / 100.0
        utc_day = limit.reset_policy == "utc_day"
        window_start = (
            math.floor(now / 86400) * 86400 if utc_day else now - int(limit.window_seconds)
        )
        relevant = [
            row
            for row in rows
            if (
                float(row["created_at"]) >= window_start
                if utc_day
                else float(row["created_at"]) > window_start
            )
        ]
        if utc_day:
            current = sum(_row_metric_value(row, limit.metric) for row in relevant)
            if current + candidate > cap:
                retry_at = max(retry_at, window_start + 86400)
            continue
        selected_retry = _retry_at_for_limit(
            relevant,
            metric=limit.metric,
            candidate=candidate,
            cap=cap,
            window_seconds=limit.window_seconds,
            now=now,
        )
        retry_at = max(retry_at, selected_retry)
    return retry_at


def _retry_at_for_limit(
    rows: Sequence[Mapping[str, Any]],
    *,
    metric: str,
    candidate: float,
    cap: float,
    window_seconds: int,
    now: float,
) -> float:
    current = sum(_row_metric_value(row, metric) for row in rows)
    if candidate > cap:
        return now + max(1, int(window_seconds))
    if current + candidate <= cap:
        return 0.0
    reduced = current
    retry_at = now + max(1, int(window_seconds))
    for row in rows:
        reduced -= _row_metric_value(row, metric)
        retry_at = float(row["created_at"]) + int(window_seconds)
        if reduced + candidate <= cap:
            break
    return max(now, retry_at)


def _live_limit_retry_at(
    connection: Any,
    rows: Sequence[Mapping[str, Any]],
    scope_key: str,
    estimate: QuotaEstimate,
    *,
    now: float,
) -> float:
    states = connection.execute(
        """
        SELECT *
        FROM runtime_quota_state
        WHERE scope_key = ? AND reset_at > ?
        """,
        (scope_key, now),
    ).fetchall()
    retry_at = 0.0
    for state in states:
        metric = str(state["metric"])
        candidate = _metric_value(estimate, metric)
        used_since_observation = sum(
            _row_metric_value(row, metric)
            for row in rows
            if float(row["created_at"]) > float(state["observed_at"])
        )
        if candidate + used_since_observation > float(state["remaining_amount"]):
            retry_at = max(retry_at, float(state["reset_at"]))
    return retry_at


def _save_runtime_state(connection: Any, state: RuntimeQuotaState) -> None:
    connection.execute(
        """
        INSERT INTO runtime_quota_state(
            scope_key, metric, window_seconds, limit_amount,
            remaining_amount, reset_at, observed_at, source
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(scope_key, metric, window_seconds) DO UPDATE SET
            limit_amount = excluded.limit_amount,
            remaining_amount = excluded.remaining_amount,
            reset_at = excluded.reset_at,
            observed_at = excluded.observed_at,
            source = excluded.source
        """,
        (
            state.scope_key,
            state.metric,
            state.window_seconds,
            state.limit_amount,
            state.remaining_amount,
            state.reset_at,
            state.observed_at,
            state.source,
        ),
    )


def _normalized_usage(
    usage: ProviderUsage | None,
    estimate: QuotaEstimate,
    *,
    profile: ProviderLimitProfile | None,
) -> ProviderUsage:
    if usage is None:
        return ProviderUsage(
            input_tokens=estimate.input_tokens,
            output_tokens=estimate.output_tokens,
            total_tokens=estimate.total_tokens,
            units=estimate.units,
        )
    input_tokens = max(0, int(usage.input_tokens))
    output_tokens = max(0, int(usage.output_tokens))
    if input_tokens == 0 and output_tokens == 0:
        input_tokens = estimate.input_tokens
        output_tokens = estimate.output_tokens
    units = max(0.0, float(usage.units))
    if units == 0 and profile is not None:
        units = _units_for_usage(input_tokens, output_tokens, profile=profile)
    return ProviderUsage(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=max(int(usage.total_tokens), input_tokens + output_tokens),
        units=units,
    )


def _units_for_usage(
    input_tokens: int,
    output_tokens: int,
    *,
    profile: ProviderLimitProfile,
) -> float:
    return (
        max(0, input_tokens) * profile.input_units_per_million_tokens
        + max(0, output_tokens) * profile.output_units_per_million_tokens
    ) / 1_000_000.0


def _matching_window(
    profile: ProviderLimitProfile,
    metric: str,
    amount: float,
) -> int:
    candidates = [limit for limit in profile.limits if limit.metric == metric]
    exact = [
        limit for limit in candidates if math.isclose(float(limit.amount), amount, rel_tol=0.001)
    ]
    selected = exact or candidates
    if selected:
        return min(selected, key=lambda item: abs(float(item.amount) - amount)).window_seconds
    return 60


def _metric_value(estimate: QuotaEstimate, metric: str) -> float:
    if metric == "requests":
        return float(estimate.request_count)
    if metric == "input_tokens":
        return float(estimate.input_tokens)
    if metric == "output_tokens":
        return float(estimate.output_tokens)
    if metric == "total_tokens":
        return float(estimate.total_tokens)
    if metric == "units":
        return float(estimate.units)
    return 0.0


def _row_metric_value(row: Mapping[str, Any], metric: str) -> float:
    column = _METRIC_COLUMNS.get(metric)
    if metric == "total_tokens":
        return float(row["input_tokens"] or 0) + float(row["output_tokens"] or 0)
    return float(row[column] or 0) if column else 0.0


def _positive_float(value: object) -> float | None:
    try:
        selected = float(str(value))
    except (TypeError, ValueError):
        return None
    return selected if selected > 0 else None


def _nonnegative_float(value: object) -> float | None:
    try:
        selected = float(str(value))
    except (TypeError, ValueError):
        return None
    return selected if selected >= 0 else None


def _ensure_database() -> None:
    selected_path = str(database_path().resolve())
    if selected_path in _INITIALIZED_DATABASES:
        return
    with _INITIALIZATION_LOCK:
        if selected_path in _INITIALIZED_DATABASES:
            return
        init_db()
        _INITIALIZED_DATABASES.add(selected_path)


def _format_timestamp(value: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))
