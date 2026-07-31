from __future__ import annotations

import re
import time
from collections.abc import Mapping
from datetime import UTC
from email.utils import parsedate_to_datetime

_RESET_HEADERS = (
    "x-ratelimit-reset-after",
    "x-ratelimit-reset-requests",
    "x-ratelimit-reset-tokens",
    "x-ratelimit-reset",
    "ratelimit-reset",
)
_DURATION_PART = re.compile(r"(\d+(?:\.\d+)?)\s*(ms|s|m|h)", re.IGNORECASE)


def retry_delay_from_headers(
    headers: Mapping[str, object] | None,
    *,
    maximum: float = 300.0,
    wall_time: float | None = None,
) -> float | None:
    if not headers:
        return None
    normalized = {str(key).lower(): str(value).strip() for key, value in headers.items()}
    now = time.time() if wall_time is None else float(wall_time)
    delays: list[float] = []

    retry_after = normalized.get("retry-after", "")
    delay = _retry_after_delay(retry_after, now)
    if delay is not None:
        delays.append(delay)

    for name in _RESET_HEADERS:
        delay = _reset_delay(normalized.get(name, ""), now)
        if delay is not None:
            delays.append(delay)
    if not delays:
        return None
    return min(max(0.0, float(maximum)), max(0.0, max(delays)))


def _retry_after_delay(value: str, now: float) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        pass
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.timestamp() - now


def _reset_delay(value: str, now: float) -> float | None:
    if not value:
        return None
    compact = value.strip().lower()
    duration = _duration_seconds(compact)
    if duration is not None:
        return duration
    try:
        number = float(compact)
    except ValueError:
        return None
    if number > 10_000_000_000:
        number /= 1_000.0
    if number > now + 1:
        return number - now
    return number


def _duration_seconds(value: str) -> float | None:
    matches = list(_DURATION_PART.finditer(value))
    matched = "".join(match.group(0) for match in matches).replace(" ", "")
    if not matches or matched != value.replace(" ", ""):
        return None
    multipliers = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0}
    return sum(float(match.group(1)) * multipliers[match.group(2).lower()] for match in matches)
