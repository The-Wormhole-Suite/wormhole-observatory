from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ConnectionState(StrEnum):
    UNKNOWN = "unknown"
    ONLINE = "online"
    DEGRADED = "degraded"
    AUTH_ERROR = "auth_error"
    OFFLINE = "offline"
    CLOSED = "closed"


@dataclass(frozen=True, slots=True)
class ConnectionHealth:
    state: ConnectionState = ConnectionState.UNKNOWN
    last_checked_at: float = 0.0
    last_success_at: float = 0.0
    latency_ms: int = 0
    consecutive_failures: int = 0
    status_code: int = 0
    last_error: str = ""
