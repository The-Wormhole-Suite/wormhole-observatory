from __future__ import annotations

from typing import Any


class PiHole6Error(RuntimeError):
    """Base exception for Pi-hole API failures."""


class PiHole6ConnectionError(PiHole6Error):
    """Raised when the Pi-hole host cannot be reached."""


class PiHole6AuthenticationError(PiHole6Error):
    """Raised when authentication fails."""


class PiHole6HTTPError(PiHole6Error):
    """Raised for non-successful HTTP responses."""

    def __init__(self, status_code: int, message: str, payload: Any = None) -> None:
        super().__init__(f"HTTP {status_code}: {message}")
        self.status_code = status_code
        self.payload = payload
