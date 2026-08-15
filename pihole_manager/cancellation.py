from __future__ import annotations

import threading
import time
from collections.abc import Iterable
from concurrent.futures import Future
from typing import Any


class OperationCancelledError(RuntimeError):
    """Raised when a cooperative long-running operation is cancelled."""


class CancellationToken:
    """Cooperative cancellation token with optional parent events.

    The local token can cancel one job without terminating its worker. Parent
    events are useful for linking a job to worker/application shutdown.
    """

    def __init__(self, *parent_events: threading.Event) -> None:
        self._event = threading.Event()
        self._parent_events = tuple(parent_events)

    def cancel(self) -> None:
        self._event.set()

    def is_set(self) -> bool:
        return self._event.is_set() or any(event.is_set() for event in self._parent_events)

    def raise_if_cancelled(self) -> None:
        if self.is_set():
            raise OperationCancelledError("Operation cancelled")

    def wait(self, timeout: float) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        while not self.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            self._event.wait(min(0.1, remaining))
        return True


def raise_if_cancelled(token: CancellationToken | None) -> None:
    if token is not None:
        token.raise_if_cancelled()


def cancel_pending(futures: Iterable[Future[Any]]) -> None:
    for future in futures:
        future.cancel()
