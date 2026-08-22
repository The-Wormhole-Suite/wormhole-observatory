from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import asdict

from pihole_manager.config import load_options
from pihole_manager.database import get_state, set_state
from pihole_manager.list_audit import run_list_audit_cycle
from pihole_manager.list_audit_config import load_list_audit_options

log = logging.getLogger(__name__)


class ListAuditWorker(threading.Thread):
    def __init__(self) -> None:
        super().__init__(name="PiHoleListAuditor", daemon=True)
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def wait(self, seconds: float) -> bool:
        return self._stop_event.wait(max(0.1, float(seconds)))

    def wake(self) -> None:
        self._wake_event.set()

    def _idle_wait(self, seconds: float) -> bool:
        deadline = time.monotonic() + max(0.1, float(seconds))
        while not self._stop_event.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            if self._wake_event.wait(min(remaining, 1.0)):
                self._wake_event.clear()
                return False
        return True

    def run(self) -> None:
        log.info("Pi-hole list auditor started")
        while not self._stop_event.is_set():
            options = load_options()
            audit = load_list_audit_options()
            if not audit.enabled:
                self._idle_wait(30)
                continue
            now = time.time()
            try:
                last_completed = float(get_state("list_audit_completed_at", "0") or 0)
            except ValueError:
                last_completed = 0.0
            due_at = last_completed + audit.interval_sec
            if last_completed > 0 and now < due_at:
                self._idle_wait(min(30.0, max(1.0, due_at - now)))
                continue
            try:
                summary = run_list_audit_cycle(
                    audit,
                    timeout_sec=options.pihole.timeout_sec,
                    should_stop=self._stop_event.is_set,
                    wait=self.wait,
                )
                if summary.cancelled:
                    break
                completed_at = int(time.time())
                set_state("list_audit_completed_at", str(completed_at))
                set_state(
                    "list_audit_last_summary",
                    json.dumps({"completed_at": completed_at, **asdict(summary)}, sort_keys=True),
                )
                log.info(
                    "List audit completed: %s list(s), %s failed, %s domain(s), "
                    "%s queued in %s batch(es), %s truncated",
                    summary.lists_audited,
                    summary.lists_failed,
                    summary.domains_seen,
                    summary.domains_queued,
                    summary.batches,
                    summary.truncated_lists,
                )
            except Exception as exc:
                log.warning("List audit cycle failed: %s", exc)
                self.wait(60)
        log.info("Pi-hole list auditor stopped")


_WORKER: ListAuditWorker | None = None
_WORKER_LOCK = threading.RLock()


def get_list_auditor() -> ListAuditWorker:
    global _WORKER
    with _WORKER_LOCK:
        if _WORKER is None or not _WORKER.is_alive():
            _WORKER = ListAuditWorker()
            _WORKER.start()
        return _WORKER


def request_list_audit_now() -> ListAuditWorker:
    set_state("list_audit_completed_at", "0")
    worker = get_list_auditor()
    worker.wake()
    return worker


def stop_list_auditor(timeout: float = 5.0) -> None:
    global _WORKER
    with _WORKER_LOCK:
        worker = _WORKER
        if worker is None:
            return
        worker.stop()
        worker.join(max(0.0, float(timeout)))
        _WORKER = None
