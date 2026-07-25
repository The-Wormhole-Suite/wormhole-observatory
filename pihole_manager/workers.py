from __future__ import annotations

import logging
import threading
import time

from pihole_manager.config import load_options
from pihole_manager.database import (
    review_save_classification,
    staging_ack,
    staging_claim,
    staging_enqueue,
    staging_fail,
    staging_requeue_processing,
)
from pihole_manager.llm import classify_domain
from pihole_manager.models import AutomationMode, Classification, Policy
from pihole_manager.notifications import Notifier
from pihole_manager.pihole_service import add_exact_domain, fetch_queries, test_connection

log = logging.getLogger(__name__)


class ManagedWorker(threading.Thread):
    def __init__(self, name: str) -> None:
        super().__init__(name=name, daemon=True)
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def wait(self, seconds: float) -> bool:
        return self._stop_event.wait(max(0.1, seconds))


class Scanner(ManagedWorker):
    def __init__(self) -> None:
        super().__init__("PiHoleScanner")
        self._from_ts = int(time.time()) - load_options().scans.initial_lookback_sec
        self._notifier = Notifier()

    def run(self) -> None:
        log.info("Pi-hole scanner started")
        backoff = 1
        while not self._stop_event.is_set():
            options = load_options()
            if not options.scans.enabled:
                self.wait(options.scans.interval_sec)
                continue
            try:
                result = test_connection()
                if not result.success:
                    raise RuntimeError(result.summary)
                rows = fetch_queries(options.scans.batch_size, self._from_ts)
                domains = {
                    str(row.get("domain") or "").strip().lower()
                    for row in rows
                    if str(row.get("domain") or "").strip()
                }
                added = staging_enqueue(domains)
                timestamps = [int(row.get("time") or 0) for row in rows]
                if timestamps:
                    self._from_ts = max(self._from_ts, max(timestamps) + 1)
                if added:
                    log.info("Queued %s new domain(s) for LLM analysis", added)
                backoff = 1
                self.wait(options.scans.interval_sec)
            except Exception as exc:
                log.warning("Scanner cycle failed: %s", exc)
                self.wait(min(60, backoff))
                backoff = min(60, backoff * 2)
        log.info("Pi-hole scanner stopped")


class Classifier(ManagedWorker):
    def __init__(self) -> None:
        super().__init__("LLMClassifier")
        self._notifier = Notifier()

    def run(self) -> None:
        staging_requeue_processing()
        log.info("LLM classifier started")
        while not self._stop_event.is_set():
            options = load_options()
            if not options.llm.enabled:
                self.wait(options.llm.interval_sec)
                continue

            domains = staging_claim(options.llm.batch_size)
            if not domains:
                self.wait(options.llm.interval_sec)
                continue

            for domain in domains:
                if self._stop_event.is_set():
                    staging_fail(domain, "Classifier stopped before processing")
                    break
                try:
                    classification = classify_domain(domain)
                    action = resolve_automatic_action(classification)
                    status = "classified"
                    if action is not None:
                        add_exact_domain(domain, action, classification.short)
                        status = f"auto_{action.value}"
                    review_save_classification(classification, status=status)
                    staging_ack(domain)
                    if action is not None:
                        self._notifier.notify(
                            "Pi-hole Manager",
                            f"{action.value}: {domain} — {classification.short}",
                        )
                except Exception as exc:
                    log.warning("Classification failed for %s: %s", domain, exc)
                    staging_fail(domain, str(exc))
        log.info("LLM classifier stopped")


def resolve_automatic_action(classification: Classification) -> Policy | None:
    options = load_options().llm
    try:
        mode = AutomationMode(options.automation_mode)
    except ValueError:
        mode = AutomationMode.HYBRID
    if mode is AutomationMode.MANUAL:
        return None

    configured = options.category_policies.get(
        classification.category.lower(), Policy.MANUAL_REVIEW.value
    )
    try:
        category_policy = Policy(configured)
    except ValueError:
        category_policy = Policy.MANUAL_REVIEW

    if category_policy not in {Policy.ALLOW, Policy.DENY}:
        return None
    if mode is AutomationMode.AUTO:
        return category_policy
    if classification.policy is category_policy:
        return category_policy
    return None


_SCANNER: Scanner | None = None
_CLASSIFIER: Classifier | None = None
_WORKER_LOCK = threading.RLock()


def get_scanner() -> Scanner:
    global _SCANNER
    with _WORKER_LOCK:
        if _SCANNER is None or not _SCANNER.is_alive():
            _SCANNER = Scanner()
            _SCANNER.start()
        return _SCANNER


def get_classifier() -> Classifier:
    global _CLASSIFIER
    with _WORKER_LOCK:
        if _CLASSIFIER is None or not _CLASSIFIER.is_alive():
            _CLASSIFIER = Classifier()
            _CLASSIFIER.start()
        return _CLASSIFIER


def stop_workers(timeout: float = 5.0) -> None:
    global _SCANNER, _CLASSIFIER
    with _WORKER_LOCK:
        workers: list[ManagedWorker] = [
            worker for worker in (_SCANNER, _CLASSIFIER) if worker is not None
        ]
        for worker in workers:
            worker.stop()
        deadline = time.monotonic() + timeout
        for worker in workers:
            remaining = max(0.0, deadline - time.monotonic())
            worker.join(remaining)
        _SCANNER = None
        _CLASSIFIER = None
