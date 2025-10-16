
import logging, threading, time, queue
from typing import List, Dict, Any
from config import load_options
from db import init_db, save_annotation, get_annotation, log_action, upsert_domain
from pihole import client
from llm import classify_domain
from notify import Notifier

log = logging.getLogger(__name__)

class Scanner(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True, name="Scanner")
        self._stop = threading.Event()
        self._wake = threading.Event()
        self.last_ts = int(time.time()) - 60
        self.notifier = Notifier()

    def run(self):
        init_db()
        log.info("Scanner started")
        while not self._stop.is_set():
            opts = load_options()
            if opts.scans.enabled:
                try:
                    self.step()
                except Exception as e:
                    log.exception("Scan step error: %s", e)
                time.sleep(max(1, min(opts.scans.interval_seconds, 5)))  # short loop, real interval inside step
            else:
                self._wake.wait(timeout=1.0)
                self._wake.clear()

    def step(self):
        opts = load_options()
        # fetch new queries since last_ts
        queries = client.poll_queries_since(self.last_ts)
        if queries:
            self.last_ts = max(q.get("ts", self.last_ts) for q in queries)
        # dedupe to domains
        domains = []
        seen = set()
        for q in queries:
            d = q.get("domain")
            if not d or d in seen:
                continue
            seen.add(d)
            domains.append(d)
        if not domains:
            return
        batch = domains[:opts.scans.batch_size]
        for domain in batch:
            upsert_domain(domain)
            ann = get_annotation(domain)
            if ann and not opts.scans.recheck_even_if_annotated:
                continue
            res = classify_domain(domain)
            save_annotation(domain, source="scan", category=res["category"], policy=res["policy"], short=res["short"], details=res["details"], provider=res["provider"])
            # Automation
            if opts.automation.dry_run:
                continue
            if res["policy"] == "block" and opts.automation.auto_block:
                applied = client.deny_exact(domain, comment=res["short"])
                log_action(domain, "deny_exact", "deny", res["short"], by_user=False, by_auto=True)
            elif res["policy"] == "allow" and opts.automation.auto_allow:
                applied = client.allow_exact(domain, comment=res["short"])
                log_action(domain, "allow_exact", "allow", res["short"], by_user=False, by_auto=True)

    def wake(self):
        self._wake.set()

    def stop(self):
        self._stop.set()
        self.wake()

_scanner = None

def get_scanner() -> Scanner:
    global _scanner
    if _scanner is None:
        _scanner = Scanner()
        _scanner.start()
    return _scanner
