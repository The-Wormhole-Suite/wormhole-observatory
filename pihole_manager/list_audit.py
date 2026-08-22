from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlparse

import requests

from pihole_manager.database import filter_unclassified_domains, staging_enqueue
from pihole_manager.list_audit_config import ListAuditOptions
from pihole_manager.list_rule_parser import domain_from_list_rule
from pihole_manager.pihole_service import fetch_subscribed_lists

log = logging.getLogger(__name__)
_MAX_DOWNLOAD_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ListFetchResult:
    domains: tuple[str, ...]
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class ListAuditSummary:
    lists_seen: int = 0
    lists_audited: int = 0
    lists_failed: int = 0
    domains_seen: int = 0
    domains_queued: int = 0
    batches: int = 0
    truncated_lists: int = 0
    cancelled: bool = False


def extract_domains_from_lines(
    lines: Iterable[str | bytes],
    *,
    max_domains: int,
    max_bytes: int = _MAX_DOWNLOAD_BYTES,
) -> ListFetchResult:
    limit = max(1, int(max_domains))
    byte_limit = max(1, int(max_bytes))
    domains: list[str] = []
    seen: set[str] = set()
    consumed = 0
    truncated = False
    for raw_line in lines:
        if isinstance(raw_line, bytes):
            consumed += len(raw_line) + 1
            line = raw_line.decode("utf-8", errors="replace")
        else:
            encoded = str(raw_line).encode("utf-8", errors="replace")
            consumed += len(encoded) + 1
            line = str(raw_line)
        if consumed > byte_limit:
            truncated = True
            break
        domain = domain_from_list_rule(line)
        if not domain or domain in seen:
            continue
        seen.add(domain)
        domains.append(domain)
        if len(domains) >= limit:
            truncated = True
            break
    return ListFetchResult(tuple(domains), truncated=truncated)


def fetch_domains_from_list(
    address: str,
    *,
    timeout_sec: float,
    max_domains: int,
) -> ListFetchResult:
    parsed = urlparse(str(address).strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("List audit currently supports HTTP and HTTPS list addresses only.")
    headers = {
        "Accept": "text/plain,*/*;q=0.5",
        "User-Agent": "Wormhole-Observatory/ListAudit",
    }
    with requests.get(
        address,
        headers=headers,
        timeout=max(1.0, float(timeout_sec)),
        stream=True,
    ) as response:
        response.raise_for_status()
        return extract_domains_from_lines(
            response.iter_lines(),
            max_domains=max_domains,
        )


def run_list_audit_cycle(
    audit: ListAuditOptions,
    *,
    timeout_sec: float,
    should_stop: Callable[[], bool] | None = None,
    wait: Callable[[float], bool] | None = None,
    list_fetcher: Callable[[], list[dict]] = fetch_subscribed_lists,
    domain_fetcher: Callable[..., ListFetchResult] = fetch_domains_from_list,
    eligible_filter: Callable[[Iterable[str]], list[str]] = filter_unclassified_domains,
    enqueue: Callable[..., int] = staging_enqueue,
) -> ListAuditSummary:
    stop = should_stop or (lambda: False)
    pause = wait or (lambda _seconds: False)
    rows = [row for row in list_fetcher() if bool(row.get("enabled", True))]
    lists_seen = len(rows)
    lists_audited = lists_failed = domains_seen = domains_queued = batches = truncated = 0
    first_batch = True

    for row in rows:
        if stop():
            return ListAuditSummary(
                lists_seen, lists_audited, lists_failed, domains_seen, domains_queued,
                batches, truncated, True
            )
        address = str(row.get("address") or "").strip()
        if not address:
            lists_failed += 1
            continue
        try:
            fetched = domain_fetcher(
                address,
                timeout_sec=timeout_sec,
                max_domains=audit.max_domains_per_list,
            )
        except Exception as exc:
            lists_failed += 1
            log.warning("List audit could not read %s: %s", address, exc)
            continue

        lists_audited += 1
        domains_seen += len(fetched.domains)
        if fetched.truncated:
            truncated += 1
        eligible_domains = eligible_filter(fetched.domains)
        batch_size = max(1, int(audit.batch_size))
        for index in range(0, len(eligible_domains), batch_size):
            if stop():
                return ListAuditSummary(
                    lists_seen, lists_audited, lists_failed, domains_seen, domains_queued,
                    batches, truncated, True
                )
            if not first_batch and audit.rate_limit_sec > 0:
                if pause(float(audit.rate_limit_sec)):
                    return ListAuditSummary(
                        lists_seen, lists_audited, lists_failed, domains_seen, domains_queued,
                        batches, truncated, True
                    )
            batch = list(eligible_domains[index : index + batch_size])
            domains_queued += enqueue(
                batch,
                priority=0,
                source="list_audit",
                pool_id="background",
            )
            batches += 1
            first_batch = False

    return ListAuditSummary(
        lists_seen, lists_audited, lists_failed, domains_seen, domains_queued, batches, truncated
    )
