from __future__ import annotations

from pihole_manager.list_audit import (
    ListFetchResult,
    extract_domains_from_lines,
    run_list_audit_cycle,
)
from pihole_manager.list_audit_config import ListAuditOptions


def test_extract_domains_supports_common_list_formats_and_deduplicates() -> None:
    result = extract_domains_from_lines(
        [
            "# comment",
            "0.0.0.0 ads.example.com",
            "||tracker.example.org^",
            "ads.example.com",
            "@@||allowed.example^",
            "not a domain",
        ],
        max_domains=10,
    )

    assert result.domains == ("ads.example.com", "tracker.example.org")
    assert result.truncated is False


def test_extract_domains_marks_max_domain_cap_as_truncated() -> None:
    result = extract_domains_from_lines(
        ["one.example", "two.example", "three.example"],
        max_domains=2,
    )

    assert result.domains == ("one.example", "two.example")
    assert result.truncated is True


def test_list_audit_queues_rate_limited_batches_with_audit_provenance() -> None:
    audit = ListAuditOptions(
        enabled=True,
        batch_size=2,
        rate_limit_sec=0.25,
        max_domains_per_list=20,
    )
    enqueued: list[tuple[list[str], str, str]] = []
    waits: list[float] = []
    fetched: list[str] = []

    def list_fetcher() -> list[dict]:
        return [
            {"address": "https://example.test/a.txt", "enabled": True},
            {"address": "https://example.test/disabled.txt", "enabled": False},
        ]

    def domain_fetcher(address: str, **_kwargs) -> ListFetchResult:
        fetched.append(address)
        return ListFetchResult(("a.example", "b.example", "c.example"))

    def enqueue(
        domains: list[str], *, priority: int, source: str, pool_id: str
    ) -> int:
        assert priority == 0
        enqueued.append((domains, source, pool_id))
        return len(domains)

    summary = run_list_audit_cycle(
        audit,
        timeout_sec=5,
        list_fetcher=list_fetcher,
        domain_fetcher=domain_fetcher,
        eligible_filter=lambda domains: list(domains),
        enqueue=enqueue,
        wait=lambda seconds: waits.append(seconds) or False,
    )

    assert fetched == ["https://example.test/a.txt"]
    assert enqueued == [
        (["a.example", "b.example"], "list_audit", "background"),
        (["c.example"], "list_audit", "background"),
    ]
    assert waits == [0.25]
    assert summary.lists_seen == 1
    assert summary.lists_audited == 1
    assert summary.domains_seen == 3
    assert summary.domains_queued == 3
    assert summary.batches == 2
    assert summary.cancelled is False


def test_list_audit_continues_after_one_unreadable_list() -> None:
    audit = ListAuditOptions(enabled=True, batch_size=10)

    def domain_fetcher(address: str, **_kwargs) -> ListFetchResult:
        if address.endswith("bad.txt"):
            raise RuntimeError("network failure")
        return ListFetchResult(("ok.example",))

    summary = run_list_audit_cycle(
        audit,
        timeout_sec=5,
        list_fetcher=lambda: [
            {"address": "https://example.test/bad.txt", "enabled": True},
            {"address": "https://example.test/good.txt", "enabled": True},
        ],
        domain_fetcher=domain_fetcher,
        eligible_filter=lambda domains: list(domains),
        enqueue=lambda domains, **_kwargs: len(domains),
    )

    assert summary.lists_seen == 2
    assert summary.lists_audited == 1
    assert summary.lists_failed == 1
    assert summary.domains_queued == 1
