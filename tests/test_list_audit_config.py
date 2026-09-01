from __future__ import annotations

from pihole_manager.list_audit_config import ListAuditOptions, normalize_list_audit_options


def test_list_audit_options_are_safely_bounded() -> None:
    options = normalize_list_audit_options(
        ListAuditOptions(
            enabled=True,
            interval_sec=1,
            batch_size=0,
            rate_limit_sec=-2,
            max_domains_per_list=999_999,
        )
    )

    assert options.enabled is True
    assert options.interval_sec == 300
    assert options.batch_size == 1
    assert options.rate_limit_sec == 0.0
    assert options.max_domains_per_list == 100_000
