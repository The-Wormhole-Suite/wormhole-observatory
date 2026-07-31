from __future__ import annotations


def test_history_deduplication_keeps_newest_domain_row() -> None:
    from pihole_manager.gui.tabs.history import _deduplicate_rows

    rows = [
        {"domain": "Example.COM", "time": 30.0, "client": "phone"},
        {"domain": "other.example", "time": 20.0, "client": "tablet"},
        {"domain": "example.com", "time": 10.0, "client": "laptop"},
    ]

    deduplicated = _deduplicate_rows(rows)

    assert [row["domain"] for row in deduplicated] == [
        "Example.COM",
        "other.example",
    ]
    assert deduplicated[0]["client"] == "phone"
