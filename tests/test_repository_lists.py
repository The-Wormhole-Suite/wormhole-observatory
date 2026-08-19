from __future__ import annotations

from pihole_manager.config import ResearchProviderOptions
from pihole_manager.repository_lists import (
    _build_repository_list_index,
    _domain_from_repository_rule,
    research_repository_lists,
)


def test_repository_rule_parser_accepts_domain_hosts_and_adblock_formats() -> None:
    assert _domain_from_repository_rule("tracker.example") == "tracker.example"
    assert _domain_from_repository_rule("0.0.0.0 tracker.example") == "tracker.example"
    assert _domain_from_repository_rule("127.0.0.1 ads.example # comment") == "ads.example"
    assert _domain_from_repository_rule("||metrics.example^$third-party") == "metrics.example"


def test_repository_rule_parser_rejects_exceptions_patterns_and_ips() -> None:
    assert _domain_from_repository_rule("@@||allowed.example^") == ""
    assert _domain_from_repository_rule("||mkto-*.com^$third-party") == ""
    assert _domain_from_repository_rule("||0.0.0.1^") == ""
    assert _domain_from_repository_rule("! comment") == ""
    assert _domain_from_repository_rule("$ping,third-party") == ""


def test_repository_index_keeps_rule_and_line_provenance() -> None:
    payload = b"! heading\n||tracker.example^\n0.0.0.0 ads.example\n"

    index = _build_repository_list_index(payload)

    assert index["tracker.example"] == [
        {
            "matched_domain": "tracker.example",
            "rule": "||tracker.example^",
            "line_number": 2,
        }
    ]
    assert index["ads.example"][0]["line_number"] == 3


def test_repository_lookup_carries_full_source_provenance(monkeypatch) -> None:
    payloads = {
        "hagezi": b"||bad.example^\n",
        "easyprivacy": b"||tracker.example^\n",
    }

    def fake_fetch(_provider, url: str, *, accept: str) -> bytes:
        assert accept == "text/plain"
        return payloads["hagezi" if "hagezi" in url else "easyprivacy"]

    monkeypatch.setattr("pihole_manager.repository_lists.fetch_cached_bytes", fake_fetch)
    provider = ResearchProviderOptions(
        name="Repository lists",
        kind="repository_lists",
        enabled=True,
        refresh_interval_hours=12,
        max_results=5,
    )

    security = research_repository_lists("sub.bad.example", provider)
    privacy = research_repository_lists("tracker.example", provider)

    assert len(security) == 1
    assert security[0].verdict == "suspicious"
    assert security[0].raw_data["source_id"] == "hagezi_tif_mini"
    assert security[0].raw_data["repository"] == "https://github.com/hagezi/dns-blocklists"
    assert security[0].raw_data["license_id"] == "GPL-3.0"
    assert security[0].raw_data["license_review_required"] is False
    assert security[0].raw_data["rule"] == "||bad.example^"
    assert security[0].raw_data["line_number"] == 1

    assert len(privacy) == 1
    assert privacy[0].verdict == "tracker"
    assert privacy[0].raw_data["source_id"] == "easyprivacy_trackingservers"
    assert privacy[0].raw_data["license_review_required"] is True


def test_repository_lookup_treats_no_match_as_neutral(monkeypatch) -> None:
    monkeypatch.setattr(
        "pihole_manager.repository_lists.fetch_cached_bytes",
        lambda *_args, **_kwargs: b"||other.example^\n",
    )
    provider = ResearchProviderOptions(
        name="Repository lists",
        kind="repository_lists",
        enabled=True,
    )

    findings = research_repository_lists("clean.example", provider)

    assert len(findings) == 1
    assert findings[0].verdict == "no_match"
    assert findings[0].decision_relevant is False
    assert findings[0].raw_data["include_in_prompt"] is False
