from __future__ import annotations

import pytest

from pihole_manager.config import Options, ResearchProviderOptions
from pihole_manager.evidence_quality import score_finding
from pihole_manager.research_common import ResearchError, provider_snapshot
from pihole_manager.research_urlhaus import research_urlhaus


class _Response:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, object]:
        return self._payload


def _provider() -> ResearchProviderOptions:
    return ResearchProviderOptions(
        name="URLhaus",
        kind="urlhaus",
        enabled=True,
        base_url="https://urlhaus-api.abuse.ch/v1",
        api_key="secret-auth-key",
        min_interval_sec=0.0,
        refresh_interval_hours=6,
    )


def test_urlhaus_requires_auth_key() -> None:
    provider = ResearchProviderOptions(name="URLhaus", kind="urlhaus")

    with pytest.raises(ResearchError, match="Auth-Key"):
        research_urlhaus("example.com", provider)


def test_urlhaus_uses_authenticated_host_contract(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_post(url: str, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return _Response({"query_status": "no_results"})

    monkeypatch.setattr("pihole_manager.research_urlhaus.requests.post", fake_post)
    monkeypatch.setattr("pihole_manager.research_urlhaus.wait_for_provider", lambda _provider: None)

    findings = research_urlhaus("Sub.Example.COM.", _provider())

    assert captured["url"] == "https://urlhaus-api.abuse.ch/v1/host/"
    assert captured["data"] == {"host": "sub.example.com"}
    headers = captured["headers"]
    assert isinstance(headers, dict)
    assert headers["Auth-Key"] == "secret-auth-key"
    assert findings[0].verdict == "no_match"
    assert findings[0].decision_relevant is False


def test_urlhaus_active_malware_is_decision_relevant(monkeypatch) -> None:
    payload = {
        "query_status": "ok",
        "urlhaus_reference": "https://urlhaus.abuse.ch/host/bad.example/",
        "host": "bad.example",
        "firstseen": "2026-08-19 10:00:00 UTC",
        "url_count": "2",
        "blacklists": {"spamhaus_dbl": "abused_legit_malware"},
        "urls": [
            {
                "id": "1",
                "url_status": "online",
                "threat": "malware_download",
                "tags": ["stealer"],
            },
            {
                "id": "2",
                "url_status": "offline",
                "threat": "malware_download",
                "tags": ["exe"],
            },
        ],
    }
    monkeypatch.setattr(
        "pihole_manager.research_urlhaus.requests.post",
        lambda *_args, **_kwargs: _Response(payload),
    )
    monkeypatch.setattr("pihole_manager.research_urlhaus.wait_for_provider", lambda _provider: None)

    finding = research_urlhaus("bad.example", _provider())[0]

    assert finding.verdict == "malware"
    assert finding.decision_relevant is True
    assert finding.confidence == 0.99
    assert finding.raw_data["active_url_count"] == 1
    assert finding.raw_data["offline_url_count"] == 1
    assert "stealer" in finding.summary
    assert score_finding(finding, now=finding.retrieved_at).source_score == 0.99


def test_urlhaus_historical_only_record_is_not_current_malware(monkeypatch) -> None:
    payload = {
        "query_status": "ok",
        "urlhaus_reference": "https://urlhaus.abuse.ch/host/cleaned.example/",
        "host": "cleaned.example",
        "url_count": "1",
        "urls": [
            {
                "id": "1",
                "url_status": "offline",
                "threat": "malware_download",
                "tags": ["historic"],
            }
        ],
    }
    monkeypatch.setattr(
        "pihole_manager.research_urlhaus.requests.post",
        lambda *_args, **_kwargs: _Response(payload),
    )
    monkeypatch.setattr("pihole_manager.research_urlhaus.wait_for_provider", lambda _provider: None)

    finding = research_urlhaus("cleaned.example", _provider())[0]

    assert finding.verdict == "historical_malware"
    assert finding.decision_relevant is False
    assert "historical/offline" in finding.summary


def test_urlhaus_source_definition_and_default_are_safe() -> None:
    snapshot = provider_snapshot(_provider())
    default = next(item for item in Options().research_providers if item.kind == "urlhaus")

    assert snapshot["mode"] == "lookup"
    assert snapshot["sends_domain"] is True
    assert snapshot["requires_api_key"] is True
    assert snapshot["api_key"] == "***"
    assert default.enabled is False
    assert default.base_url == "https://urlhaus-api.abuse.ch/v1"
