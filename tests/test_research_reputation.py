from __future__ import annotations

import pytest

from pihole_manager.config import ResearchProviderOptions
from pihole_manager.research import _PROVIDER_HANDLERS
from pihole_manager.research import test_research_provider as run_provider_test
from pihole_manager.research_common import ResearchError
from pihole_manager.research_reputation import research_crtsh, research_google_safe_browsing


class _Response:
    def __init__(self, payload, *, url: str = "https://example.invalid/") -> None:
        self._payload = payload
        self.url = url

    def raise_for_status(self) -> None:
        return None

    def json(self):
        return self._payload


def test_crtsh_returns_context_only(monkeypatch) -> None:
    payload = [
        {
            "name_value": "example.com\nwww.example.com",
            "issuer_name": "Example CA",
            "not_before": "2026-01-01T00:00:00",
            "not_after": "2030-01-01T00:00:00",
        }
    ]
    monkeypatch.setattr(
        "pihole_manager.research_reputation.requests.get",
        lambda *_args, **_kwargs: _Response(
            payload,
            url="https://crt.sh/?q=example.com&output=json",
        ),
    )
    monkeypatch.setattr(
        "pihole_manager.research_reputation.wait_for_provider",
        lambda _provider: None,
    )
    provider = ResearchProviderOptions(
        name="crt.sh",
        kind="crtsh",
        enabled=True,
        min_interval_sec=0.0,
    )

    finding = research_crtsh("Example.COM.", provider)[0]

    assert finding.kind == "registration"
    assert finding.verdict == "certificate_transparency_context"
    assert finding.decision_relevant is False
    assert finding.raw_data["matching_names"] == ["example.com", "www.example.com"]


def test_safe_browsing_requires_key() -> None:
    provider = ResearchProviderOptions(name="Safe Browsing", kind="google_safe_browsing")

    with pytest.raises(ResearchError, match="API key"):
        research_google_safe_browsing("example.com", provider)


def test_safe_browsing_maps_social_engineering_to_phishing(monkeypatch) -> None:
    captured = {}

    def fake_get(url: str, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return _Response(
            {
                "threats": [
                    {
                        "url": "https://bad.example/",
                        "threatTypes": ["SOCIAL_ENGINEERING"],
                    }
                ],
                "cacheDuration": "300s",
            }
        )

    monkeypatch.setattr("pihole_manager.research_reputation.requests.get", fake_get)
    monkeypatch.setattr(
        "pihole_manager.research_reputation.wait_for_provider",
        lambda _provider: None,
    )
    provider = ResearchProviderOptions(
        name="Safe Browsing",
        kind="google_safe_browsing",
        enabled=True,
        base_url="https://safebrowsing.googleapis.com",
        api_key="secret-key",
        min_interval_sec=0.0,
    )

    finding = research_google_safe_browsing("bad.example", provider)[0]

    assert captured["url"] == "https://safebrowsing.googleapis.com/v5/urls:search"
    assert ("key", "secret-key") in captured["params"]
    assert ("urls", "https://bad.example/") in captured["params"]
    assert finding.verdict == "phishing"
    assert finding.decision_relevant is True
    assert finding.raw_data["cache_duration"] == "300s"


def test_safe_browsing_no_match_is_neutral(monkeypatch) -> None:
    monkeypatch.setattr(
        "pihole_manager.research_reputation.requests.get",
        lambda *_args, **_kwargs: _Response({"threats": [], "cacheDuration": "600s"}),
    )
    monkeypatch.setattr(
        "pihole_manager.research_reputation.wait_for_provider",
        lambda _provider: None,
    )
    provider = ResearchProviderOptions(
        name="Safe Browsing",
        kind="google_safe_browsing",
        enabled=True,
        api_key="secret-key",
        min_interval_sec=0.0,
    )

    finding = research_google_safe_browsing("example.com", provider)[0]

    assert finding.verdict == "no_match"
    assert finding.decision_relevant is False


def test_research_dispatch_registers_new_adapters_and_api_key_skip() -> None:
    assert _PROVIDER_HANDLERS["crtsh"] is research_crtsh
    assert _PROVIDER_HANDLERS["google_safe_browsing"] is research_google_safe_browsing

    result = run_provider_test(
        ResearchProviderOptions(
            name="Safe Browsing",
            kind="google_safe_browsing",
            enabled=True,
        ),
        skip_missing_api_keys=True,
    )
    assert result.status == "skip"
