from __future__ import annotations

import json
import threading
import time
from types import SimpleNamespace

from pihole_manager.config import ResearchProviderOptions
from pihole_manager.research import provider_snapshot


def test_provider_snapshot_redacts_api_key() -> None:
    provider = ResearchProviderOptions(
        name="VirusTotal",
        kind="virustotal",
        api_key="secret-token",
    )
    snapshot = provider_snapshot(provider)
    assert snapshot["api_key"] == "***"
    assert snapshot["kind"] == "virustotal"
    assert snapshot["mode"] == "lookup"
    assert snapshot["sends_domain"] is True


def test_cached_research_is_used_without_external_refresh(monkeypatch, tmp_path) -> None:
    from pihole_manager.config import load_options, save_options
    from pihole_manager.database import init_db, save_research_findings
    from pihole_manager.models import ResearchFinding
    from pihole_manager.workers import Classifier

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    options = load_options()
    for provider in options.research_providers:
        provider.enabled = False
    save_options(options)
    now = int(time.time())
    save_research_findings(
        [
            ResearchFinding(
                domain="cached.example",
                provider="cache",
                kind="test",
                title="Cached evidence",
                summary="Stored locally",
                retrieved_at=now,
                expires_at=now + 3600,
            )
        ]
    )

    dossier = Classifier()._build_dossier("cached.example")

    assert dossier["research"]["findings"][0]["title"] == "Cached evidence"


def test_enabled_research_source_refreshes_without_global_switch(monkeypatch, tmp_path) -> None:
    from pihole_manager.config import load_options, save_options
    from pihole_manager.database import init_db
    from pihole_manager.models import ResearchFinding
    from pihole_manager.research import research_domain

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    options = load_options()
    for provider in options.research_providers:
        provider.enabled = False
    options.research_providers[0].enabled = True
    options.research_providers[0].name = "Test source"
    save_options(options)
    calls: list[str] = []

    def fake_provider(domain, provider):
        calls.append(provider.name)
        now = int(time.time())
        return [
            ResearchFinding(
                domain=domain,
                provider=provider.name,
                kind="test",
                title="Fresh evidence",
                summary="Fetched once",
                retrieved_at=now,
                expires_at=now + 3600,
            )
        ]

    monkeypatch.setattr("pihole_manager.research._run_provider", fake_provider)

    first = research_domain("fresh.example")
    second = research_domain("fresh.example")

    assert first[0].title == "Fresh evidence"
    assert second[0].title == "Fresh evidence"
    assert calls == ["Test source"]


def test_research_context_hides_negative_cache_rows(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import init_db, save_research_findings
    from pihole_manager.models import ResearchFinding
    from pihole_manager.research import research_context

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    now = int(time.time())
    save_research_findings(
        [
            ResearchFinding(
                domain="example.com",
                provider="No match",
                kind="lookup_status",
                title="No matching evidence",
                summary="No match",
                retrieved_at=now,
                expires_at=now + 3600,
                raw_data={"include_in_prompt": False},
            ),
            ResearchFinding(
                domain="example.com",
                provider="Threat source",
                kind="ioc_database",
                title="Confirmed IOC",
                summary="Exact active IOC",
                signal_type="security",
                verdict="command_and_control",
                decision_relevant=True,
                confidence=0.99,
                retrieved_at=now,
                expires_at=now + 3600,
            ),
        ]
    )

    context = research_context("example.com")

    assert context["finding_count"] == 1
    assert context["decision_relevant_count"] == 1
    assert context["findings"][0]["verdict"] == "command_and_control"


def test_adguard_service_catalog_is_matched_locally(monkeypatch) -> None:
    from pihole_manager.research_catalogs import research_adguard_services

    payload = json.dumps(
        [
            {
                "id": "example-service",
                "name": "Example Service",
                "group": "software",
                "rules": ["||api.example.com^"],
            }
        ]
    ).encode()
    monkeypatch.setattr(
        "pihole_manager.research_catalogs.fetch_cached_bytes",
        lambda *_args, **_kwargs: payload,
    )
    provider = ResearchProviderOptions(
        name="AdGuard",
        kind="adguard_services",
        enabled=True,
    )

    findings = research_adguard_services("sub.api.example.com", provider)

    assert findings[0].verdict == "service_match"
    assert findings[0].decision_relevant is False
    assert "Example Service" in findings[0].summary


def test_netcraft_parser_extracts_selected_table_fields() -> None:
    from pihole_manager.research_lookups import (
        _NetcraftTableParser,
        _select_netcraft_fields,
    )

    parser = _NetcraftTableParser()
    parser.feed(
        "<table><tr><th>Hosting company</th><td>Example Hosting</td></tr>"
        "<tr><th>Site rank</th><td>123</td></tr>"
        "<tr><th>Unrelated</th><td>ignored</td></tr></table>"
    )

    assert _select_netcraft_fields(parser.fields) == {
        "Site rank": "123",
        "Hosting company": "Example Hosting",
    }


def test_dns_source_falls_back_when_dnspython_is_missing(monkeypatch) -> None:
    from pihole_manager import research_lookups
    from pihole_manager.config import ResearchProviderOptions

    monkeypatch.setattr(research_lookups, "dns_resolver", None)
    monkeypatch.setattr(research_lookups, "dns_exception", None)
    monkeypatch.setattr(
        research_lookups.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (
                research_lookups.socket.AF_INET,
                research_lookups.socket.SOCK_STREAM,
                6,
                "example.com",
                ("93.184.216.34", 0),
            )
        ],
    )
    provider = ResearchProviderOptions(
        name="Local DNS records",
        kind="dns_records",
        enabled=True,
    )

    findings = research_lookups.research_dns_records("example.com", provider)

    assert findings[0].raw_data["backend"] == "socket_fallback"
    assert findings[0].raw_data["records"] == {"A": ["93.184.216.34"]}
    assert findings[0].decision_relevant is False


def test_protected_domain_uses_cache_and_blocks_forced_refresh(monkeypatch, tmp_path) -> None:
    import pytest

    from pihole_manager.database import init_db, save_research_findings, set_domain_lock
    from pihole_manager.models import ResearchFinding
    from pihole_manager.research import research_domain

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    now = int(time.time())
    save_research_findings(
        [
            ResearchFinding(
                domain="locked.example",
                provider="cache",
                kind="test",
                title="Cached evidence",
                summary="Stored before the lock",
                retrieved_at=now,
                expires_at=now + 3600,
            )
        ]
    )
    set_domain_lock("locked.example", "deny", "Do not re-evaluate")

    assert research_domain("locked.example")[0].title == "Cached evidence"
    with pytest.raises(RuntimeError, match="Unlock it"):
        research_domain("locked.example", force=True)


def test_evidence_source_test_reports_structured_result(monkeypatch) -> None:
    from pihole_manager.models import ResearchFinding
    from pihole_manager.research import test_research_provider

    provider = ResearchProviderOptions(name="Test source", kind="rdap")

    monkeypatch.setattr(
        "pihole_manager.research._run_provider",
        lambda domain, selected: [
            ResearchFinding(
                domain=domain,
                provider=selected.name,
                kind="registration",
                title="RDAP result",
                summary="Registrar data available",
                source_url="https://example.test",
                confidence=0.8,
                signal_type="identity",
                verdict="registration_context",
                decision_relevant=False,
                retrieved_at=1,
                expires_at=2,
                raw_data={},
            )
        ],
    )

    result = test_research_provider(provider)

    assert result.success is True
    assert result.provider == "Test source"
    assert result.finding_count == 1
    assert "registration_context" in result.summary


def test_evidence_source_test_can_skip_api_key_sources() -> None:
    from pihole_manager.research import test_research_provider

    provider = ResearchProviderOptions(
        name="VirusTotal",
        kind="virustotal",
        api_key="configured",
    )

    result = test_research_provider(provider, skip_api_key_sources=True)

    assert result.status == "skip"
    assert result.domain == "example.com"


def test_evidence_source_test_can_skip_missing_api_keys() -> None:
    from pihole_manager.research import test_research_provider

    provider = ResearchProviderOptions(name="ThreatFox", kind="threatfox")

    result = test_research_provider(provider, skip_missing_api_keys=True)

    assert result.status == "skip"
    assert "no API key" in result.summary


def test_evidence_queues_are_serial_per_source_and_parallel_between_sources(
    monkeypatch,
) -> None:
    from pihole_manager.models import ResearchFinding
    from pihole_manager.research import research_many

    providers = [
        ResearchProviderOptions(
            name="Provider A",
            kind="rdap",
            enabled=True,
            min_interval_sec=0.0,
        ),
        ResearchProviderOptions(
            name="Provider B",
            kind="rdap",
            enabled=True,
            min_interval_sec=0.0,
        ),
    ]
    options = SimpleNamespace(
        research_providers=providers,
        llm=SimpleNamespace(max_retries=0),
    )
    monkeypatch.setattr("pihole_manager.research.load_options", lambda: options)
    monkeypatch.setattr(
        "pihole_manager.research.research_findings_get",
        lambda *_args, **_kwargs: [],
    )
    monkeypatch.setattr(
        "pihole_manager.research.get_domain_lock",
        lambda _domain: None,
    )
    monkeypatch.setattr(
        "pihole_manager.research.save_research_findings",
        lambda values, **_kwargs: len(list(values)),
    )

    lock = threading.Lock()
    active_by_provider: dict[str, int] = {}
    max_by_provider: dict[str, int] = {}
    active_total = 0
    max_total = 0

    def fake_run(
        domain: str,
        provider: ResearchProviderOptions,
    ) -> list[ResearchFinding]:
        nonlocal active_total, max_total
        with lock:
            active_by_provider[provider.name] = active_by_provider.get(provider.name, 0) + 1
            max_by_provider[provider.name] = max(
                max_by_provider.get(provider.name, 0),
                active_by_provider[provider.name],
            )
            active_total += 1
            max_total = max(max_total, active_total)
        time.sleep(0.03)
        with lock:
            active_by_provider[provider.name] -= 1
            active_total -= 1
        now = int(time.time())
        return [
            ResearchFinding(
                domain=domain,
                provider=provider.name,
                kind="test",
                title="Test",
                summary="Test finding",
                retrieved_at=now,
                expires_at=now + 60,
            )
        ]

    monkeypatch.setattr("pihole_manager.research._run_provider", fake_run)

    result = research_many(["a.example", "b.example"])

    assert set(result) == {"a.example", "b.example"}
    assert all(value == 1 for value in max_by_provider.values())
    assert max_total >= 2


def test_catalog_indexes_for_different_sources_remain_cached() -> None:
    from pihole_manager import research_catalogs

    research_catalogs._INDEX_CACHE.clear()
    research_catalogs._INDEX_LOCKS.clear()
    calls: list[bytes] = []

    def build(payload: bytes) -> dict[str, bytes]:
        calls.append(payload)
        return {"payload": payload}

    first = research_catalogs._cached_index("adguard", b"one", build)
    second = research_catalogs._cached_index("disconnect", b"two", build)
    repeated = research_catalogs._cached_index("adguard", b"one", build)

    assert first is repeated
    assert second == {"payload": b"two"}
    assert calls == [b"one", b"two"]


def test_catalog_downloads_use_independent_cache_locks(monkeypatch, tmp_path) -> None:
    from concurrent.futures import ThreadPoolExecutor

    from pihole_manager.research_common import fetch_cached_bytes

    monkeypatch.setattr(
        "pihole_manager.research_common.cache_directory",
        lambda: tmp_path,
    )
    monkeypatch.setattr(
        "pihole_manager.research_common.wait_for_provider",
        lambda _provider: None,
    )
    both_entered = threading.Event()
    counter_lock = threading.Lock()
    active = 0

    class Response:
        status_code = 200
        headers: dict[str, str] = {}
        content = b"catalog"

        def raise_for_status(self) -> None:
            return None

    def fake_get(*_args, **_kwargs):
        nonlocal active
        with counter_lock:
            active += 1
            if active == 2:
                both_entered.set()
        if not both_entered.wait(1):
            raise AssertionError("Different catalog downloads were serialized")
        with counter_lock:
            active -= 1
        return Response()

    monkeypatch.setattr("pihole_manager.research_common.requests.get", fake_get)
    providers = (
        ResearchProviderOptions(name="A", kind="adguard_services"),
        ResearchProviderOptions(name="B", kind="disconnect_tracking"),
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(
                fetch_cached_bytes,
                provider,
                f"https://example.test/{provider.name}",
                accept="application/json",
            )
            for provider in providers
        ]

    assert [future.result() for future in futures] == [b"catalog", b"catalog"]


def test_final_transient_evidence_failure_updates_backoff(monkeypatch) -> None:
    import pytest
    import requests

    from pihole_manager.research import _run_provider_with_retries

    provider = ResearchProviderOptions(name="Limited", kind="rdap")
    options = SimpleNamespace(llm=SimpleNamespace(max_retries=0))
    response = requests.Response()
    response.status_code = 429
    error = requests.HTTPError("rate limited", response=response)
    failures: list[int] = []

    def fail(*_args, **_kwargs):
        raise error

    monkeypatch.setattr("pihole_manager.research.load_options", lambda: options)
    monkeypatch.setattr("pihole_manager.research._run_provider", fail)
    monkeypatch.setattr(
        "pihole_manager.research.register_provider_failure",
        lambda _provider, attempt, _response=None: failures.append(attempt),
    )

    with pytest.raises(requests.HTTPError):
        _run_provider_with_retries("example.com", provider)

    assert failures == [0]
