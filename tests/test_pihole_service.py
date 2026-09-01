from __future__ import annotations

from types import SimpleNamespace

from pihole6api.health import ConnectionHealth, ConnectionState
from pihole_manager import pihole_service
from pihole_manager.config import PiHoleOptions
from pihole_manager.pihole_service import _extract_version


def test_extract_version_understands_real_v6_component_shape() -> None:
    payload = {
        "version": {
            "core": {"local": {"version": "v6.4.3"}},
            "web": {"local": {"version": "v6.5"}},
            "ftl": {"local": {"version": "v6.6.2"}},
        }
    }

    assert _extract_version(payload) == "v6.6.2"


def test_connection_reports_invalid_configuration_without_network_access() -> None:
    result = pihole_service.test_connection(PiHoleOptions(base_url="ftp://pi.hole"))

    assert result.success is False
    assert result.state == ConnectionState.INVALID_CONFIG
    assert "configuration is invalid" in result.summary


def test_connection_reports_incompatible_success_payload_as_api_error(monkeypatch) -> None:
    client = SimpleNamespace(
        ftl_info=SimpleNamespace(get_version=lambda: "<html>not the API</html>"),
        connection=SimpleNamespace(
            health=ConnectionHealth(state=ConnectionState.ONLINE),
        ),
    )
    monkeypatch.setattr(pihole_service, "configure_client", lambda _settings: client)

    result = pihole_service.test_connection(PiHoleOptions())

    assert result.success is False
    assert result.state == ConnectionState.API_ERROR
    assert "incompatible API response" in result.summary


def test_fetch_groups_normalizes_and_sorts(monkeypatch) -> None:
    client = SimpleNamespace(
        group_management=SimpleNamespace(
            get_groups=lambda: {
                "groups": [
                    {"id": 2, "name": "IoT", "enabled": False, "comment": "devices"},
                    {"id": 0, "name": "Default", "enabled": True},
                ]
            }
        )
    )
    monkeypatch.setattr(pihole_service, "get_client", lambda: client)

    assert pihole_service.fetch_groups() == [
        {"id": 0, "name": "Default", "comment": "", "enabled": True},
        {"id": 2, "name": "IoT", "comment": "devices", "enabled": False},
    ]


def test_update_exact_domain_groups_preserves_metadata_and_deduplicates(monkeypatch) -> None:
    calls = []
    client = SimpleNamespace(
        domain_management=SimpleNamespace(
            update_domain=lambda *args, **kwargs: calls.append((args, kwargs)) or {"ok": True}
        )
    )
    monkeypatch.setattr(pihole_service, "get_client", lambda: client)

    result = pihole_service.update_exact_domain_groups(
        "example.com", "deny", [3, 1, 3], comment="keep", enabled=False
    )

    assert result == {"ok": True}
    assert calls == [
        (
            (),
            {
                "domain": "example.com",
                "domain_type": "deny",
                "kind": "exact",
                "comment": "keep",
                "groups": [1, 3],
                "enabled": False,
            },
        )
    ]


def test_subscribed_list_group_assignment_uses_list_api(monkeypatch) -> None:
    calls = []
    client = SimpleNamespace(
        list_management=SimpleNamespace(
            update_list=lambda *args, **kwargs: calls.append((args, kwargs)) or {"ok": True}
        )
    )
    monkeypatch.setattr(pihole_service, "get_client", lambda: client)

    result = pihole_service.update_subscribed_list_groups(
        "https://example.invalid/list.txt",
        "block",
        [4, 2, 4],
        comment="source",
        enabled=True,
    )

    assert result == {"ok": True}
    assert calls == [
        (
            (),
            {
                "address": "https://example.invalid/list.txt",
                "list_type": "block",
                "comment": "source",
                "groups": [2, 4],
                "enabled": True,
            },
        )
    ]
