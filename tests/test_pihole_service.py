from __future__ import annotations

from types import SimpleNamespace

from pihole6api.health import ConnectionHealth, ConnectionState
from pihole_manager.config import PiHoleOptions
from pihole_manager import pihole_service
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
