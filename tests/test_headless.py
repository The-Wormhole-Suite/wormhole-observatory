from __future__ import annotations

import pytest

from pihole_manager.config import ExternalTriggerOptions
from pihole_manager.headless import build_headless_trigger_options


def test_headless_requires_authentication_token() -> None:
    with pytest.raises(RuntimeError, match="WORMHOLE_API_TOKEN"):
        build_headless_trigger_options(ExternalTriggerOptions(), {})


def test_headless_uses_safe_container_defaults() -> None:
    trigger, access = build_headless_trigger_options(
        ExternalTriggerOptions(max_domains_per_request=500),
        {"WORMHOLE_API_TOKEN": "secret-token"},
    )

    assert trigger.enabled is True
    assert trigger.bind_host == "0.0.0.0"
    assert trigger.port == 8765
    assert trigger.token == "secret-token"
    assert trigger.allow_remote is True
    assert trigger.max_domains_per_request == 500
    assert access.mode == "lan_tailscale"


def test_headless_accepts_explicit_runtime_overrides() -> None:
    trigger, access = build_headless_trigger_options(
        ExternalTriggerOptions(token="stored-token"),
        {
            "WORMHOLE_API_TOKEN": "runtime-token",
            "WORMHOLE_BIND_HOST": "127.0.0.1",
            "WORMHOLE_PORT": "9000",
            "WORMHOLE_ACCESS_MODE": "local",
            "WORMHOLE_MAX_DOMAINS": "42",
        },
    )

    assert trigger.bind_host == "127.0.0.1"
    assert trigger.port == 9000
    assert trigger.token == "runtime-token"
    assert trigger.allow_remote is False
    assert trigger.max_domains_per_request == 42
    assert access.mode == "local"


def test_headless_rejects_invalid_port_and_access_mode() -> None:
    base = ExternalTriggerOptions(token="stored-token")
    with pytest.raises(ValueError, match="WORMHOLE_PORT"):
        build_headless_trigger_options(base, {"WORMHOLE_PORT": "70000"})
    with pytest.raises(ValueError, match="WORMHOLE_ACCESS_MODE"):
        build_headless_trigger_options(base, {"WORMHOLE_ACCESS_MODE": "internet"})
