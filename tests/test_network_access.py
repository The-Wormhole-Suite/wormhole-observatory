from __future__ import annotations

from pihole_manager.config import ExternalTriggerOptions
from pihole_manager.network_access import (
    ReviewAccessOptions,
    client_access_allowed,
    load_review_access_options,
    save_review_access_options,
)


def test_network_modes_classify_lan_and_tailscale_ranges() -> None:
    assert client_access_allowed("127.0.0.1", "local")
    assert not client_access_allowed("192.168.1.20", "local")

    assert client_access_allowed("10.0.0.5", "lan")
    assert client_access_allowed("172.20.0.5", "lan")
    assert client_access_allowed("192.168.1.20", "lan")
    assert client_access_allowed("fd00::1234", "lan")
    assert not client_access_allowed("100.64.12.34", "lan")

    assert client_access_allowed("100.64.12.34", "tailscale")
    assert client_access_allowed("fd7a:115c:a1e0::1234", "tailscale")
    assert not client_access_allowed("192.168.1.20", "tailscale")

    assert client_access_allowed("192.168.1.20", "lan_tailscale")
    assert client_access_allowed("100.64.12.34", "lan_tailscale")
    assert client_access_allowed("203.0.113.20", "any")
    assert not client_access_allowed("not-an-ip", "any")


def test_access_mode_round_trip(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))

    saved = save_review_access_options(ReviewAccessOptions(mode="tailscale"))
    loaded = load_review_access_options()

    assert saved.mode == "tailscale"
    assert loaded.mode == "tailscale"


def test_legacy_remote_opt_in_defaults_to_any_network(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    trigger = ExternalTriggerOptions(allow_remote=True)

    assert load_review_access_options(trigger).mode == "any"


def test_legacy_local_configuration_stays_local(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    trigger = ExternalTriggerOptions(allow_remote=False)

    assert load_review_access_options(trigger).mode == "local"
