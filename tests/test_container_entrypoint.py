from __future__ import annotations

import json
from pathlib import Path

import pytest

from pihole_manager.container_entrypoint import (
    _safe_application_home,
    apply_home_assistant_options,
    load_home_assistant_options,
)


def test_home_assistant_options_map_to_runtime_environment() -> None:
    target: dict[str, str] = {}
    apply_home_assistant_options(
        {
            "api_token": "ha-token",
            "access_mode": "tailscale",
            "max_domains": 25,
            "ignored": "value",
        },
        target,
    )

    assert target == {
        "WORMHOLE_API_TOKEN": "ha-token",
        "WORMHOLE_ACCESS_MODE": "tailscale",
        "WORMHOLE_MAX_DOMAINS": "25",
    }


def test_explicit_environment_overrides_home_assistant_options() -> None:
    target = {
        "WORMHOLE_API_TOKEN": "environment-token",
        "WORMHOLE_ACCESS_MODE": "lan",
    }
    apply_home_assistant_options(
        {
            "api_token": "ha-token",
            "access_mode": "any",
            "max_domains": 42,
        },
        target,
    )

    assert target["WORMHOLE_API_TOKEN"] == "environment-token"
    assert target["WORMHOLE_ACCESS_MODE"] == "lan"
    assert target["WORMHOLE_MAX_DOMAINS"] == "42"


def test_load_home_assistant_options(tmp_path: Path) -> None:
    path = tmp_path / "options.json"
    path.write_text(json.dumps({"api_token": "secret"}), encoding="utf-8")

    assert load_home_assistant_options(path) == {"api_token": "secret"}
    assert load_home_assistant_options(tmp_path / "missing.json") == {}


def test_load_home_assistant_options_rejects_invalid_payload(tmp_path: Path) -> None:
    path = tmp_path / "options.json"
    path.write_text("[]", encoding="utf-8")

    with pytest.raises(RuntimeError, match="must be a JSON object"):
        load_home_assistant_options(path)


def test_container_home_must_stay_below_data(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", "/tmp/wormhole")
    with pytest.raises(RuntimeError, match="must stay below /data"):
        _safe_application_home()
