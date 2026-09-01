from __future__ import annotations

import tomllib
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[1]
_APP_DIR = _ROOT / "wormhole_observatory"


def _yaml(path: Path) -> dict[str, object]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_home_assistant_repository_metadata() -> None:
    repository = _yaml(_ROOT / "repository.yaml")
    assert repository["name"] == "Wormhole Observatory Apps"
    assert repository["url"] == "https://github.com/The-Wormhole-Suite/wormhole-observatory"


def test_home_assistant_app_uses_matching_prebuilt_multiarch_image() -> None:
    config = _yaml(_APP_DIR / "config.yaml")
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert config["version"] == project["project"]["version"]
    assert config["image"] == "ghcr.io/the-wormhole-suite/wormhole-observatory"
    assert set(config["arch"]) == {"amd64", "aarch64"}
    assert config["legacy"] is True
    assert not (_APP_DIR / "Dockerfile").exists()


def test_home_assistant_app_keeps_security_boundaries() -> None:
    config = _yaml(_APP_DIR / "config.yaml")
    assert config["ingress"] is False
    assert config["backup"] == "cold"
    assert config["webui"] == "http://[HOST]:[PORT:8765]/app/"
    assert config["watchdog"] == "tcp://[HOST]:[PORT:8765]"
    assert config["ports"] == {"8765/tcp": 8765}
    assert "host_network" not in config
    assert "privileged" not in config
    assert "docker_api" not in config


def test_home_assistant_app_options_match_headless_runtime() -> None:
    config = _yaml(_APP_DIR / "config.yaml")
    assert config["options"] == {
        "api_token": None,
        "access_mode": "lan_tailscale",
        "max_domains": 500,
    }
    assert config["schema"] == {
        "api_token": "password",
        "access_mode": "list(local|lan|tailscale|lan_tailscale|any)",
        "max_domains": "int(1,10000)",
    }

    for language in ("en", "de"):
        translations = _yaml(_APP_DIR / "translations" / f"{language}.yaml")
        assert set(translations["configuration"]) == set(config["schema"])
