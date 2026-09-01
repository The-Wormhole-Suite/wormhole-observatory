from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping, MutableMapping
from pathlib import Path
from typing import Any

_RUNTIME_UID = 10_001
_RUNTIME_GID = 10_001
_HOME_ASSISTANT_OPTIONS_PATH = Path("/data/options.json")
_DATA_ROOT = Path("/data")
_OPTION_ENV_MAP = {
    "api_token": "WORMHOLE_API_TOKEN",
    "access_mode": "WORMHOLE_ACCESS_MODE",
    "max_domains": "WORMHOLE_MAX_DOMAINS",
}


def load_home_assistant_options(
    path: Path = _HOME_ASSISTANT_OPTIONS_PATH,
) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read Home Assistant options from {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"Home Assistant options in {path} must be a JSON object")
    return payload


def apply_home_assistant_options(
    options: Mapping[str, Any],
    environ: MutableMapping[str, str] | None = None,
) -> None:
    target = os.environ if environ is None else environ
    for option_name, env_name in _OPTION_ENV_MAP.items():
        if env_name in target or option_name not in options:
            continue
        value = options[option_name]
        if value is None:
            continue
        target[env_name] = str(value)


def _safe_application_home() -> Path:
    configured = Path(os.environ.get("PIHOLE_MANAGER_HOME", "/data/wormhole"))
    home = Path(os.path.abspath(configured))
    if not home.is_relative_to(_DATA_ROOT):
        raise RuntimeError("Container PIHOLE_MANAGER_HOME must stay below /data")
    return home


def _chown_tree(path: Path, uid: int, gid: int) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.lchown(path, uid, gid)
    for root, directories, files in os.walk(path, followlinks=False):
        root_path = Path(root)
        for name in directories:
            os.lchown(root_path / name, uid, gid)
        for name in files:
            os.lchown(root_path / name, uid, gid)


def prepare_runtime() -> None:
    if os.geteuid() != 0:
        return

    apply_home_assistant_options(load_home_assistant_options())
    _chown_tree(_safe_application_home(), _RUNTIME_UID, _RUNTIME_GID)
    os.setgroups([])
    os.setgid(_RUNTIME_GID)
    os.setuid(_RUNTIME_UID)


def main() -> int:
    prepare_runtime()
    os.execv(
        sys.executable,
        [sys.executable, "-m", "pihole_manager.headless", *sys.argv[1:]],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
