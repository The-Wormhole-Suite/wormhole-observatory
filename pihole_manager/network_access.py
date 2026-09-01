from __future__ import annotations

import ipaddress
import json
import os
import tempfile
import threading
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import Path

from pihole_manager.config import ExternalTriggerOptions, app_directory
from pihole_manager.external_trigger import ExternalTriggerServer

ACCESS_MODES = {"local", "lan", "tailscale", "lan_tailscale", "any"}
_LAN_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)
_TAILSCALE_NETWORKS = (
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fd7a:115c:a1e0::/48"),
)


@dataclass(slots=True)
class ReviewAccessOptions:
    mode: str = "local"


def review_access_path() -> Path:
    return app_directory() / "review_access.json"


def normalize_access_mode(value: object, *, legacy_remote: bool = False) -> str:
    mode = str(value or "").strip().lower()
    if mode in ACCESS_MODES:
        return mode
    return "any" if legacy_remote else "local"


def load_review_access_options(
    trigger_options: ExternalTriggerOptions | None = None,
) -> ReviewAccessOptions:
    legacy_remote = bool(trigger_options and trigger_options.allow_remote)
    path = review_access_path()
    if not path.exists():
        return ReviewAccessOptions(mode="any" if legacy_remote else "local")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ReviewAccessOptions(mode="any" if legacy_remote else "local")
    if not isinstance(raw, dict):
        return ReviewAccessOptions(mode="any" if legacy_remote else "local")
    return ReviewAccessOptions(
        mode=normalize_access_mode(raw.get("mode"), legacy_remote=legacy_remote)
    )


def save_review_access_options(options: ReviewAccessOptions) -> ReviewAccessOptions:
    normalized = ReviewAccessOptions(mode=normalize_access_mode(options.mode))
    path = review_access_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"version": 1, "mode": normalized.mode}, indent=2) + "\n"
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, delete=False
        ) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            temp_path = Path(handle.name)
        os.replace(temp_path, path)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
    return normalized


def client_access_allowed(address: str, mode: str) -> bool:
    try:
        ip = ipaddress.ip_address(str(address).split("%", 1)[0])
    except ValueError:
        return False
    normalized_mode = normalize_access_mode(mode)
    if ip.is_loopback:
        return True
    if normalized_mode == "any":
        return True
    if normalized_mode in {"lan", "lan_tailscale"} and any(
        ip in network for network in _LAN_NETWORKS
    ):
        return True
    return normalized_mode in {"tailscale", "lan_tailscale"} and any(
        ip in network for network in _TAILSCALE_NETWORKS
    )


class ScopedExternalTriggerServer(ExternalTriggerServer):
    def start(self) -> None:
        access = load_review_access_options(self.options)
        original_allow_remote = self.options.allow_remote
        self.options.allow_remote = access.mode != "local"
        try:
            super().start()
        finally:
            self.options.allow_remote = original_allow_remote

    def _handler_factory(self, token: str):
        base_handler = super()._handler_factory(token)
        access_mode = load_review_access_options(self.options).mode

        class Handler(base_handler):
            def _network_allowed(self) -> bool:
                return client_access_allowed(str(self.client_address[0]), access_mode)

            def do_GET(self) -> None:  # noqa: N802
                if not self._network_allowed():
                    self._send_json(
                        HTTPStatus.FORBIDDEN,
                        {"error": "client_network_not_allowed"},
                    )
                    return
                super().do_GET()

            def do_POST(self) -> None:  # noqa: N802
                if not self._network_allowed():
                    self._send_json(
                        HTTPStatus.FORBIDDEN,
                        {"error": "client_network_not_allowed"},
                    )
                    return
                super().do_POST()

        return Handler


_SERVER_LOCK = threading.RLock()
_SERVER: ScopedExternalTriggerServer | None = None


def configure_external_trigger(
    options: ExternalTriggerOptions,
) -> ScopedExternalTriggerServer | None:
    global _SERVER
    with _SERVER_LOCK:
        if _SERVER is not None:
            _SERVER.stop()
            _SERVER = None
        if not options.enabled:
            return None
        server = ScopedExternalTriggerServer(options)
        server.start()
        _SERVER = server
        return server


def stop_external_trigger() -> None:
    global _SERVER
    with _SERVER_LOCK:
        if _SERVER is not None:
            _SERVER.stop()
            _SERVER = None
