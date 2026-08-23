from __future__ import annotations

import argparse
import logging
import os
import signal
import threading
from collections.abc import Mapping, Sequence
from dataclasses import replace

from pihole_manager.config import ExternalTriggerOptions, load_options
from pihole_manager.database import init_db
from pihole_manager.list_audit_worker import get_list_auditor, stop_list_auditor
from pihole_manager.logging_setup import setup_logging
from pihole_manager.network_access import (
    ACCESS_MODES,
    ReviewAccessOptions,
    configure_external_trigger,
    save_review_access_options,
    stop_external_trigger,
)
from pihole_manager.pihole_service import close_client
from pihole_manager.workers import get_classifier, get_scanner, stop_workers

log = logging.getLogger(__name__)
_DEFAULT_BIND_HOST = "0.0.0.0"
_DEFAULT_PORT = 8765
_DEFAULT_ACCESS_MODE = "lan_tailscale"


def _bounded_int(
    values: Mapping[str, str],
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    raw = str(values.get(name, default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def build_headless_trigger_options(
    base: ExternalTriggerOptions,
    env: Mapping[str, str] | None = None,
) -> tuple[ExternalTriggerOptions, ReviewAccessOptions]:
    values = os.environ if env is None else env
    token_override = values.get("WORMHOLE_API_TOKEN")
    token = str(base.token if token_override is None else token_override).strip()
    if not token:
        raise RuntimeError(
            "Headless mode requires WORMHOLE_API_TOKEN or an existing external trigger token"
        )

    bind_host = str(values.get("WORMHOLE_BIND_HOST", _DEFAULT_BIND_HOST)).strip()
    if not bind_host:
        bind_host = _DEFAULT_BIND_HOST
    port = _bounded_int(
        values,
        "WORMHOLE_PORT",
        _DEFAULT_PORT,
        minimum=1,
        maximum=65_535,
    )
    max_domains = _bounded_int(
        values,
        "WORMHOLE_MAX_DOMAINS",
        max(1, int(base.max_domains_per_request)),
        minimum=1,
        maximum=10_000,
    )
    access_mode = str(values.get("WORMHOLE_ACCESS_MODE", _DEFAULT_ACCESS_MODE)).strip().lower()
    if access_mode not in ACCESS_MODES:
        supported = ", ".join(sorted(ACCESS_MODES))
        raise ValueError(f"WORMHOLE_ACCESS_MODE must be one of: {supported}")

    trigger = replace(
        base,
        enabled=True,
        bind_host=bind_host,
        port=port,
        token=token,
        allow_remote=access_mode != "local",
        max_domains_per_request=max_domains,
    )
    return trigger, ReviewAccessOptions(mode=access_mode)


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Wormhole Observatory headless Web/API service"
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Validate container/headless settings and exit without starting the service",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    setup_logging()
    init_db()
    options = load_options()
    trigger, access = build_headless_trigger_options(options.external_trigger)
    save_review_access_options(access)

    if args.check_config:
        log.info(
            "Headless configuration valid for %s:%s (%s access)",
            trigger.bind_host,
            trigger.port,
            access.mode,
        )
        return 0

    stop_event = threading.Event()

    def request_stop(_signum: int, _frame: object) -> None:
        stop_event.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    server = configure_external_trigger(trigger)
    if server is None:
        raise RuntimeError("Headless review server did not start")
    get_scanner()
    get_list_auditor()
    get_classifier()

    address = server.address or (trigger.bind_host, trigger.port)
    log.info(
        "Wormhole Observatory headless service listening on %s:%s with %s access",
        address[0],
        address[1],
        access.mode,
    )
    try:
        stop_event.wait()
    finally:
        stop_external_trigger()
        stop_list_auditor()
        stop_workers()
        close_client()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
