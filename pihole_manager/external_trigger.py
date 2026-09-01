from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import threading
from collections.abc import Callable
from dataclasses import asdict, is_dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from pihole_manager.config import ExternalTriggerOptions, load_options
from pihole_manager.database import queue_domains_for_review, queue_due_rechecks, review_queue_get
from pihole_manager.manual_tag_overrides import domain_browser_search
from pihole_manager.review_decisions import apply_review_decision
from pihole_manager.webapp import WebAsset, get_web_asset
from pihole_manager.workers import cancel_classifier_jobs

log = logging.getLogger(__name__)

QueueCallback = Callable[..., Any]
CancelCallback = Callable[..., int]
RecheckCallback = Callable[..., int]
ReviewQueueCallback = Callable[..., list[dict[str, Any]]]
ReviewLookupCallback = Callable[[str], dict[str, Any] | None]
DecisionCallback = Callable[..., dict[str, Any]]
_MAX_BODY_BYTES = 64 * 1024
_API_VERSION = 1

_REVIEW_API_FIELDS = (
    "domain",
    "tags",
    "categories",
    "policy",
    "short",
    "details",
    "provider",
    "status",
    "service",
    "service_role",
    "privacy_risk",
    "security_risk",
    "breakage_risk",
    "confidence",
    "needs_review",
    "review_reason",
    "planned_action",
    "action_status",
    "locked",
    "queue_source",
    "queue_state",
    "queue_error",
    "queue_priority",
    "queue_created_at",
    "updated_at",
)


def _serialize_review(row: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for field in _REVIEW_API_FIELDS:
        if field in row:
            payload[field] = row[field]
    if "tags" not in payload and "categories" in payload:
        categories = payload.get("categories")
        payload["tags"] = list(categories) if isinstance(categories, list | tuple) else []
    payload.pop("categories", None)
    return payload


def _lookup_review(domain: str) -> dict[str, Any] | None:
    rows, _total = domain_browser_search(search=domain, limit=25, offset=0)
    normalized = domain.strip().lower().rstrip(".")
    return next(
        (row for row in rows if str(row.get("domain") or "").lower().rstrip(".") == normalized),
        None,
    )


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


class ExternalTriggerServer:
    def __init__(
        self,
        options: ExternalTriggerOptions,
        *,
        queue_callback: QueueCallback = queue_domains_for_review,
        cancel_callback: CancelCallback = cancel_classifier_jobs,
        recheck_callback: RecheckCallback = queue_due_rechecks,
        review_queue_callback: ReviewQueueCallback = review_queue_get,
        review_lookup_callback: ReviewLookupCallback = _lookup_review,
        decision_callback: DecisionCallback = apply_review_decision,
    ) -> None:
        self.options = options
        self._queue_callback = queue_callback
        self._cancel_callback = cancel_callback
        self._recheck_callback = recheck_callback
        self._review_queue_callback = review_queue_callback
        self._review_lookup_callback = review_lookup_callback
        self._decision_callback = decision_callback
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return self._server is not None and self._thread is not None and self._thread.is_alive()

    @property
    def address(self) -> tuple[str, int] | None:
        if self._server is None:
            return None
        host, port = self._server.server_address[:2]
        return str(host), int(port)

    def start(self) -> None:
        if self.running:
            return
        if not self.options.enabled:
            return
        token = self.options.token.strip()
        if not token:
            raise ValueError("External trigger requires an authentication token")
        host = self.options.bind_host.strip() or "127.0.0.1"
        if not _is_loopback_host(host) and not self.options.allow_remote:
            raise ValueError(
                "External trigger may bind to a non-loopback address only when "
                "remote access is explicitly enabled"
            )

        handler = self._handler_factory(token)
        self._server = ThreadingHTTPServer((host, int(self.options.port)), handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="ExternalReviewTrigger",
            daemon=True,
        )
        self._thread.start()
        actual = self.address
        log.info("External review trigger listening on %s:%s", *(actual or (host, 0)))

    def stop(self) -> None:
        server = self._server
        thread = self._thread
        self._server = None
        self._thread = None
        if server is None:
            return
        server.shutdown()
        server.server_close()
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=2)

    def _handler_factory(self, token: str):
        queue_callback = self._queue_callback
        cancel_callback = self._cancel_callback
        recheck_callback = self._recheck_callback
        review_queue_callback = self._review_queue_callback
        review_lookup_callback = self._review_lookup_callback
        decision_callback = self._decision_callback
        max_domains = max(1, int(self.options.max_domains_per_request))

        class Handler(BaseHTTPRequestHandler):
            server_version = "WormholeObservatoryAPI/1"

            def setup(self) -> None:
                super().setup()
                self.connection.settimeout(10)

            def log_message(self, format: str, *args: Any) -> None:
                log.debug("External trigger: " + format, *args)

            def _authorized(self) -> bool:
                expected = f"Bearer {token}"
                supplied = self.headers.get("Authorization", "")
                return hmac.compare_digest(supplied, expected)

            def _send_json(self, status: int, payload: dict[str, Any]) -> None:
                body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)

            def _send_web_asset(self, asset: WebAsset) -> None:
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", asset.content_type)
                self.send_header("Content-Length", str(len(asset.content)))
                self.send_header("Cache-Control", asset.cache_control)
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'self'; connect-src 'self'; img-src 'self'; "
                    "manifest-src 'self'; script-src 'self'; style-src 'self'; worker-src 'self'",
                )
                self.end_headers()
                self.wfile.write(asset.content)

            def _redirect(self, location: str) -> None:
                self.send_response(HTTPStatus.TEMPORARY_REDIRECT)
                self.send_header("Location", location)
                self.send_header("Cache-Control", "no-store")
                self.end_headers()

            def _require_auth(self) -> bool:
                if self._authorized():
                    return True
                self._send_json(
                    HTTPStatus.UNAUTHORIZED,
                    {"error": "unauthorized"},
                )
                return False

            def _read_json(self) -> dict[str, Any] | None:
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    length = 0
                if length <= 0 or length > _MAX_BODY_BYTES:
                    self._send_json(
                        HTTPStatus.BAD_REQUEST,
                        {"error": "invalid_request_body"},
                    )
                    return None
                try:
                    payload = json.loads(self.rfile.read(length).decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
                    return None
                if not isinstance(payload, dict):
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
                    return None
                return payload

            def do_GET(self) -> None:  # noqa: N802
                parsed = urlsplit(self.path)
                path = parsed.path
                if path in {"/", "/app"}:
                    self._redirect("/app/")
                    return
                asset = get_web_asset(path)
                if asset is not None:
                    self._send_web_asset(asset)
                    return

                if not self._require_auth():
                    return
                if path == "/health":
                    self._send_json(HTTPStatus.OK, {"status": "ok"})
                    return

                if path == "/v1/status":
                    self._send_json(
                        HTTPStatus.OK,
                        {
                            "status": "ok",
                            "api_version": _API_VERSION,
                            "service": "wormhole-observatory",
                            "capabilities": [
                                "review_queue",
                                "review_lookup",
                                "queue_review",
                                "queue_rechecks",
                                "cancel_jobs",
                                "review_pwa",
                                "review_decisions",
                            ],
                        },
                    )
                    return

                if path == "/v1/reviews":
                    query = parse_qs(parsed.query)
                    try:
                        requested = int(query.get("limit", ["200"])[0])
                    except ValueError:
                        requested = 200
                    limit = min(max_domains, max(1, requested))
                    rows = review_queue_callback(limit=limit)
                    items = [_serialize_review(row) for row in rows[:limit]]
                    self._send_json(
                        HTTPStatus.OK,
                        {"items": items, "count": len(items), "limit": limit},
                    )
                    return

                prefix = "/v1/reviews/"
                if path.startswith(prefix):
                    domain = unquote(path[len(prefix) :]).strip().lower().rstrip(".")
                    if not domain or "/" in domain:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_domain"})
                        return
                    row = review_lookup_callback(domain)
                    if row is None:
                        self._send_json(HTTPStatus.NOT_FOUND, {"error": "review_not_found"})
                        return
                    self._send_json(HTTPStatus.OK, {"item": _serialize_review(row)})
                    return

                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

            def do_POST(self) -> None:  # noqa: N802
                if not self._require_auth():
                    return
                parsed = urlsplit(self.path)
                path = parsed.path
                decision_prefix = "/v1/reviews/"
                decision_suffix = "/decision"
                if path.startswith(decision_prefix) and path.endswith(decision_suffix):
                    encoded_domain = path[len(decision_prefix) : -len(decision_suffix)]
                    domain = unquote(encoded_domain).strip().lower().rstrip(".")
                    if not domain or "/" in domain:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_domain"})
                        return
                    payload = self._read_json()
                    if payload is None:
                        return
                    decision = str(payload.get("decision") or "").strip().lower()
                    raw_postpone = payload.get("postpone_until")
                    postpone_until: int | None = None
                    if raw_postpone is not None:
                        try:
                            postpone_until = int(raw_postpone)
                        except (TypeError, ValueError):
                            self._send_json(
                                HTTPStatus.BAD_REQUEST,
                                {"error": "invalid_postpone_until"},
                            )
                            return
                    try:
                        result = decision_callback(
                            domain,
                            decision,
                            postpone_until=postpone_until,
                        )
                    except ValueError as exc:
                        self._send_json(
                            HTTPStatus.BAD_REQUEST,
                            {"error": "invalid_decision", "message": str(exc)},
                        )
                        return
                    except RuntimeError as exc:
                        self._send_json(
                            HTTPStatus.CONFLICT,
                            {"error": "decision_conflict", "message": str(exc)},
                        )
                        return
                    self._send_json(HTTPStatus.OK, {"result": result})
                    return

                if path == "/v1/review":
                    payload = self._read_json()
                    if payload is None:
                        return
                    raw_domains = payload.get("domains")
                    if not isinstance(raw_domains, list):
                        self._send_json(
                            HTTPStatus.BAD_REQUEST,
                            {"error": "domains_must_be_a_list"},
                        )
                        return
                    domains: list[str] = []
                    seen: set[str] = set()
                    for value in raw_domains:
                        if not isinstance(value, str):
                            continue
                        domain = value.strip().lower().rstrip(".")
                        if not domain or domain in seen:
                            continue
                        seen.add(domain)
                        domains.append(domain)
                    if not domains:
                        self._send_json(
                            HTTPStatus.BAD_REQUEST,
                            {"error": "no_valid_domains"},
                        )
                        return
                    if len(domains) > max_domains:
                        self._send_json(
                            HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                            {"error": "too_many_domains", "limit": max_domains},
                        )
                        return
                    result = queue_callback(domains, source="manual_external_trigger")
                    if is_dataclass(result) and not isinstance(result, type):
                        queued = asdict(result)
                    elif isinstance(result, dict):
                        queued = result
                    else:
                        queued = {"accepted": int(result)}
                    self._send_json(
                        HTTPStatus.ACCEPTED,
                        {"status": "queued", "domains": domains, "result": queued},
                    )
                    return

                if path == "/v1/recheck-due":
                    query = parse_qs(parsed.query)
                    try:
                        requested = int(query.get("limit", [str(max_domains)])[0])
                    except ValueError:
                        requested = max_domains
                    limit = min(max_domains, max(1, requested))
                    queued = int(recheck_callback(limit=limit))
                    self._send_json(
                        HTTPStatus.ACCEPTED,
                        {"status": "queued", "queued": queued, "limit": limit},
                    )
                    return

                if path == "/v1/cancel":
                    cancelled = int(cancel_callback())
                    self._send_json(
                        HTTPStatus.OK,
                        {"status": "cancelled", "jobs": cancelled},
                    )
                    return

                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

        return Handler


_SERVER_LOCK = threading.RLock()
_SERVER: ExternalTriggerServer | None = None


def configure_external_trigger(
    options: ExternalTriggerOptions | None = None,
) -> ExternalTriggerServer | None:
    global _SERVER
    settings = options or load_options().external_trigger
    with _SERVER_LOCK:
        if _SERVER is not None:
            _SERVER.stop()
            _SERVER = None
        if not settings.enabled:
            return None
        server = ExternalTriggerServer(settings)
        server.start()
        _SERVER = server
        return server


def stop_external_trigger() -> None:
    global _SERVER
    with _SERVER_LOCK:
        if _SERVER is not None:
            _SERVER.stop()
            _SERVER = None
