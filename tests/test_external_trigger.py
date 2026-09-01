from __future__ import annotations

import http.client
import json

import pytest

from pihole_manager.config import ExternalTriggerOptions
from pihole_manager.external_trigger import ExternalTriggerServer


def _request(
    server: ExternalTriggerServer,
    method: str,
    path: str,
    *,
    token: str = "",
    payload: dict | None = None,
) -> tuple[int, dict]:
    address = server.address
    assert address is not None
    host, port = address
    connection = http.client.HTTPConnection(host, port, timeout=3)
    headers = {}
    body = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload)
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    data = json.loads(response.read().decode("utf-8"))
    connection.close()
    return response.status, data


def test_trigger_requires_bearer_authentication() -> None:
    server = ExternalTriggerServer(
        ExternalTriggerOptions(enabled=True, port=0, token="secret-token")
    )
    server.start()
    try:
        status, payload = _request(server, "GET", "/health")
        assert status == 401
        assert payload["error"] == "unauthorized"

        status, payload = _request(
            server,
            "GET",
            "/health",
            token="secret-token",
        )
        assert status == 200
        assert payload == {"status": "ok"}
    finally:
        server.stop()


def test_status_endpoint_exposes_versioned_capabilities() -> None:
    server = ExternalTriggerServer(
        ExternalTriggerOptions(enabled=True, port=0, token="secret-token")
    )
    server.start()
    try:
        status, payload = _request(server, "GET", "/v1/status", token="secret-token")
        assert status == 200
        assert payload["api_version"] == 1
        assert payload["service"] == "wormhole-observatory"
        assert "review_queue" in payload["capabilities"]
        assert "review_lookup" in payload["capabilities"]
    finally:
        server.stop()


def test_review_queue_endpoint_is_bounded_and_serialized() -> None:
    calls: list[int] = []

    def queue_rows(*, limit):
        calls.append(limit)
        return [
            {
                "domain": "tracker.example",
                "categories": ["tracking"],
                "policy": "deny",
                "short": "Tracker",
                "needs_review": True,
                "queue_state": "queued",
                "internal_only": "must-not-leak",
            }
        ]

    server = ExternalTriggerServer(
        ExternalTriggerOptions(
            enabled=True,
            port=0,
            token="secret-token",
            max_domains_per_request=50,
        ),
        review_queue_callback=queue_rows,
    )
    server.start()
    try:
        status, payload = _request(
            server,
            "GET",
            "/v1/reviews?limit=500",
            token="secret-token",
        )
        assert status == 200
        assert calls == [50]
        assert payload["limit"] == 50
        assert payload["count"] == 1
        assert payload["items"][0]["domain"] == "tracker.example"
        assert payload["items"][0]["tags"] == ["tracking"]
        assert "categories" not in payload["items"][0]
        assert "internal_only" not in payload["items"][0]
    finally:
        server.stop()


def test_review_lookup_endpoint_normalizes_domain_and_handles_missing() -> None:
    calls: list[str] = []

    def lookup(domain: str):
        calls.append(domain)
        if domain == "api.example":
            return {"domain": domain, "tags": ["service"], "needs_review": True}
        return None

    server = ExternalTriggerServer(
        ExternalTriggerOptions(enabled=True, port=0, token="secret-token"),
        review_lookup_callback=lookup,
    )
    server.start()
    try:
        status, payload = _request(
            server,
            "GET",
            "/v1/reviews/API.EXAMPLE.",
            token="secret-token",
        )
        assert status == 200
        assert payload["item"]["domain"] == "api.example"
        assert calls == ["api.example"]

        status, payload = _request(
            server,
            "GET",
            "/v1/reviews/missing.example",
            token="secret-token",
        )
        assert status == 404
        assert payload["error"] == "review_not_found"
    finally:
        server.stop()


def test_review_endpoint_queues_normalized_domains() -> None:
    calls: list[tuple[list[str], str]] = []

    def queue(domains, *, source):
        calls.append((list(domains), source))
        return {"accepted": len(domains)}

    server = ExternalTriggerServer(
        ExternalTriggerOptions(enabled=True, port=0, token="secret-token"),
        queue_callback=queue,
    )
    server.start()
    try:
        status, payload = _request(
            server,
            "POST",
            "/v1/review",
            token="secret-token",
            payload={"domains": ["Example.COM.", "example.com", "api.example.org"]},
        )
        assert status == 202
        assert calls == [(["example.com", "api.example.org"], "manual_external_trigger")]
        assert payload["result"]["accepted"] == 2
    finally:
        server.stop()


def test_scheduled_recheck_endpoint_queues_due_domains() -> None:
    calls: list[int] = []

    def recheck(*, limit):
        calls.append(limit)
        return 7

    server = ExternalTriggerServer(
        ExternalTriggerOptions(
            enabled=True,
            port=0,
            token="secret-token",
            max_domains_per_request=100,
        ),
        recheck_callback=recheck,
    )
    server.start()
    try:
        status, payload = _request(
            server,
            "POST",
            "/v1/recheck-due?limit=25",
            token="secret-token",
            payload={},
        )
        assert status == 202
        assert calls == [25]
        assert payload["queued"] == 7
    finally:
        server.stop()


def test_cancel_endpoint_delegates_to_classifier_jobs() -> None:
    server = ExternalTriggerServer(
        ExternalTriggerOptions(enabled=True, port=0, token="secret-token"),
        cancel_callback=lambda: 2,
    )
    server.start()
    try:
        status, payload = _request(
            server,
            "POST",
            "/v1/cancel",
            token="secret-token",
            payload={},
        )
        assert status == 200
        assert payload == {"status": "cancelled", "jobs": 2}
    finally:
        server.stop()


def test_remote_bind_requires_explicit_opt_in() -> None:
    server = ExternalTriggerServer(
        ExternalTriggerOptions(
            enabled=True,
            bind_host="0.0.0.0",
            port=0,
            token="secret-token",
            allow_remote=False,
        )
    )
    with pytest.raises(ValueError, match="non-loopback"):
        server.start()


def test_enabled_trigger_requires_token() -> None:
    server = ExternalTriggerServer(ExternalTriggerOptions(enabled=True, port=0, token=""))
    with pytest.raises(ValueError, match="authentication token"):
        server.start()
