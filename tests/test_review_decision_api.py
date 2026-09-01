from __future__ import annotations

import http.client
import json

from pihole_manager.config import ExternalTriggerOptions
from pihole_manager.external_trigger import ExternalTriggerServer


def _request(server, path: str, *, token: str, payload: dict) -> tuple[int, dict]:
    address = server.address
    assert address is not None
    connection = http.client.HTTPConnection(address[0], address[1], timeout=3)
    connection.request(
        "POST",
        path,
        body=json.dumps(payload),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    response = connection.getresponse()
    data = json.loads(response.read().decode("utf-8"))
    connection.close()
    return response.status, data


def test_review_decision_endpoint_is_authenticated_and_normalized() -> None:
    calls: list[tuple[str, str, int | None]] = []

    def decide(domain: str, decision: str, *, postpone_until=None):
        calls.append((domain, decision, postpone_until))
        return {"domain": domain, "decision": decision}

    server = ExternalTriggerServer(
        ExternalTriggerOptions(enabled=True, port=0, token="secret-token"),
        decision_callback=decide,
    )
    server.start()
    try:
        status, payload = _request(
            server,
            "/v1/reviews/EXAMPLE.COM./decision",
            token="secret-token",
            payload={"decision": "postpone", "postpone_until": 2_000_000_000},
        )
        assert status == 200
        assert payload["result"] == {"domain": "example.com", "decision": "postpone"}
        assert calls == [("example.com", "postpone", 2_000_000_000)]
    finally:
        server.stop()


def test_review_decision_endpoint_maps_validation_errors() -> None:
    def decide(domain: str, decision: str, *, postpone_until=None):
        raise ValueError("bad decision")

    server = ExternalTriggerServer(
        ExternalTriggerOptions(enabled=True, port=0, token="secret-token"),
        decision_callback=decide,
    )
    server.start()
    try:
        status, payload = _request(
            server,
            "/v1/reviews/example.com/decision",
            token="secret-token",
            payload={"decision": "invalid"},
        )
        assert status == 400
        assert payload["error"] == "invalid_decision"
    finally:
        server.stop()
