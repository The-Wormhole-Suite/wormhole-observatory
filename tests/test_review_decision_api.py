from __future__ import annotations

import http.client
import json

from pihole_manager.application.review_decisions import (
    ReviewDecisionApplicationService,
    ReviewDecisionCommand,
    ReviewDecisionPorts,
)
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


def _recording_service():
    events: list[tuple] = []
    rules = {"allow": set(), "deny": set()}

    def fetch(policy: str):
        return [{"domain": domain} for domain in sorted(rules[policy])]

    def add(domain, policy, *, comment=""):
        rules[policy.value].add(domain)
        events.append(("add", domain, policy.value, comment))

    def delete(domain: str, policy: str):
        rules[policy].discard(domain)
        events.append(("delete", domain, policy))

    def mark(domain: str, action: str):
        events.append(("mark", domain, action))

    def staging(domains: list[str]):
        events.append(("staging", tuple(domains)))

    def resolve_review(domains: list[str], *, decision: str):
        events.append(("review", tuple(domains), decision))

    def preference(domain: str, **kwargs):
        events.append(("preference", domain, tuple(sorted(kwargs.items()))))
        return {"domain": domain, **kwargs}

    def resolve_tasks(domain: str, decision: str):
        events.append(("tasks", domain, decision))

    return (
        ReviewDecisionApplicationService(
            ReviewDecisionPorts(
                fetch_exact_domains=fetch,
                add_exact_domain=add,
                delete_exact_domain=delete,
                mark_action_applied=mark,
                staging_remove=staging,
                resolve_review=resolve_review,
                set_review_preference=preference,
                resolve_open_review_tasks=resolve_tasks,
                clock=lambda: 1_700_000_000,
            )
        ),
        events,
    )


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


def test_http_and_direct_service_paths_have_equivalent_canonical_effects() -> None:
    direct_service, direct_events = _recording_service()
    direct_result = direct_service.execute(ReviewDecisionCommand("PARITY.EXAMPLE.", "allow"))

    http_service, http_events = _recording_service()

    def decide(domain: str, decision: str, *, postpone_until=None):
        return http_service.execute(
            ReviewDecisionCommand(
                domain=domain,
                decision=decision,
                postpone_until=postpone_until,
            )
        ).to_dict()

    server = ExternalTriggerServer(
        ExternalTriggerOptions(enabled=True, port=0, token="secret-token"),
        decision_callback=decide,
    )
    server.start()
    try:
        status, payload = _request(
            server,
            "/v1/reviews/PARITY.EXAMPLE./decision",
            token="secret-token",
            payload={"decision": "allow"},
        )
    finally:
        server.stop()

    assert status == 200
    assert payload["result"] == direct_result.to_dict()
    assert http_events == direct_events
