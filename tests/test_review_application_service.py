from __future__ import annotations

import pytest

from pihole_manager.application.review_decisions import (
    InvalidReviewDecision,
    ReviewDecisionApplicationService,
    ReviewDecisionCommand,
    ReviewDecisionConflict,
    ReviewDecisionPorts,
)


def _service():
    state: dict[str, object] = {
        "rules": {"allow": set(), "deny": set()},
        "events": [],
        "preferences": {},
    }
    rules = state["rules"]
    events = state["events"]
    preferences = state["preferences"]
    assert isinstance(rules, dict)
    assert isinstance(events, list)
    assert isinstance(preferences, dict)

    def fetch(policy: str):
        values = rules[policy]
        return [{"domain": domain} for domain in sorted(values)]

    def add(domain, policy, *, comment=""):
        rules[policy.value].add(domain)
        events.append(("add", domain, policy.value, comment))

    def delete(domain: str, policy: str):
        rules[policy].discard(domain)
        events.append(("delete", domain, policy))

    def mark(domain: str, action: str):
        events.append(("mark", domain, action))

    def staging(domains: list[str]):
        events.append(("staging_remove", tuple(domains)))

    def resolve_review(domains: list[str], *, decision: str):
        events.append(("review_resolve", tuple(domains), decision))

    def set_preference(domain: str, **kwargs):
        value = {"domain": domain, **kwargs}
        preferences[domain] = value
        events.append(("preference", domain, tuple(sorted(kwargs.items()))))
        return value

    def resolve_tasks(domain: str, decision: str):
        events.append(("resolve_tasks", domain, decision))

    ports = ReviewDecisionPorts(
        fetch_exact_domains=fetch,
        add_exact_domain=add,
        delete_exact_domain=delete,
        mark_action_applied=mark,
        staging_remove=staging,
        resolve_review=resolve_review,
        set_review_preference=set_preference,
        resolve_open_review_tasks=resolve_tasks,
        clock=lambda: 1_700_000_000,
    )
    return ReviewDecisionApplicationService(ports), state


def test_application_service_normalizes_and_returns_typed_result() -> None:
    service, state = _service()

    result = service.execute(
        ReviewDecisionCommand(
            domain="Example.COM.",
            decision="ALLOW",
            comment="manual review",
        )
    )

    assert result.domain == "example.com"
    assert result.decision == "allow"
    assert result.applied is True
    assert result.to_dict()["preference"]["last_decision"] == "allow"
    assert state["events"] == [
        ("add", "example.com", "allow", "manual review"),
        ("mark", "example.com", "allow"),
        ("staging_remove", ("example.com",)),
        ("preference", "example.com", (("last_decision", "allow"),)),
    ]


def test_application_service_preserves_distinct_ignore_and_postpone_semantics() -> None:
    ignore_service, ignore_state = _service()
    ignore_service.execute(ReviewDecisionCommand("ignore.example", "ignore"))
    assert ("review_resolve", ("ignore.example",), "ignored") in ignore_state["events"]
    assert not any(event[0] == "resolve_tasks" for event in ignore_state["events"])

    postpone_service, postpone_state = _service()
    result = postpone_service.execute(
        ReviewDecisionCommand(
            "postpone.example",
            "postpone",
            postpone_until=1_700_003_600,
        )
    )
    assert result.postpone_until == 1_700_003_600
    assert ("resolve_tasks", "postpone.example", "postponed") in postpone_state["events"]
    assert not any(event[0] == "review_resolve" for event in postpone_state["events"])


def test_application_service_exposes_stable_validation_and_conflict_errors() -> None:
    service, _state = _service()
    with pytest.raises(InvalidReviewDecision, match="decision must be"):
        service.execute(ReviewDecisionCommand("example.com", "invalid"))
    with pytest.raises(InvalidReviewDecision, match="future"):
        service.execute(
            ReviewDecisionCommand(
                "example.com",
                "postpone",
                postpone_until=1_700_000_000,
            )
        )

    failing_service, _ = _service()
    original = failing_service._ports
    failing_service = ReviewDecisionApplicationService(
        ReviewDecisionPorts(
            fetch_exact_domains=original.fetch_exact_domains,
            add_exact_domain=lambda *args, **kwargs: (_ for _ in ()).throw(
                RuntimeError("Pi-hole offline")
            ),
            delete_exact_domain=original.delete_exact_domain,
            mark_action_applied=original.mark_action_applied,
            staging_remove=original.staging_remove,
            resolve_review=original.resolve_review,
            set_review_preference=original.set_review_preference,
            resolve_open_review_tasks=original.resolve_open_review_tasks,
            clock=original.clock,
        )
    )
    with pytest.raises(ReviewDecisionConflict, match="Pi-hole offline"):
        failing_service.execute(ReviewDecisionCommand("example.com", "allow"))
