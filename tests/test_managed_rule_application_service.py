from __future__ import annotations

import pytest

from pihole_manager.application.managed_rules import (
    InvalidManagedRule,
    ManagedRuleApplicationService,
    ManagedRuleConflict,
    ManagedRuleMutationCommand,
    ManagedRulePorts,
    ManagedRuleQuery,
)


def _service(*, fail_add: bool = False):
    events: list[tuple] = []

    def fetch_regex(rule_type: str):
        events.append(("fetch_regex", rule_type))
        return [{"domain": "regex.example", "type": rule_type}]

    def fetch_lists(rule_type: str):
        events.append(("fetch_list", rule_type))
        return [{"address": "https://list.example", "type": rule_type}]

    def add_regex(value, rule_type, **kwargs):
        if fail_add:
            raise RuntimeError("Pi-hole offline")
        events.append(("add_regex", value, rule_type, kwargs))
        return {"ok": True}

    def update_regex(value, rule_type, **kwargs):
        events.append(("update_regex", value, rule_type, kwargs))
        return {"ok": True}

    def delete_regex(value, rule_type):
        events.append(("delete_regex", value, rule_type))
        return {"ok": True}

    def add_list(value, rule_type, **kwargs):
        events.append(("add_list", value, rule_type, kwargs))
        return {"ok": True}

    def update_list(value, rule_type, **kwargs):
        events.append(("update_list", value, rule_type, kwargs))
        return {"ok": True}

    def delete_list(value, rule_type):
        events.append(("delete_list", value, rule_type))
        return {"ok": True}

    service = ManagedRuleApplicationService(
        ManagedRulePorts(
            fetch_regex_domains=fetch_regex,
            add_regex_domain=add_regex,
            update_regex_domain=update_regex,
            delete_regex_domain=delete_regex,
            fetch_subscribed_lists=fetch_lists,
            add_subscribed_list=add_list,
            update_subscribed_list=update_list,
            delete_subscribed_list=delete_list,
        )
    )
    return service, events


def test_managed_rule_service_dispatches_queries_by_kind() -> None:
    service, events = _service()

    regex = service.fetch(ManagedRuleQuery("regex_domain", "deny"))
    subscribed = service.fetch(ManagedRuleQuery("subscribed_list", "block"))

    assert regex == [{"domain": "regex.example", "type": "deny"}]
    assert subscribed == [{"address": "https://list.example", "type": "block"}]
    assert events == [("fetch_regex", "deny"), ("fetch_list", "block")]


def test_managed_rule_service_normalizes_add_and_returns_canonical_result() -> None:
    service, events = _service()

    result = service.execute(
        ManagedRuleMutationCommand(
            operation="ADD",
            kind="regex_domain",
            value="  ^ads\\.example$  ",
            rule_type="DENY",
            comment="tracker",
            groups=(3, 1),
            enabled=False,
        )
    )

    assert result.to_dict() == {
        "kind": "regex_domain",
        "operation": "add",
        "value": r"^ads\.example$",
        "rule_type": "deny",
        "applied": True,
    }
    assert result.provider_result == {"ok": True}
    assert events == [
        (
            "add_regex",
            r"^ads\.example$",
            "deny",
            {"comment": "tracker", "groups": [3, 1], "enabled": False},
        )
    ]


def test_managed_rule_service_rejects_cross_kind_types_before_infrastructure() -> None:
    service, events = _service()

    with pytest.raises(InvalidManagedRule, match="rule_type"):
        service.fetch(ManagedRuleQuery("regex_domain", "block"))
    with pytest.raises(InvalidManagedRule, match="rule_type"):
        service.execute(
            ManagedRuleMutationCommand(
                operation="add",
                kind="subscribed_list",
                value="https://example.invalid/list.txt",
                rule_type="deny",
            )
        )

    assert events == []


def test_managed_rule_service_maps_runtime_failures_to_stable_conflict() -> None:
    service, events = _service(fail_add=True)

    with pytest.raises(ManagedRuleConflict, match="Pi-hole offline"):
        service.execute(
            ManagedRuleMutationCommand(
                operation="add",
                kind="regex_domain",
                value="^ads$",
                rule_type="deny",
            )
        )

    assert events == []
