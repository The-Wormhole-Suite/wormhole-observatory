from __future__ import annotations

from pihole_manager.rule_conflicts import detect_rule_conflicts


def test_detects_exact_allow_deny_only_when_groups_overlap() -> None:
    conflicts = detect_rule_conflicts(
        exact_rules={
            "allow": [{"domain": "example.com", "enabled": True, "groups": [1]}],
            "deny": [
                {"domain": "example.com", "enabled": True, "groups": [2]},
                {"domain": "example.com", "enabled": True, "groups": [1, 3]},
            ],
        },
        regex_rules={"allow": [], "deny": []},
        groups=[{"id": 1, "enabled": True}, {"id": 2, "enabled": True}, {"id": 3, "enabled": True}],
        locks=[],
    )

    exact = [item for item in conflicts if item.kind == "exact_policy_overlap"]
    assert len(exact) == 1
    assert exact[0].subject == "example.com"


def test_detects_exact_regex_and_lock_conflicts() -> None:
    conflicts = detect_rule_conflicts(
        exact_rules={
            "allow": [{"domain": "tracker.example.com", "enabled": True, "groups": [0]}],
            "deny": [],
        },
        regex_rules={
            "allow": [],
            "deny": [{"domain": r"(^|\.)example\.com$", "enabled": True, "groups": [0]}],
        },
        groups=[{"id": 0, "enabled": True}],
        locks=[{"domain": "tracker.example.com", "list_type": "allow"}],
    )

    kinds = {item.kind for item in conflicts}
    assert "exact_regex_overlap" in kinds
    assert "lock_regex_conflict" in kinds


def test_detects_missing_disabled_groups_and_invalid_regex() -> None:
    conflicts = detect_rule_conflicts(
        exact_rules={
            "allow": [{"domain": "a.example", "enabled": True, "groups": [7]}],
            "deny": [{"domain": "b.example", "enabled": True, "groups": [8]}],
        },
        regex_rules={
            "allow": [{"domain": "[", "enabled": True, "groups": [8]}],
            "deny": [],
        },
        groups=[{"id": 7, "enabled": False}, {"id": 8, "enabled": True}],
        locks=[],
    )

    kinds = {item.kind for item in conflicts}
    assert "disabled_groups_only" in kinds
    assert "invalid_regex" in kinds

    missing = detect_rule_conflicts(
        exact_rules={
            "allow": [{"domain": "a.example", "enabled": True, "groups": [99]}],
            "deny": [],
        },
        regex_rules={"allow": [], "deny": []},
        groups=[{"id": 0, "enabled": True}],
        locks=[],
    )
    assert any(item.kind == "missing_group" for item in missing)


def test_disabled_rules_do_not_create_policy_conflicts() -> None:
    conflicts = detect_rule_conflicts(
        exact_rules={
            "allow": [{"domain": "example.com", "enabled": False, "groups": [0]}],
            "deny": [{"domain": "example.com", "enabled": True, "groups": [0]}],
        },
        regex_rules={"allow": [], "deny": []},
        groups=[{"id": 0, "enabled": True}],
        locks=[],
    )
    assert not any(item.kind == "exact_policy_overlap" for item in conflicts)
