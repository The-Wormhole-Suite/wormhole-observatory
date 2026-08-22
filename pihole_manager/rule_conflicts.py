from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from pihole_manager.database import list_domain_locks
from pihole_manager.pihole_rules import fetch_regex_domains
from pihole_manager.pihole_service import fetch_exact_domains, fetch_groups


@dataclass(frozen=True, slots=True)
class RuleConflict:
    severity: str
    kind: str
    subject: str
    details: str

    def as_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "kind": self.kind,
            "subject": self.subject,
            "details": self.details,
        }


def scan_rule_conflicts() -> list[RuleConflict]:
    exact = {
        "allow": fetch_exact_domains("allow"),
        "deny": fetch_exact_domains("deny"),
    }
    regex = {
        "allow": fetch_regex_domains("allow"),
        "deny": fetch_regex_domains("deny"),
    }
    return detect_rule_conflicts(
        exact_rules=exact,
        regex_rules=regex,
        groups=fetch_groups(),
        locks=list_domain_locks(),
    )


def detect_rule_conflicts(
    *,
    exact_rules: dict[str, list[dict[str, Any]]],
    regex_rules: dict[str, list[dict[str, Any]]],
    groups: list[dict[str, Any]],
    locks: list[dict[str, Any]],
) -> list[RuleConflict]:
    conflicts: list[RuleConflict] = []
    enabled_groups = {
        int(group["id"]): bool(group.get("enabled", True))
        for group in groups
        if _as_int(group.get("id")) is not None
    }

    exact_allow = _normalize_rule_rows(exact_rules.get("allow", []), "allow", "exact")
    exact_deny = _normalize_rule_rows(exact_rules.get("deny", []), "deny", "exact")
    regex_allow = _normalize_rule_rows(regex_rules.get("allow", []), "allow", "regex")
    regex_deny = _normalize_rule_rows(regex_rules.get("deny", []), "deny", "regex")
    all_rules = exact_allow + exact_deny + regex_allow + regex_deny

    conflicts.extend(_group_conflicts(all_rules, enabled_groups))
    conflicts.extend(_exact_policy_conflicts(exact_allow, exact_deny))
    conflicts.extend(_regex_policy_conflicts(regex_allow, regex_deny))
    conflicts.extend(_exact_regex_conflicts(exact_allow, regex_deny))
    conflicts.extend(_exact_regex_conflicts(exact_deny, regex_allow))
    conflicts.extend(_lock_conflicts(locks, exact_allow, exact_deny, regex_allow, regex_deny))

    unique: dict[tuple[str, str, str, str], RuleConflict] = {}
    for conflict in conflicts:
        key = (conflict.severity, conflict.kind, conflict.subject, conflict.details)
        unique[key] = conflict
    severity_rank = {"error": 0, "warning": 1, "info": 2}
    return sorted(
        unique.values(),
        key=lambda item: (
            severity_rank.get(item.severity, 9),
            item.kind,
            item.subject.casefold(),
            item.details.casefold(),
        ),
    )


def _normalize_rule_rows(
    rows: list[dict[str, Any]], policy: str, kind: str
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for row in rows:
        value = str(row.get("domain") or "").strip()
        if not value or not bool(row.get("enabled", True)):
            continue
        groups = {_as_int(group_id) for group_id in row.get("groups") or []}
        output.append(
            {
                "value": value,
                "policy": policy,
                "kind": kind,
                "groups": {group_id for group_id in groups if group_id is not None},
            }
        )
    return output


def _group_conflicts(
    rules: list[dict[str, Any]], enabled_groups: dict[int, bool]
) -> list[RuleConflict]:
    conflicts: list[RuleConflict] = []
    known_groups = set(enabled_groups)
    for rule in rules:
        groups = set(rule["groups"])
        missing = sorted(groups - known_groups)
        disabled = sorted(group_id for group_id in groups if enabled_groups.get(group_id) is False)
        label = _rule_label(rule)
        if missing:
            conflicts.append(
                RuleConflict(
                    "error",
                    "missing_group",
                    label,
                    f"References unknown Pi-hole group IDs: {', '.join(map(str, missing))}.",
                )
            )
        if groups and groups.issubset(set(disabled)):
            conflicts.append(
                RuleConflict(
                    "warning",
                    "disabled_groups_only",
                    label,
                    "The rule is assigned only to disabled Pi-hole groups.",
                )
            )
    return conflicts


def _exact_policy_conflicts(
    allow_rules: list[dict[str, Any]], deny_rules: list[dict[str, Any]]
) -> list[RuleConflict]:
    conflicts: list[RuleConflict] = []
    for allow in allow_rules:
        for deny in deny_rules:
            if allow["value"].casefold() != deny["value"].casefold():
                continue
            if not _groups_overlap(allow["groups"], deny["groups"]):
                continue
            conflicts.append(
                RuleConflict(
                    "error",
                    "exact_policy_overlap",
                    allow["value"],
                    "Active exact allow and deny rules overlap in at least one Pi-hole group.",
                )
            )
    return conflicts


def _regex_policy_conflicts(
    allow_rules: list[dict[str, Any]], deny_rules: list[dict[str, Any]]
) -> list[RuleConflict]:
    conflicts: list[RuleConflict] = []
    compiled: dict[str, re.Pattern[str] | None] = {}
    for rule in allow_rules + deny_rules:
        pattern = rule["value"]
        if pattern not in compiled:
            try:
                compiled[pattern] = re.compile(pattern)
            except re.error as exc:
                compiled[pattern] = None
                conflicts.append(
                    RuleConflict(
                        "error",
                        "invalid_regex",
                        pattern,
                        f"Regex cannot be compiled: {exc}.",
                    )
                )
    for allow in allow_rules:
        for deny in deny_rules:
            if allow["value"] != deny["value"]:
                continue
            if not _groups_overlap(allow["groups"], deny["groups"]):
                continue
            conflicts.append(
                RuleConflict(
                    "error",
                    "regex_policy_overlap",
                    allow["value"],
                    (
                        "Identical active allow and deny regex rules overlap in at least "
                        "one Pi-hole group."
                    ),
                )
            )
    return conflicts


def _exact_regex_conflicts(
    exact_rules: list[dict[str, Any]], opposite_regex_rules: list[dict[str, Any]]
) -> list[RuleConflict]:
    conflicts: list[RuleConflict] = []
    compiled: dict[str, re.Pattern[str] | None] = {}
    for regex_rule in opposite_regex_rules:
        pattern = regex_rule["value"]
        if pattern not in compiled:
            try:
                compiled[pattern] = re.compile(pattern)
            except re.error:
                compiled[pattern] = None
        expression = compiled[pattern]
        if expression is None:
            continue
        for exact in exact_rules:
            if not _groups_overlap(exact["groups"], regex_rule["groups"]):
                continue
            if expression.search(exact["value"]) is None:
                continue
            conflicts.append(
                RuleConflict(
                    "warning",
                    "exact_regex_overlap",
                    exact["value"],
                    (
                        f"Exact {exact['policy']} rule matches opposite "
                        f"{regex_rule['policy']} regex {pattern!r} in an overlapping group."
                    ),
                )
            )
    return conflicts


def _lock_conflicts(
    locks: list[dict[str, Any]],
    exact_allow: list[dict[str, Any]],
    exact_deny: list[dict[str, Any]],
    regex_allow: list[dict[str, Any]],
    regex_deny: list[dict[str, Any]],
) -> list[RuleConflict]:
    conflicts: list[RuleConflict] = []
    exact_by_policy = {"allow": exact_allow, "deny": exact_deny}
    regex_by_policy = {"allow": regex_allow, "deny": regex_deny}
    for lock in locks:
        domain = str(lock.get("domain") or "").strip().lower()
        desired = str(lock.get("list_type") or "").strip().lower()
        if not domain or desired not in {"allow", "deny"}:
            continue
        opposite = "deny" if desired == "allow" else "allow"
        for rule in exact_by_policy[opposite]:
            if rule["value"].casefold() == domain.casefold():
                conflicts.append(
                    RuleConflict(
                        "error",
                        "lock_exact_conflict",
                        domain,
                        f"Local {desired} lock conflicts with active exact {opposite} rule.",
                    )
                )
        for rule in regex_by_policy[opposite]:
            try:
                matches = re.search(rule["value"], domain) is not None
            except re.error:
                matches = False
            if matches:
                conflicts.append(
                    RuleConflict(
                        "error",
                        "lock_regex_conflict",
                        domain,
                        (
                            f"Local {desired} lock is matched by active {opposite} regex "
                            f"{rule['value']!r}."
                        ),
                    )
                )
    return conflicts


def _groups_overlap(first: set[int], second: set[int]) -> bool:
    if not first or not second:
        return True
    return bool(first & second)


def _rule_label(rule: dict[str, Any]) -> str:
    return f"{rule['kind']} {rule['policy']}: {rule['value']}"


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
