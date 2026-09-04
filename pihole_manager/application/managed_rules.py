from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

VALID_MANAGED_RULE_KINDS = frozenset({"regex_domain", "subscribed_list"})
VALID_MANAGED_RULE_OPERATIONS = frozenset({"add", "update", "delete"})
_VALID_RULE_TYPES = {
    "regex_domain": frozenset({"allow", "deny"}),
    "subscribed_list": frozenset({"allow", "block"}),
}


class InvalidManagedRule(ValueError):
    """The managed-rule command is not valid application input."""


class ManagedRuleConflict(RuntimeError):
    """A valid managed-rule command could not be applied to Pi-hole state."""


@dataclass(frozen=True, slots=True)
class ManagedRuleQuery:
    kind: str
    rule_type: str


@dataclass(frozen=True, slots=True)
class ManagedRuleMutationCommand:
    operation: str
    kind: str
    value: str
    rule_type: str
    comment: str = ""
    groups: tuple[int, ...] | None = None
    enabled: bool = True


@dataclass(frozen=True, slots=True)
class ManagedRuleMutationResult:
    kind: str
    operation: str
    value: str
    rule_type: str
    applied: bool
    provider_result: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "operation": self.operation,
            "value": self.value,
            "rule_type": self.rule_type,
            "applied": self.applied,
        }


@dataclass(frozen=True, slots=True)
class ManagedRulePorts:
    fetch_regex_domains: Callable[[str], list[dict[str, Any]]]
    add_regex_domain: Callable[..., Any]
    update_regex_domain: Callable[..., Any]
    delete_regex_domain: Callable[[str, str], Any]
    fetch_subscribed_lists: Callable[[str], list[dict[str, Any]]]
    add_subscribed_list: Callable[..., Any]
    update_subscribed_list: Callable[..., Any]
    delete_subscribed_list: Callable[[str, str], Any]


class ManagedRuleApplicationService:
    """Canonical application boundary for regex-rule and subscribed-list management."""

    def __init__(self, ports: ManagedRulePorts) -> None:
        self._ports = ports

    def fetch(self, query: ManagedRuleQuery) -> list[dict[str, Any]]:
        kind = self._validate_kind(query.kind)
        rule_type = self._validate_rule_type(kind, query.rule_type)
        try:
            if kind == "regex_domain":
                return self._ports.fetch_regex_domains(rule_type)
            return self._ports.fetch_subscribed_lists(rule_type)
        except RuntimeError as exc:
            raise ManagedRuleConflict(str(exc)) from exc

    def execute(self, command: ManagedRuleMutationCommand) -> ManagedRuleMutationResult:
        operation = str(command.operation or "").strip().lower()
        if operation not in VALID_MANAGED_RULE_OPERATIONS:
            raise InvalidManagedRule("operation must be add, update, or delete")
        kind = self._validate_kind(command.kind)
        rule_type = self._validate_rule_type(kind, command.rule_type)
        value = str(command.value or "")
        if operation == "add":
            value = value.strip()
            if not value:
                label = "regex domain" if kind == "regex_domain" else "list address"
                raise InvalidManagedRule(f"{label} must not be empty")

        groups = None if command.groups is None else list(command.groups)
        try:
            if kind == "regex_domain":
                provider_result = self._mutate_regex(
                    operation,
                    value,
                    rule_type,
                    comment=command.comment,
                    groups=groups,
                    enabled=command.enabled,
                )
            else:
                provider_result = self._mutate_subscription(
                    operation,
                    value,
                    rule_type,
                    comment=command.comment,
                    groups=groups,
                    enabled=command.enabled,
                )
        except RuntimeError as exc:
            raise ManagedRuleConflict(str(exc)) from exc

        return ManagedRuleMutationResult(
            kind=kind,
            operation=operation,
            value=value,
            rule_type=rule_type,
            applied=True,
            provider_result=provider_result,
        )

    def _validate_kind(self, raw_kind: str) -> str:
        kind = str(raw_kind or "").strip().lower()
        if kind not in VALID_MANAGED_RULE_KINDS:
            raise InvalidManagedRule("kind must be regex_domain or subscribed_list")
        return kind

    def _validate_rule_type(self, kind: str, raw_rule_type: str) -> str:
        rule_type = str(raw_rule_type or "").strip().lower()
        if rule_type not in _VALID_RULE_TYPES[kind]:
            allowed = " or ".join(sorted(_VALID_RULE_TYPES[kind]))
            raise InvalidManagedRule(f"rule_type for {kind} must be {allowed}")
        return rule_type

    def _mutate_regex(
        self,
        operation: str,
        value: str,
        rule_type: str,
        *,
        comment: str,
        groups: list[int] | None,
        enabled: bool,
    ) -> Any:
        if operation == "add":
            return self._ports.add_regex_domain(
                value,
                rule_type,
                comment=comment,
                groups=groups,
                enabled=enabled,
            )
        if operation == "update":
            return self._ports.update_regex_domain(
                value,
                rule_type,
                comment=comment,
                groups=groups,
                enabled=enabled,
            )
        return self._ports.delete_regex_domain(value, rule_type)

    def _mutate_subscription(
        self,
        operation: str,
        value: str,
        rule_type: str,
        *,
        comment: str,
        groups: list[int] | None,
        enabled: bool,
    ) -> Any:
        if operation == "add":
            return self._ports.add_subscribed_list(
                value,
                rule_type,
                comment=comment,
                groups=groups,
                enabled=enabled,
            )
        if operation == "update":
            return self._ports.update_subscribed_list(
                value,
                rule_type,
                comment=comment,
                groups=groups,
                enabled=enabled,
            )
        return self._ports.delete_subscribed_list(value, rule_type)
