from __future__ import annotations

from typing import Any

from pihole_manager.application.managed_rules import (
    InvalidManagedRule,
    ManagedRuleApplicationService,
    ManagedRuleConflict,
    ManagedRuleMutationCommand,
    ManagedRuleMutationResult,
    ManagedRulePorts,
    ManagedRuleQuery,
)
from pihole_manager.pihole_audit import capture_pihole_snapshot, record_pihole_change
from pihole_manager.pihole_service import extract_collection, get_client


def _fetch_regex_domains_impl(domain_type: str) -> list[dict[str, Any]]:
    payload = get_client().domain_management.get_domains(domain_type, "regex")
    rows = extract_collection(payload, "domains", domain_type, "data")
    output: list[dict[str, Any]] = []
    for row in rows:
        domain = row.get("domain") or row.get("item")
        if not domain:
            continue
        output.append(
            {
                "domain": str(domain),
                "type": domain_type,
                "comment": str(row.get("comment") or ""),
                "enabled": bool(row.get("enabled", True)),
                "groups": _normalize_groups(row.get("groups")),
            }
        )
    return output


def _add_regex_domain_impl(
    domain: str,
    domain_type: str,
    *,
    comment: str = "",
    groups: list[int] | None = None,
    enabled: bool = True,
) -> Any:
    value = domain.strip()
    normalized_groups = _normalize_groups(groups)
    result = get_client().domain_management.add_domain(
        value,
        domain_type,
        "regex",
        comment=comment or None,
        groups=normalized_groups,
        enabled=bool(enabled),
    )
    record_pihole_change(
        "add",
        "regex_domain",
        domain_type,
        value,
        after={
            "domain": value,
            "type": domain_type,
            "comment": comment,
            "groups": normalized_groups,
            "enabled": bool(enabled),
        },
    )
    return result


def _update_regex_domain_impl(
    domain: str,
    domain_type: str,
    *,
    comment: str = "",
    groups: list[int] | None = None,
    enabled: bool = True,
) -> Any:
    normalized_groups = _normalize_groups(groups)
    before = capture_pihole_snapshot("regex_domain", domain_type, domain)
    result = get_client().domain_management.update_domain(
        domain,
        domain_type,
        "regex",
        comment=comment or None,
        groups=normalized_groups,
        enabled=bool(enabled),
    )
    record_pihole_change(
        "update",
        "regex_domain",
        domain_type,
        domain,
        before=before,
        after={
            "domain": domain,
            "type": domain_type,
            "comment": comment,
            "groups": normalized_groups,
            "enabled": bool(enabled),
        },
    )
    return result


def _delete_regex_domain_impl(domain: str, domain_type: str) -> Any:
    before = capture_pihole_snapshot("regex_domain", domain_type, domain)
    result = get_client().domain_management.delete_domain(domain, domain_type, "regex")
    record_pihole_change(
        "delete",
        "regex_domain",
        domain_type,
        domain,
        before=before,
    )
    return result


def _fetch_subscribed_lists_impl(list_type: str) -> list[dict[str, Any]]:
    payload = get_client().list_management.get_lists(list_type)
    rows = extract_collection(payload, "lists", "data")
    output: list[dict[str, Any]] = []
    for row in rows:
        address = row.get("address") or row.get("url") or row.get("item")
        if not address:
            continue
        output.append(
            {
                "address": str(address),
                "type": str(row.get("type") or list_type),
                "comment": str(row.get("comment") or ""),
                "enabled": bool(row.get("enabled", True)),
                "groups": _normalize_groups(row.get("groups")),
            }
        )
    return output


def _add_subscribed_list_impl(
    address: str,
    list_type: str,
    *,
    comment: str = "",
    groups: list[int] | None = None,
    enabled: bool = True,
) -> Any:
    value = address.strip()
    normalized_groups = _normalize_groups(groups)
    result = get_client().list_management.add_list(
        value,
        list_type,
        comment=comment or None,
        groups=normalized_groups,
        enabled=bool(enabled),
    )
    record_pihole_change(
        "add",
        "subscribed_list",
        list_type,
        value,
        after={
            "address": value,
            "type": list_type,
            "comment": comment,
            "groups": normalized_groups,
            "enabled": bool(enabled),
        },
    )
    return result


def _update_subscribed_list_impl(
    address: str,
    list_type: str,
    *,
    comment: str = "",
    groups: list[int] | None = None,
    enabled: bool = True,
) -> Any:
    normalized_groups = _normalize_groups(groups)
    before = capture_pihole_snapshot("subscribed_list", list_type, address)
    result = get_client().list_management.update_list(
        address,
        list_type,
        comment=comment or None,
        groups=normalized_groups,
        enabled=bool(enabled),
    )
    record_pihole_change(
        "update",
        "subscribed_list",
        list_type,
        address,
        before=before,
        after={
            "address": address,
            "type": list_type,
            "comment": comment,
            "groups": normalized_groups,
            "enabled": bool(enabled),
        },
    )
    return result


def _delete_subscribed_list_impl(address: str, list_type: str) -> Any:
    before = capture_pihole_snapshot("subscribed_list", list_type, address)
    result = get_client().list_management.delete_list(address, list_type)
    record_pihole_change(
        "delete",
        "subscribed_list",
        list_type,
        address,
        before=before,
    )
    return result


def _application_service() -> ManagedRuleApplicationService:
    return ManagedRuleApplicationService(
        ManagedRulePorts(
            fetch_regex_domains=_fetch_regex_domains_impl,
            add_regex_domain=_add_regex_domain_impl,
            update_regex_domain=_update_regex_domain_impl,
            delete_regex_domain=_delete_regex_domain_impl,
            fetch_subscribed_lists=_fetch_subscribed_lists_impl,
            add_subscribed_list=_add_subscribed_list_impl,
            update_subscribed_list=_update_subscribed_list_impl,
            delete_subscribed_list=_delete_subscribed_list_impl,
        )
    )


def fetch_managed_rules(query: ManagedRuleQuery) -> list[dict[str, Any]]:
    return _application_service().fetch(query)


def execute_managed_rule_mutation(
    command: ManagedRuleMutationCommand,
) -> ManagedRuleMutationResult:
    return _application_service().execute(command)


def fetch_regex_domains(domain_type: str) -> list[dict[str, Any]]:
    return fetch_managed_rules(ManagedRuleQuery("regex_domain", domain_type))


def add_regex_domain(
    domain: str,
    domain_type: str,
    *,
    comment: str = "",
    groups: list[int] | None = None,
    enabled: bool = True,
) -> Any:
    return execute_managed_rule_mutation(
        ManagedRuleMutationCommand(
            operation="add",
            kind="regex_domain",
            value=domain,
            rule_type=domain_type,
            comment=comment,
            groups=None if groups is None else tuple(groups),
            enabled=enabled,
        )
    ).provider_result


def update_regex_domain(
    domain: str,
    domain_type: str,
    *,
    comment: str = "",
    groups: list[int] | None = None,
    enabled: bool = True,
) -> Any:
    return execute_managed_rule_mutation(
        ManagedRuleMutationCommand(
            operation="update",
            kind="regex_domain",
            value=domain,
            rule_type=domain_type,
            comment=comment,
            groups=None if groups is None else tuple(groups),
            enabled=enabled,
        )
    ).provider_result


def delete_regex_domain(domain: str, domain_type: str) -> Any:
    return execute_managed_rule_mutation(
        ManagedRuleMutationCommand(
            operation="delete",
            kind="regex_domain",
            value=domain,
            rule_type=domain_type,
        )
    ).provider_result


def fetch_subscribed_lists(list_type: str) -> list[dict[str, Any]]:
    return fetch_managed_rules(ManagedRuleQuery("subscribed_list", list_type))


def add_subscribed_list(
    address: str,
    list_type: str,
    *,
    comment: str = "",
    groups: list[int] | None = None,
    enabled: bool = True,
) -> Any:
    return execute_managed_rule_mutation(
        ManagedRuleMutationCommand(
            operation="add",
            kind="subscribed_list",
            value=address,
            rule_type=list_type,
            comment=comment,
            groups=None if groups is None else tuple(groups),
            enabled=enabled,
        )
    ).provider_result


def update_subscribed_list(
    address: str,
    list_type: str,
    *,
    comment: str = "",
    groups: list[int] | None = None,
    enabled: bool = True,
) -> Any:
    return execute_managed_rule_mutation(
        ManagedRuleMutationCommand(
            operation="update",
            kind="subscribed_list",
            value=address,
            rule_type=list_type,
            comment=comment,
            groups=None if groups is None else tuple(groups),
            enabled=enabled,
        )
    ).provider_result


def delete_subscribed_list(address: str, list_type: str) -> Any:
    return execute_managed_rule_mutation(
        ManagedRuleMutationCommand(
            operation="delete",
            kind="subscribed_list",
            value=address,
            rule_type=list_type,
        )
    ).provider_result


def _normalize_groups(groups: Any) -> list[int]:
    output: set[int] = set()
    for value in groups or []:
        try:
            output.add(int(value))
        except (TypeError, ValueError):
            continue
    return sorted(output)


__all__ = [
    "InvalidManagedRule",
    "ManagedRuleConflict",
    "ManagedRuleMutationCommand",
    "ManagedRuleMutationResult",
    "ManagedRuleQuery",
    "add_regex_domain",
    "add_subscribed_list",
    "delete_regex_domain",
    "delete_subscribed_list",
    "execute_managed_rule_mutation",
    "fetch_managed_rules",
    "fetch_regex_domains",
    "fetch_subscribed_lists",
    "update_regex_domain",
    "update_subscribed_list",
]
