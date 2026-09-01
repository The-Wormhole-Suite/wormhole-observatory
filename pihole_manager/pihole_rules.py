from __future__ import annotations

from typing import Any

from pihole_manager.pihole_audit import capture_pihole_snapshot, record_pihole_change
from pihole_manager.pihole_service import extract_collection, get_client


def fetch_regex_domains(domain_type: str) -> list[dict[str, Any]]:
    if domain_type not in {"allow", "deny"}:
        raise ValueError("domain_type must be 'allow' or 'deny'")
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


def add_regex_domain(
    domain: str,
    domain_type: str,
    *,
    comment: str = "",
    groups: list[int] | None = None,
    enabled: bool = True,
) -> Any:
    if domain_type not in {"allow", "deny"}:
        raise ValueError("domain_type must be 'allow' or 'deny'")
    value = domain.strip()
    if not value:
        raise ValueError("regex domain must not be empty")
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


def update_regex_domain(
    domain: str,
    domain_type: str,
    *,
    comment: str = "",
    groups: list[int] | None = None,
    enabled: bool = True,
) -> Any:
    if domain_type not in {"allow", "deny"}:
        raise ValueError("domain_type must be 'allow' or 'deny'")
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


def delete_regex_domain(domain: str, domain_type: str) -> Any:
    if domain_type not in {"allow", "deny"}:
        raise ValueError("domain_type must be 'allow' or 'deny'")
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


def fetch_subscribed_lists(list_type: str) -> list[dict[str, Any]]:
    if list_type not in {"allow", "block"}:
        raise ValueError("list_type must be 'allow' or 'block'")
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


def add_subscribed_list(
    address: str,
    list_type: str,
    *,
    comment: str = "",
    groups: list[int] | None = None,
    enabled: bool = True,
) -> Any:
    if list_type not in {"allow", "block"}:
        raise ValueError("list_type must be 'allow' or 'block'")
    value = address.strip()
    if not value:
        raise ValueError("list address must not be empty")
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


def update_subscribed_list(
    address: str,
    list_type: str,
    *,
    comment: str = "",
    groups: list[int] | None = None,
    enabled: bool = True,
) -> Any:
    if list_type not in {"allow", "block"}:
        raise ValueError("list_type must be 'allow' or 'block'")
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


def delete_subscribed_list(address: str, list_type: str) -> Any:
    if list_type not in {"allow", "block"}:
        raise ValueError("list_type must be 'allow' or 'block'")
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


def _normalize_groups(groups: Any) -> list[int]:
    output: set[int] = set()
    for value in groups or []:
        try:
            output.add(int(value))
        except (TypeError, ValueError):
            continue
    return sorted(output)
