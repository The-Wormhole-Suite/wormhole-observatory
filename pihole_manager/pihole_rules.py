from __future__ import annotations

from typing import Any

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
    return get_client().domain_management.add_domain(
        value,
        domain_type,
        "regex",
        comment=comment or None,
        groups=_normalize_groups(groups),
        enabled=bool(enabled),
    )


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
    return get_client().domain_management.update_domain(
        domain,
        domain_type,
        "regex",
        comment=comment or None,
        groups=_normalize_groups(groups),
        enabled=bool(enabled),
    )


def delete_regex_domain(domain: str, domain_type: str) -> Any:
    if domain_type not in {"allow", "deny"}:
        raise ValueError("domain_type must be 'allow' or 'deny'")
    return get_client().domain_management.delete_domain(domain, domain_type, "regex")


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
    return get_client().list_management.add_list(
        value,
        list_type,
        comment=comment or None,
        groups=_normalize_groups(groups),
        enabled=bool(enabled),
    )


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
    return get_client().list_management.update_list(
        address,
        list_type,
        comment=comment or None,
        groups=_normalize_groups(groups),
        enabled=bool(enabled),
    )


def delete_subscribed_list(address: str, list_type: str) -> Any:
    if list_type not in {"allow", "block"}:
        raise ValueError("list_type must be 'allow' or 'block'")
    return get_client().list_management.delete_list(address, list_type)


def _normalize_groups(groups: Any) -> list[int]:
    output: set[int] = set()
    for value in groups or []:
        try:
            output.add(int(value))
        except (TypeError, ValueError):
            continue
    return sorted(output)
