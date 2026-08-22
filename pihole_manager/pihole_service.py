from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any

from pihole6api import (
    ConnectionHealth,
    ConnectionState,
    PiHole6Client,
    normalize_api_url,
)
from pihole_manager.compatibility_profiles import compatibility_match_for_domain
from pihole_manager.config import PiHoleOptions, load_options
from pihole_manager.database import get_domain_lock
from pihole_manager.pihole_audit import capture_pihole_snapshot, record_pihole_change
from pihole_manager.models import ConnectionTestResult, Policy


@dataclass(frozen=True, slots=True)
class QueryPage:
    rows: list[dict[str, Any]]
    cursor: str = ""
    total: int | None = None


_CLIENT_LOCK = threading.RLock()
_CLIENT: PiHole6Client | None = None
_CLIENT_SIGNATURE: tuple[Any, ...] | None = None


def _signature(options: PiHoleOptions) -> tuple[Any, ...]:
    return (
        options.base_url.strip(),
        options.password,
        bool(options.verify_tls),
        float(options.timeout_sec),
    )


def configure_client(options: PiHoleOptions | None = None) -> PiHole6Client:
    global _CLIENT, _CLIENT_SIGNATURE
    settings = options or load_options().pihole
    signature = _signature(settings)
    with _CLIENT_LOCK:
        if _CLIENT is not None and signature == _CLIENT_SIGNATURE:
            return _CLIENT
        if _CLIENT is not None:
            _CLIENT.close()
        _CLIENT = PiHole6Client(
            base_url=settings.base_url,
            password=settings.password,
            verify_tls=settings.verify_tls,
            timeout=settings.timeout_sec,
        )
        _CLIENT_SIGNATURE = signature
        return _CLIENT


def get_client() -> PiHole6Client:
    return configure_client()


def close_client() -> None:
    global _CLIENT, _CLIENT_SIGNATURE
    with _CLIENT_LOCK:
        if _CLIENT is not None:
            _CLIENT.close()
        _CLIENT = None
        _CLIENT_SIGNATURE = None


def get_connection_health() -> ConnectionHealth:
    with _CLIENT_LOCK:
        if _CLIENT is None:
            return ConnectionHealth()
        return _CLIENT.connection.health


def test_connection(options: PiHoleOptions | None = None) -> ConnectionTestResult:
    settings = options or load_options().pihole
    started = time.perf_counter()
    request_url = settings.base_url.strip()
    client: PiHole6Client | None = None
    try:
        request_url = f"{normalize_api_url(settings.base_url)}info/version"
        client = configure_client(settings)
        payload = client.ftl_info.get_version()
        if not isinstance(payload, dict):
            elapsed_ms = round((time.perf_counter() - started) * 1000)
            return ConnectionTestResult(
                False,
                request_url,
                elapsed_ms,
                "Pi-hole returned an incompatible API response.",
                state=ConnectionState.API_ERROR,
            )
        elapsed_ms = round((time.perf_counter() - started) * 1000)
        version = _extract_version(payload)
        summary = "Pi-hole v6 API responded successfully"
        if version:
            summary = f"Pi-hole API responded successfully ({version})"
        return ConnectionTestResult(
            True,
            request_url,
            elapsed_ms,
            summary,
            version,
            str(client.connection.health.state),
        )
    except ValueError as exc:
        elapsed_ms = round((time.perf_counter() - started) * 1000)
        return ConnectionTestResult(
            False,
            request_url,
            elapsed_ms,
            f"Pi-hole configuration is invalid: {exc}",
            state=ConnectionState.INVALID_CONFIG,
        )
    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - started) * 1000)
        health = client.connection.health if client is not None else ConnectionHealth()
        if health.state is ConnectionState.AUTH_ERROR:
            summary = f"Pi-hole is reachable, but authentication failed: {exc}"
        elif health.state is ConnectionState.DEGRADED:
            summary = f"Pi-hole is reachable, but the API is temporarily unavailable: {exc}"
        elif health.state is ConnectionState.OFFLINE:
            summary = f"Pi-hole is offline or unreachable: {exc}"
        elif health.state is ConnectionState.TLS_ERROR:
            summary = f"Pi-hole TLS verification failed: {exc}"
        elif health.state is ConnectionState.API_ERROR:
            summary = f"Pi-hole returned an API error: {exc}"
        elif health.state is ConnectionState.INVALID_CONFIG:
            summary = f"Pi-hole configuration is invalid: {exc}"
        else:
            summary = str(exc)
        return ConnectionTestResult(
            False,
            request_url,
            elapsed_ms,
            summary,
            state=str(health.state),
        )


def _extract_version(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    version = payload.get("version")
    if isinstance(version, str):
        return version
    if not isinstance(version, dict):
        return ""

    for key in ("ftl", "core", "web"):
        item = version.get(key)
        if isinstance(item, dict):
            local = item.get("local")
            if isinstance(local, dict):
                value = local.get("version")
                if value:
                    return str(value)
            value = item.get("version")
            if value:
                return str(value)
        elif item:
            return str(item)
    return ""


def extract_collection(payload: Any, *keys: str) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def fetch_query_page(
    length: int = 200,
    from_ts: float | None = None,
    until_ts: float | None = None,
    *,
    domain: str | None = None,
    client: str | None = None,
    cursor: str | None = None,
) -> QueryPage:
    payload = get_client().metrics.get_queries(
        length=length,
        from_ts=from_ts,
        until_ts=until_ts,
        domain=domain,
        client=client,
        cursor=cursor,
    )
    rows = extract_collection(payload, "queries", "data")
    normalized: list[dict[str, Any]] = []
    for row in rows:
        timestamp = row.get("time") or row.get("timestamp") or row.get("ts") or 0
        try:
            timestamp = float(timestamp)
        except (TypeError, ValueError):
            timestamp = 0.0
        query_client = row.get("client")
        if isinstance(query_client, dict):
            query_client = query_client.get("name") or query_client.get("ip")
        normalized.append(
            {
                "time": timestamp,
                "client": str(query_client or row.get("ip") or row.get("requester") or ""),
                "domain": str(row.get("domain") or row.get("name") or row.get("qname") or ""),
                "type": str(row.get("type") or row.get("qtype") or ""),
                "status": str(row.get("status") or row.get("answer") or row.get("result") or ""),
            }
        )

    page_cursor = ""
    total: int | None = None
    if isinstance(payload, dict):
        raw_cursor = payload.get("cursor") or payload.get("next_cursor")
        if isinstance(raw_cursor, dict):
            page_cursor = str(
                raw_cursor.get("next")
                or raw_cursor.get("forward")
                or raw_cursor.get("cursor")
                or ""
            )
        elif raw_cursor is not None:
            page_cursor = str(raw_cursor)
        for key in ("total", "recordsTotal", "count"):
            value = payload.get(key)
            if isinstance(value, int):
                total = value
                break
    return QueryPage(normalized, page_cursor, total)


def fetch_queries(
    length: int = 200,
    from_ts: float | None = None,
    until_ts: float | None = None,
) -> list[dict[str, Any]]:
    return fetch_query_page(length, from_ts, until_ts).rows


def fetch_exact_domains(domain_type: str) -> list[dict[str, Any]]:
    if domain_type not in {"allow", "deny"}:
        raise ValueError("domain_type must be 'allow' or 'deny'")
    payload = get_client().domain_management.get_domains(domain_type, "exact")
    rows = extract_collection(payload, "domains", domain_type, "data")
    output: list[dict[str, Any]] = []
    for row in rows:
        domain = row.get("domain") or row.get("item")
        if not domain:
            continue
        output.append(
            {
                "domain": str(domain),
                "comment": str(row.get("comment") or ""),
                "enabled": bool(row.get("enabled", True)),
                "groups": row.get("groups") or [],
                "date_added": row.get("date_added") or row.get("dateAdded") or "",
                "date_modified": row.get("date_modified") or row.get("dateModified") or "",
            }
        )
    return output


def fetch_groups() -> list[dict[str, Any]]:
    payload = get_client().group_management.get_groups()
    rows = extract_collection(payload, "groups", "data")
    output: list[dict[str, Any]] = []
    for row in rows:
        group_id = row.get("id")
        name = row.get("name")
        if group_id is None or name is None:
            continue
        try:
            normalized_id = int(group_id)
        except (TypeError, ValueError):
            continue
        output.append(
            {
                "id": normalized_id,
                "name": str(name),
                "comment": str(row.get("comment") or ""),
                "enabled": bool(row.get("enabled", True)),
            }
        )
    return sorted(output, key=lambda item: (str(item["name"]).casefold(), int(item["id"])))


def update_exact_domain_groups(
    domain: str,
    domain_type: str,
    groups: list[int],
    *,
    comment: str = "",
    enabled: bool = True,
) -> Any:
    if domain_type not in {"allow", "deny"}:
        raise ValueError("domain_type must be 'allow' or 'deny'")
    normalized_groups = sorted({int(group_id) for group_id in groups})
    before = capture_pihole_snapshot("exact_domain", domain_type, domain)
    result = get_client().domain_management.update_domain(
        domain=domain,
        domain_type=domain_type,
        kind="exact",
        comment=comment or None,
        groups=normalized_groups,
        enabled=bool(enabled),
    )
    record_pihole_change(
        "update",
        "exact_domain",
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


def fetch_subscribed_lists(list_type: str | None = None) -> list[dict[str, Any]]:
    if list_type is not None and list_type not in {"allow", "block"}:
        raise ValueError("list_type must be 'allow', 'block', or None")
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
                "type": str(row.get("type") or list_type or "block"),
                "comment": str(row.get("comment") or ""),
                "enabled": bool(row.get("enabled", True)),
                "groups": row.get("groups") or [],
                "date_added": row.get("date_added") or row.get("dateAdded") or "",
                "date_modified": row.get("date_modified") or row.get("dateModified") or "",
            }
        )
    return output


def update_subscribed_list_groups(
    address: str,
    list_type: str,
    groups: list[int],
    *,
    comment: str = "",
    enabled: bool = True,
) -> Any:
    if list_type not in {"allow", "block"}:
        raise ValueError("list_type must be 'allow' or 'block'")
    normalized_groups = sorted({int(group_id) for group_id in groups})
    before = capture_pihole_snapshot("subscribed_list", list_type, address)
    result = get_client().list_management.update_list(
        address=address,
        list_type=list_type,
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


def add_exact_domain(
    domain: str,
    policy: Policy | str,
    comment: str = "",
    *,
    compatibility_override: bool = False,
) -> Any:
    policy_value = policy.value if isinstance(policy, Policy) else str(policy)
    if policy_value not in {Policy.ALLOW.value, Policy.DENY.value}:
        raise ValueError("policy must be allow or deny")
    lock = get_domain_lock(domain)
    if lock and lock["list_type"] != policy_value:
        raise RuntimeError(
            "Domain is protected in the "
            f"{lock['list_type']} list and cannot be added to {policy_value}."
        )
    compatibility = compatibility_match_for_domain(domain)
    if (
        policy_value == Policy.DENY.value
        and compatibility is not None
        and not compatibility_override
    ):
        raise RuntimeError(
            f"Domain matches protected compatibility profile '{compatibility.profile.name}' "
            f"({compatibility.matched_pattern}). Blocking requires an explicit compatibility "
            f"override. {compatibility.profile.reason}"
        )
    result = get_client().domain_management.add_domain(
        domain=domain,
        domain_type=policy_value,
        kind="exact",
        comment=comment or None,
        groups=None,
        enabled=True,
    )
    record_pihole_change(
        "add",
        "exact_domain",
        policy_value,
        domain,
        after={
            "domain": domain,
            "type": policy_value,
            "comment": comment,
            "groups": None,
            "enabled": True,
        },
    )
    return result


def delete_exact_domain(domain: str, domain_type: str) -> Any:
    if domain_type not in {"allow", "deny"}:
        raise ValueError("domain_type must be 'allow' or 'deny'")
    lock = get_domain_lock(domain)
    if lock and lock["list_type"] == domain_type:
        raise RuntimeError("Domain is protected and cannot be removed until it is unlocked.")
    before = capture_pihole_snapshot("exact_domain", domain_type, domain)
    result = get_client().domain_management.delete_domain(domain, domain_type, "exact")
    record_pihole_change(
        "delete",
        "exact_domain",
        domain_type,
        domain,
        before=before,
    )
    return result
