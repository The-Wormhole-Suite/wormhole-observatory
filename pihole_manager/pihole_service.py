from __future__ import annotations

import threading
import time
from typing import Any

from pihole6api import PiHole6Client, normalize_api_url
from pihole_manager.config import PiHoleOptions, load_options
from pihole_manager.database import get_domain_lock
from pihole_manager.models import ConnectionTestResult, Policy

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


def test_connection(options: PiHoleOptions | None = None) -> ConnectionTestResult:
    settings = options or load_options().pihole
    request_url = f"{normalize_api_url(settings.base_url)}info/version"
    started = time.perf_counter()
    try:
        client = configure_client(settings)
        payload = client.ftl_info.get_version()
        elapsed_ms = round((time.perf_counter() - started) * 1000)
        version = _extract_version(payload)
        summary = "Pi-hole v6 API responded successfully"
        if version:
            summary = f"Pi-hole API responded successfully ({version})"
        return ConnectionTestResult(True, request_url, elapsed_ms, summary, version)
    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - started) * 1000)
        return ConnectionTestResult(False, request_url, elapsed_ms, str(exc))


def _extract_version(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    version = payload.get("version")
    if isinstance(version, str):
        return version
    if isinstance(version, dict):
        for key in ("core", "ftl", "web"):
            item = version.get(key)
            if isinstance(item, dict):
                value = item.get("version") or item.get("local")
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


def fetch_queries(length: int = 200, from_ts: int | None = None) -> list[dict[str, Any]]:
    payload = get_client().metrics.get_queries(length=length, from_ts=from_ts)
    rows = extract_collection(payload, "queries", "data")
    normalized: list[dict[str, Any]] = []
    for row in rows:
        timestamp = row.get("time") or row.get("timestamp") or row.get("ts") or 0
        try:
            timestamp = int(float(timestamp))
        except (TypeError, ValueError):
            timestamp = 0
        client = row.get("client")
        if isinstance(client, dict):
            client = client.get("name") or client.get("ip")
        normalized.append(
            {
                "time": timestamp,
                "client": str(client or row.get("ip") or row.get("requester") or ""),
                "domain": str(row.get("domain") or row.get("name") or row.get("qname") or ""),
                "type": str(row.get("type") or row.get("qtype") or ""),
                "status": str(row.get("status") or row.get("answer") or row.get("result") or ""),
            }
        )
    return normalized


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


def add_exact_domain(domain: str, policy: Policy | str, comment: str = "") -> Any:
    policy_value = policy.value if isinstance(policy, Policy) else str(policy)
    if policy_value not in {Policy.ALLOW.value, Policy.DENY.value}:
        raise ValueError("policy must be allow or deny")
    lock = get_domain_lock(domain)
    if lock and lock["list_type"] != policy_value:
        raise RuntimeError(
            "Domain is protected in the "
            f"{lock['list_type']} list and cannot be added to {policy_value}."
        )
    return get_client().domain_management.add_domain(
        domain=domain,
        domain_type=policy_value,
        kind="exact",
        comment=comment or None,
        groups=None,
        enabled=True,
    )


def delete_exact_domain(domain: str, domain_type: str) -> Any:
    if domain_type not in {"allow", "deny"}:
        raise ValueError("domain_type must be 'allow' or 'deny'")
    lock = get_domain_lock(domain)
    if lock and lock["list_type"] == domain_type:
        raise RuntimeError("Domain is protected and cannot be removed until it is unlocked.")
    return get_client().domain_management.delete_domain(domain, domain_type, "exact")
