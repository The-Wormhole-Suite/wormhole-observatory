from __future__ import annotations

import bz2
import json
import threading
import time
from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit

from pihole_manager.config import ResearchProviderOptions
from pihole_manager.models import ResearchFinding
from pihole_manager.research_common import (
    fetch_cached_bytes,
    negative_finding,
    normalize_domain,
)

_INDEX_LOCK = threading.RLock()
_INDEX_CACHE: dict[str, tuple[bytes, Any]] = {}
_INDEX_LOCKS: dict[str, threading.RLock] = {}


def research_adguard_services(
    domain: str,
    provider: ResearchProviderOptions,
) -> list[ResearchFinding]:
    url = provider.base_url or (
        "https://adguardteam.github.io/HostlistsRegistry/assets/services.json"
    )
    payload = fetch_cached_bytes(provider, url, accept="application/json")
    index = _cached_index("adguard", payload, _build_adguard_index)
    matches = _lookup_suffixes(domain, index)
    if not matches:
        return [negative_finding(domain, provider)]

    now = int(time.time())
    findings = []
    for item in matches[: provider.max_results]:
        service = str(item.get("name") or item.get("id") or "Unknown service")
        group = str(item.get("group") or "unknown")
        rule = str(item.get("rule") or "")
        findings.append(
            ResearchFinding(
                domain=normalize_domain(domain),
                provider=provider.name,
                kind="service_catalog",
                title=f"AdGuard service match: {service}",
                summary=(
                    f"Matched service {service} in group {group} using rule {rule}. "
                    "This identifies a service relationship but does not by itself justify "
                    "allowing or blocking the domain."
                ),
                source_url=url,
                confidence=0.92,
                signal_type="identity",
                verdict="service_match",
                decision_relevant=False,
                retrieved_at=now,
                expires_at=now + provider.refresh_interval_hours * 3600,
                raw_data=item,
            )
        )
    return findings


def research_disconnect_tracking(
    domain: str,
    provider: ResearchProviderOptions,
) -> list[ResearchFinding]:
    url = provider.base_url or (
        "https://raw.githubusercontent.com/disconnectme/"
        "disconnect-tracking-protection/master/services.json"
    )
    payload = fetch_cached_bytes(provider, url, accept="application/json")
    index = _cached_index("disconnect", payload, _build_disconnect_index)
    matches = _lookup_suffixes(domain, index)
    if not matches:
        return [negative_finding(domain, provider)]

    now = int(time.time())
    findings = []
    for item in matches[: provider.max_results]:
        category = str(item.get("category") or "Unknown")
        company = str(item.get("company") or "Unknown")
        homepage = str(item.get("homepage") or "")
        findings.append(
            ResearchFinding(
                domain=normalize_domain(domain),
                provider=provider.name,
                kind="tracker_catalog",
                title=f"Disconnect catalog match: {company}",
                summary=(
                    f"Disconnect classifies the matched domain under {category} and associates "
                    f"it with {company}."
                ),
                source_url=homepage or url,
                confidence=0.9,
                signal_type="privacy",
                verdict=_disconnect_verdict(category),
                decision_relevant=True,
                retrieved_at=now,
                expires_at=now + provider.refresh_interval_hours * 3600,
                raw_data=item,
            )
        )
    return findings


def research_phishtank(
    domain: str,
    provider: ResearchProviderOptions,
) -> list[ResearchFinding]:
    url = provider.base_url or ("https://data.phishtank.com/data/{api_key}/online-valid.json.bz2")
    payload = fetch_cached_bytes(provider, url, accept="application/json, application/x-bzip2")
    index = _cached_index("phishtank", payload, _build_phishtank_index)
    matches = _lookup_suffixes(domain, index)
    if not matches:
        return [negative_finding(domain, provider)]

    now = int(time.time())
    findings = []
    for item in matches[: provider.max_results]:
        target = str(item.get("target") or "unknown target")
        findings.append(
            ResearchFinding(
                domain=normalize_domain(domain),
                provider=provider.name,
                kind="phishing_database",
                title=f"Verified PhishTank entry targeting {target}",
                summary=(
                    "The hostname occurs in PhishTank's downloadable database of verified, "
                    f"currently online phishing URLs. Target: {target}."
                ),
                source_url=str(item.get("phish_detail_url") or ""),
                confidence=0.98,
                signal_type="security",
                verdict="phishing",
                decision_relevant=True,
                retrieved_at=now,
                expires_at=now + provider.refresh_interval_hours * 3600,
                raw_data=item,
            )
        )
    return findings


def _cached_index(prefix: str, payload: bytes, builder):
    # Retain one immutable source payload next to its parsed index. Exact byte
    # comparison avoids treating authenticated download content as password-like
    # hash input and guarantees that changed catalogs invalidate the cache.
    with _index_lock(prefix):
        with _INDEX_LOCK:
            cached = _INDEX_CACHE.get(prefix)
        if cached is not None and cached[0] == payload:
            return cached[1]

        built = builder(payload)
        with _INDEX_LOCK:
            _INDEX_CACHE[prefix] = (payload, built)
        return built
    

def _index_lock(prefix: str) -> threading.RLock:
    with _INDEX_LOCK:
        return _INDEX_LOCKS.setdefault(prefix, threading.RLock())


def _build_adguard_index(payload: bytes) -> dict[str, list[dict[str, Any]]]:
    data = json.loads(payload.decode("utf-8"))
    services = data if isinstance(data, list) else data.get("services", [])
    index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for service in services:
        if not isinstance(service, dict):
            continue
        for rule in service.get("rules") or []:
            suffix = _domain_from_adblock_rule(str(rule))
            if not suffix:
                continue
            index[suffix].append(
                {
                    "id": service.get("id"),
                    "name": service.get("name"),
                    "group": service.get("group"),
                    "rule": rule,
                    "matched_domain": suffix,
                }
            )
    return dict(index)


def _domain_from_adblock_rule(rule: str) -> str:
    value = rule.strip()
    if value.startswith("@@"):
        return ""
    if not value.startswith("||"):
        return ""
    value = value[2:].split("$", 1)[0]
    value = value.split("^", 1)[0].strip("|/")
    if not value or any(character in value for character in "*[]()\\"):
        return ""
    return normalize_domain(value)


def _build_disconnect_index(payload: bytes) -> dict[str, list[dict[str, Any]]]:
    data = json.loads(payload.decode("utf-8"))
    categories = data.get("categories") if isinstance(data, dict) else None
    index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if not isinstance(categories, dict):
        return {}
    for category, entries in categories.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            for company, homepage_map in entry.items():
                if not isinstance(homepage_map, dict):
                    continue
                for homepage, domains in homepage_map.items():
                    if not isinstance(domains, list):
                        continue
                    for listed_domain in domains:
                        suffix = normalize_domain(str(listed_domain))
                        if not suffix:
                            continue
                        index[suffix].append(
                            {
                                "category": str(category),
                                "company": str(company),
                                "homepage": str(homepage),
                                "matched_domain": suffix,
                            }
                        )
    return dict(index)


def _build_phishtank_index(payload: bytes) -> dict[str, list[dict[str, Any]]]:
    try:
        decoded = bz2.decompress(payload)
    except OSError:
        decoded = payload
    data = json.loads(decoded.decode("utf-8"))
    entries = data if isinstance(data, list) else data.get("entries", [])
    index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in entries:
        if not isinstance(item, dict):
            continue
        hostname = normalize_domain(urlsplit(str(item.get("url") or "")).hostname or "")
        if hostname:
            index[hostname].append(item)
    return dict(index)


def _lookup_suffixes(
    domain: str,
    index: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    normalized = normalize_domain(domain)
    labels = normalized.split(".")
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for position in range(max(0, len(labels) - 6), len(labels) - 1):
        suffix = ".".join(labels[position:])
        for item in index.get(suffix, []):
            marker = json.dumps(item, sort_keys=True, default=str)
            if marker not in seen:
                seen.add(marker)
                output.append(item)
    return output


def _disconnect_verdict(category: str) -> str:
    normalized = category.strip().lower().replace(" ", "_")
    mapping = {
        "advertising": "advertising",
        "analytics": "analytics",
        "fingerprinting": "cross_site_tracking",
        "session_replay": "cross_site_tracking",
        "cryptomining": "cryptomining",
        "email": "email_tracking",
        "emailaggressive": "email_tracking",
        "social": "social_tracking",
    }
    return mapping.get(normalized, normalized or "tracker")
