from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import asdict
from typing import Any
from urllib.parse import quote

import requests

from pihole_manager.config import ResearchProviderOptions, load_options
from pihole_manager.database import research_findings_get, save_research_findings
from pihole_manager.models import ResearchFinding

log = logging.getLogger(__name__)

_IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_RATE_LOCK = threading.RLock()
_LAST_REQUEST: dict[str, float] = {}
_BOOTSTRAP_LOCK = threading.RLock()
_BOOTSTRAP_CACHE: tuple[float, dict[str, str]] | None = None


class ResearchError(RuntimeError):
    pass


def research_domain(domain: str, *, force: bool = False) -> list[ResearchFinding]:
    options = load_options()
    normalized = domain.strip().lower().rstrip(".")
    if not normalized:
        raise ValueError("domain must not be empty")
    if not options.research.enabled:
        return []

    if not force:
        cached = research_findings_get(normalized, fresh_only=True)
        if cached:
            return [_finding_from_row(row) for row in cached]

    findings: list[ResearchFinding] = []
    for provider in options.research_providers:
        if not provider.enabled:
            continue
        try:
            provider_findings = _run_provider(normalized, provider)
        except Exception as exc:
            log.warning("Research provider %s failed for %s: %s", provider.name, normalized, exc)
            continue
        findings.extend(provider_findings[: provider.max_results])

    if findings:
        save_research_findings(findings)
    return findings


def research_many(domains: list[str], *, force: bool = False) -> dict[str, list[ResearchFinding]]:
    return {domain: research_domain(domain, force=force) for domain in domains}


def research_context(domain: str, findings: list[ResearchFinding] | None = None) -> dict[str, Any]:
    selected = findings
    if selected is None:
        selected = [
            _finding_from_row(row)
            for row in research_findings_get(domain, fresh_only=True)
        ]
    return {
        "domain": domain.strip().lower().rstrip("."),
        "findings": [
            {
                "provider": item.provider,
                "kind": item.kind,
                "title": item.title,
                "summary": item.summary,
                "source_url": item.source_url,
                "confidence": item.confidence,
                "retrieved_at": item.retrieved_at,
            }
            for item in selected
        ],
    }


def _run_provider(domain: str, provider: ResearchProviderOptions) -> list[ResearchFinding]:
    handlers: dict[str, Callable[[str, ResearchProviderOptions], list[ResearchFinding]]] = {
        "rdap": _research_rdap,
        "github_code": _research_github,
        "brave_search": _research_brave,
        "virustotal": _research_virustotal,
    }
    handler = handlers.get(provider.kind)
    if handler is None:
        raise ResearchError(f"Unsupported research provider kind: {provider.kind}")
    _wait_for_provider(provider)
    return handler(domain, provider)


def _wait_for_provider(provider: ResearchProviderOptions) -> None:
    key = f"{provider.kind}:{provider.name}"
    with _RATE_LOCK:
        elapsed = time.monotonic() - _LAST_REQUEST.get(key, 0.0)
        delay = max(0.0, provider.min_interval_sec - elapsed)
    if delay:
        time.sleep(delay)
    with _RATE_LOCK:
        _LAST_REQUEST[key] = time.monotonic()


def _research_rdap(domain: str, provider: ResearchProviderOptions) -> list[ResearchFinding]:
    bootstrap = _rdap_bootstrap(provider.timeout_sec)
    labels = domain.split(".")
    if len(labels) < 2:
        return []
    server = bootstrap.get(labels[-1])
    if not server:
        return []

    response: requests.Response | None = None
    candidate = domain
    for index in range(max(0, len(labels) - 4), len(labels) - 1):
        candidate = ".".join(labels[index:])
        url = f"{server.rstrip('/')}/domain/{quote(candidate, safe='.-_')}"
        response = requests.get(
            url,
            headers={"Accept": "application/rdap+json, application/json"},
            timeout=provider.timeout_sec,
            allow_redirects=True,
        )
        if response.status_code == 404:
            continue
        response.raise_for_status()
        break
    if response is None or response.status_code == 404:
        return []

    data = response.json()
    registrar = _rdap_registrar(data)
    statuses = ", ".join(str(value) for value in data.get("status") or [])
    nameservers = ", ".join(
        str(item.get("ldhName") or "")
        for item in data.get("nameservers") or []
        if isinstance(item, dict) and item.get("ldhName")
    )
    events = {
        str(item.get("eventAction") or ""): str(item.get("eventDate") or "")
        for item in data.get("events") or []
        if isinstance(item, dict)
    }
    parts = [f"Registered domain: {data.get('ldhName') or candidate}"]
    if registrar:
        parts.append(f"Registrar: {registrar}")
    if events.get("registration"):
        parts.append(f"Registered: {events['registration']}")
    if events.get("expiration"):
        parts.append(f"Expires: {events['expiration']}")
    if statuses:
        parts.append(f"Status: {statuses}")
    if nameservers:
        parts.append(f"Nameservers: {nameservers}")
    now = int(time.time())
    return [
        ResearchFinding(
            domain=domain,
            provider=provider.name,
            kind="registration",
            title=f"RDAP registration for {candidate}",
            summary="; ".join(parts),
            source_url=response.url,
            confidence=0.98,
            retrieved_at=now,
            expires_at=now + load_options().research.max_age_days * 86400,
            raw_data=data,
        )
    ]


def _rdap_bootstrap(timeout: float) -> dict[str, str]:
    global _BOOTSTRAP_CACHE
    with _BOOTSTRAP_LOCK:
        if _BOOTSTRAP_CACHE and time.time() - _BOOTSTRAP_CACHE[0] < 86400:
            return dict(_BOOTSTRAP_CACHE[1])
        response = requests.get(_IANA_BOOTSTRAP_URL, timeout=timeout)
        response.raise_for_status()
        data = response.json()
        mapping: dict[str, str] = {}
        for service in data.get("services") or []:
            if not isinstance(service, list) or len(service) != 2:
                continue
            tlds, urls = service
            if not urls:
                continue
            for tld in tlds:
                mapping[str(tld).lower()] = str(urls[0])
        _BOOTSTRAP_CACHE = (time.time(), mapping)
        return dict(mapping)


def _rdap_registrar(data: dict[str, Any]) -> str:
    for entity in data.get("entities") or []:
        if not isinstance(entity, dict) or "registrar" not in (entity.get("roles") or []):
            continue
        vcard = entity.get("vcardArray")
        if not isinstance(vcard, list) or len(vcard) != 2:
            continue
        for item in vcard[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] in {"fn", "org"}:
                return str(item[3])
    return ""


def _research_github(domain: str, provider: ResearchProviderOptions) -> list[ResearchFinding]:
    if not provider.api_key.strip():
        return []
    base_url = (provider.base_url or "https://api.github.com").rstrip("/")
    response = requests.get(
        f"{base_url}/search/code",
        params={"q": f'"{domain}" in:file', "per_page": provider.max_results},
        headers={
            "Accept": "application/vnd.github.text-match+json",
            "Authorization": f"Bearer {provider.api_key}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Pi-Hole-Manager",
        },
        timeout=provider.timeout_sec,
    )
    response.raise_for_status()
    data = response.json()
    now = int(time.time())
    findings: list[ResearchFinding] = []
    for item in data.get("items") or []:
        if not isinstance(item, dict):
            continue
        repository = item.get("repository") or {}
        repo_name = str(repository.get("full_name") or "unknown repository")
        fragments = []
        for match in item.get("text_matches") or []:
            if isinstance(match, dict) and match.get("fragment"):
                fragments.append(str(match["fragment"]).strip())
        summary = f"Domain referenced in {repo_name}/{item.get('path') or item.get('name') or ''}."
        if fragments:
            summary += " Context: " + " ".join(fragments)[:1000]
        findings.append(
            ResearchFinding(
                domain=domain,
                provider=provider.name,
                kind="github_code",
                title=f"GitHub reference in {repo_name}",
                summary=summary,
                source_url=str(item.get("html_url") or ""),
                confidence=0.7,
                retrieved_at=now,
                expires_at=now + load_options().research.max_age_days * 86400,
                raw_data=item,
            )
        )
    return findings


def _research_brave(domain: str, provider: ResearchProviderOptions) -> list[ResearchFinding]:
    if not provider.api_key.strip():
        return []
    url = provider.base_url or "https://api.search.brave.com/res/v1/web/search"
    query = f'"{domain}" (Pi-hole OR blocklist OR whitelist OR tracker OR telemetry OR GitHub)'
    response = requests.get(
        url,
        params={"q": query, "count": provider.max_results, "safesearch": "moderate"},
        headers={
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "X-Subscription-Token": provider.api_key,
            "User-Agent": "Pi-Hole-Manager",
        },
        timeout=provider.timeout_sec,
    )
    response.raise_for_status()
    data = response.json()
    now = int(time.time())
    results = ((data.get("web") or {}).get("results") or [])[: provider.max_results]
    return [
        ResearchFinding(
            domain=domain,
            provider=provider.name,
            kind="web_search",
            title=str(item.get("title") or "Web search result"),
            summary=str(item.get("description") or ""),
            source_url=str(item.get("url") or ""),
            confidence=0.55,
            retrieved_at=now,
            expires_at=now + load_options().research.max_age_days * 86400,
            raw_data=item,
        )
        for item in results
        if isinstance(item, dict)
    ]


def _research_virustotal(domain: str, provider: ResearchProviderOptions) -> list[ResearchFinding]:
    if not provider.api_key.strip():
        return []
    base_url = (provider.base_url or "https://www.virustotal.com/api/v3").rstrip("/")
    response = requests.get(
        f"{base_url}/domains/{quote(domain, safe='.-_')}",
        headers={"Accept": "application/json", "x-apikey": provider.api_key},
        timeout=provider.timeout_sec,
    )
    if response.status_code == 404:
        return []
    response.raise_for_status()
    data = response.json()
    attributes = ((data.get("data") or {}).get("attributes") or {})
    stats = attributes.get("last_analysis_stats") or {}
    categories = attributes.get("categories") or {}
    summary = (
        f"VirusTotal analysis: malicious={stats.get('malicious', 0)}, "
        f"suspicious={stats.get('suspicious', 0)}, harmless={stats.get('harmless', 0)}, "
        f"undetected={stats.get('undetected', 0)}. "
        f"Reputation={attributes.get('reputation', 0)}."
    )
    if categories:
        summary += " Categories: " + ", ".join(
            f"{key}={value}" for key, value in list(categories.items())[:10]
        )
    now = int(time.time())
    return [
        ResearchFinding(
            domain=domain,
            provider=provider.name,
            kind="threat_intelligence",
            title="VirusTotal domain report",
            summary=summary,
            source_url=f"https://www.virustotal.com/gui/domain/{domain}",
            confidence=0.9,
            retrieved_at=now,
            expires_at=now + min(7, load_options().research.max_age_days) * 86400,
            raw_data=data,
        )
    ]


def _finding_from_row(row: dict[str, Any]) -> ResearchFinding:
    payload = dict(row)
    payload.pop("id", None)
    return ResearchFinding(
        domain=str(payload.get("domain") or ""),
        provider=str(payload.get("provider") or ""),
        kind=str(payload.get("kind") or ""),
        title=str(payload.get("title") or ""),
        summary=str(payload.get("summary") or ""),
        source_url=str(payload.get("source_url") or ""),
        confidence=float(payload.get("confidence") or 0.0),
        retrieved_at=int(payload.get("retrieved_at") or 0),
        expires_at=int(payload.get("expires_at") or 0),
        raw_data=dict(payload.get("raw_data") or {}),
    )


def provider_snapshot(provider: ResearchProviderOptions) -> dict[str, Any]:
    data = asdict(provider)
    if data.get("api_key"):
        data["api_key"] = "***"
    return data
