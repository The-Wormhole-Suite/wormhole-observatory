from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, quote_plus

import requests

from pihole_manager.config import ResearchProviderOptions, app_directory
from pihole_manager.evidence_licensing import source_license_policy
from pihole_manager.http_retry import retry_delay_from_headers
from pihole_manager.models import ResearchFinding

_USER_AGENT = (
    "Pi-Hole-Manager/0.3.6 "
    "(+https://github.com/HyperCriSiS/Pi-Hole-Manager; structured evidence lookup)"
)
_RATE_LOCK = threading.RLock()
_CACHE_LOCKS_GUARD = threading.RLock()
_CACHE_LOCKS: dict[str, threading.RLock] = {}


@dataclass(slots=True)
class _ProviderRateState:
    next_request_at: float = 0.0
    adaptive_interval: float = 0.0


_RATE_STATES: dict[str, _ProviderRateState] = {}


@dataclass(frozen=True, slots=True)
class SourceDefinition:
    kind: str
    display_name: str
    mode: str
    sends_domain: bool
    requires_api_key: bool
    description: str
    license_note: str = ""
    experimental: bool = False


_SOURCE_DEFINITIONS = {
    item.kind: item
    for item in (
        SourceDefinition(
            "adguard_services",
            "AdGuard service catalog",
            "catalog",
            False,
            False,
            "Downloads a complete service-to-domain catalog and performs lookups locally.",
            "GPL-3.0 dataset; downloaded at runtime and not bundled.",
        ),
        SourceDefinition(
            "dns_records",
            "Local DNS records",
            "local",
            False,
            False,
            "Queries the configured DNS resolver for A, AAAA, CNAME, NS, MX, HTTPS, and SVCB.",
        ),
        SourceDefinition(
            "disconnect_tracking",
            "Disconnect tracker catalog",
            "catalog",
            False,
            False,
            "Downloads the complete Disconnect tracker catalog and performs lookups locally.",
            "CC BY-NC-SA 4.0; enable only when the intended use complies with the license.",
        ),
        SourceDefinition(
            "rdap",
            "RDAP registration data",
            "lookup",
            True,
            False,
            "Retrieves registrar, registration events, status, and authoritative nameservers.",
        ),
        SourceDefinition(
            "ripestat",
            "RIPEstat network information",
            "lookup",
            False,
            False,
            "Resolves the domain locally and sends only resulting public IP addresses to RIPEstat.",
        ),
        SourceDefinition(
            "netcraft",
            "Netcraft Site Report",
            "lookup",
            True,
            False,
            "Parses selected structured fields from the public Site Report when "
            "robots.txt permits it.",
            "Public HTML under Netcraft fair-use terms; layout may change and access "
            "may be blocked.",
            True,
        ),
        SourceDefinition(
            "virustotal",
            "VirusTotal domain report",
            "lookup",
            True,
            True,
            "Retrieves reputation, scanner verdict counts, and vendor categories.",
        ),
        SourceDefinition(
            "threatfox",
            "ThreatFox IOC lookup",
            "lookup",
            True,
            True,
            "Performs an exact IOC lookup for active malware infrastructure.",
        ),
        SourceDefinition(
            "phishtank",
            "PhishTank verified phishing database",
            "catalog",
            False,
            True,
            "Downloads the verified online phishing database and performs hostname "
            "lookups locally.",
        ),
        SourceDefinition(
            "urlscan",
            "urlscan.io archived scans",
            "lookup",
            True,
            False,
            "Searches existing archived scans; it never submits a new active scan.",
        ),
        SourceDefinition(
            "cloudflare_radar",
            "Cloudflare Radar domain ranking",
            "lookup",
            True,
            True,
            "Retrieves popularity bucket, rank, and Cloudflare domain categories.",
        ),
        SourceDefinition(
            "repository_lists",
            "Curated repository blocklists",
            "catalog",
            False,
            False,
            "Downloads selected upstream DNS-safe lists and performs lookups locally.",
            "Per-source licences are reviewed and recorded in evidence provenance.",
        ),
        SourceDefinition(
            "urlhaus",
            "URLhaus host lookup",
            "lookup",
            True,
            True,
            "Queries the authenticated URLhaus host endpoint for malware-distribution URLs.",
            "Community API is subject to abuse.ch fair-use terms.",
        ),
    )
}


class ResearchError(RuntimeError):
    pass


def source_definitions() -> tuple[SourceDefinition, ...]:
    return tuple(_SOURCE_DEFINITIONS.values())


def source_definition(kind: str) -> SourceDefinition | None:
    return _SOURCE_DEFINITIONS.get(kind.strip().lower())


def provider_snapshot(provider: ResearchProviderOptions) -> dict[str, Any]:
    snapshot = asdict(provider)
    if snapshot.get("api_key"):
        snapshot["api_key"] = "***"
    definition = source_definition(provider.kind)
    if definition:
        snapshot.update(
            {
                "mode": definition.mode,
                "sends_domain": definition.sends_domain,
                "requires_api_key": definition.requires_api_key,
                "experimental": definition.experimental,
                "license_note": definition.license_note,
            }
        )
    license_policy = source_license_policy(provider.kind)
    if license_policy is not None:
        snapshot["license_policy"] = asdict(license_policy)
    return snapshot


def normalize_domain(domain: str) -> str:
    return domain.strip().lower().rstrip(".")


def domain_candidates(domain: str) -> list[str]:
    normalized = normalize_domain(domain)
    labels = normalized.split(".")
    if len(labels) < 2:
        return [normalized] if normalized else []
    return [".".join(labels[index:]) for index in range(len(labels) - 1)]


def negative_finding(
    domain: str,
    provider: ResearchProviderOptions,
    *,
    summary: str = "No matching structured evidence was found.",
) -> ResearchFinding:
    now = int(time.time())
    return ResearchFinding(
        domain=normalize_domain(domain),
        provider=provider.name,
        kind="lookup_status",
        title="No matching evidence",
        summary=summary,
        confidence=0.0,
        signal_type="status",
        verdict="no_match",
        decision_relevant=False,
        retrieved_at=now,
        expires_at=now + provider.refresh_interval_hours * 3600,
        raw_data={"include_in_prompt": False},
    )


def wait_for_provider(provider: ResearchProviderOptions) -> None:
    key = _provider_key(provider)
    while True:
        with _RATE_LOCK:
            state = _RATE_STATES.setdefault(key, _ProviderRateState())
            now = time.monotonic()
            delay = max(0.0, state.next_request_at - now)
            if delay <= 0:
                interval = max(
                    max(0.0, float(provider.min_interval_sec)),
                    state.adaptive_interval,
                )
                state.next_request_at = now + interval
                return
        time.sleep(delay)


def register_provider_failure(
    provider: ResearchProviderOptions,
    attempt: int,
    response: requests.Response | None = None,
) -> float:
    delay = retry_delay_from_headers(getattr(response, "headers", None))
    if delay is None:
        delay = min(300.0, max(1.0, 2.0**attempt))
    key = _provider_key(provider)
    with _RATE_LOCK:
        state = _RATE_STATES.setdefault(key, _ProviderRateState())
        base = max(0.0, float(provider.min_interval_sec))
        adaptive = state.adaptive_interval * 2 if state.adaptive_interval else max(1.0, base)
        state.adaptive_interval = min(60.0, max(base, adaptive))
        state.next_request_at = max(
            state.next_request_at,
            time.monotonic() + max(delay, state.adaptive_interval),
        )
    return delay


def register_provider_success(provider: ResearchProviderOptions) -> None:
    key = _provider_key(provider)
    with _RATE_LOCK:
        state = _RATE_STATES.setdefault(key, _ProviderRateState())
        base = max(0.0, float(provider.min_interval_sec))
        state.adaptive_interval = max(base, state.adaptive_interval / 2)


def _provider_key(provider: ResearchProviderOptions) -> str:
    return f"{provider.kind.strip().lower()}:{provider.name.strip().lower()}"


def request_headers(**extra: str) -> dict[str, str]:
    headers = {"User-Agent": _USER_AGENT, "Accept": "application/json"}
    headers.update(extra)
    return headers


def cache_directory() -> Path:
    path = app_directory() / "evidence_cache"
    path.mkdir(parents=True, exist_ok=True)
    return path


def fetch_cached_bytes(
    provider: ResearchProviderOptions,
    url: str,
    *,
    accept: str,
) -> bytes:
    resolved_url = resolve_url_template(url, provider.api_key)
    cache_root = cache_directory()
    _scrub_cached_metadata_secret(cache_root, provider.api_key)
    cache_identity_url = redact_provider_text(url, provider)
    cache_id = hashlib.sha256(f"{provider.kind}\0{cache_identity_url}".encode()).hexdigest()
    payload_path = cache_root / f"{cache_id}.bin"
    meta_path = cache_root / f"{cache_id}.json"
    with _cache_lock(cache_id):
        metadata = _read_metadata(meta_path)
        metadata = _redact_metadata(metadata, provider.api_key)
        max_age = provider.refresh_interval_hours * 3600
        if payload_path.exists() and time.time() - metadata.get("fetched_at", 0) < max_age:
            return payload_path.read_bytes()

        headers = request_headers(Accept=accept)
        if metadata.get("etag"):
            headers["If-None-Match"] = str(metadata["etag"])
        if metadata.get("last_modified"):
            headers["If-Modified-Since"] = str(metadata["last_modified"])
        wait_for_provider(provider)
        try:
            response = requests.get(
                resolved_url,
                headers=headers,
                timeout=provider.timeout_sec,
                allow_redirects=True,
            )
        except requests.RequestException as exc:
            sanitize_provider_exception(exc, provider)
            raise
        if response.status_code == 304 and payload_path.exists():
            metadata["fetched_at"] = time.time()
            _write_metadata(meta_path, metadata)
            return payload_path.read_bytes()
        try:
            response.raise_for_status()
        except requests.RequestException as exc:
            sanitize_provider_exception(exc, provider)
            raise
        payload = response.content
        _atomic_write(payload_path, payload)
        _write_metadata(
            meta_path,
            {
                "url": cache_identity_url,
                "fetched_at": time.time(),
                "etag": response.headers.get("ETag", ""),
                "last_modified": response.headers.get("Last-Modified", ""),
                "content_type": response.headers.get("Content-Type", ""),
            },
        )
        return payload


def _cache_lock(cache_id: str) -> threading.RLock:
    with _CACHE_LOCKS_GUARD:
        return _CACHE_LOCKS.setdefault(cache_id, threading.RLock())


def resolve_url_template(url: str, api_key: str) -> str:
    value = url.strip()
    if "{api_key}" in value:
        if not api_key.strip():
            raise ResearchError("This evidence source requires an API key")
        value = value.replace("{api_key}", api_key.strip())
    return value


def redact_provider_text(value: object, provider: ResearchProviderOptions) -> str:
    return _redact_secret_text(str(value), provider.api_key)


def sanitize_provider_exception(
    exc: requests.RequestException,
    provider: ResearchProviderOptions,
) -> None:
    exc.args = tuple(
        _redact_secret_text(value, provider.api_key) if isinstance(value, str) else value
        for value in exc.args
    )
    response = getattr(exc, "response", None)
    request = getattr(exc, "request", None)
    _redact_request_url(request, provider.api_key)
    if response is not None:
        if getattr(response, "url", None):
            response.url = _redact_secret_text(str(response.url), provider.api_key)
        _redact_request_url(getattr(response, "request", None), provider.api_key)
        for previous in getattr(response, "history", ()):
            if getattr(previous, "url", None):
                previous.url = _redact_secret_text(str(previous.url), provider.api_key)
            _redact_request_url(getattr(previous, "request", None), provider.api_key)


def _redact_request_url(request: object, api_key: str) -> None:
    if request is not None and getattr(request, "url", None):
        request.url = _redact_secret_text(str(request.url), api_key)


def _redact_secret_text(value: str, api_key: str) -> str:
    secret = api_key.strip()
    if not secret:
        return value
    redacted = value
    variants = {
        secret,
        quote(secret, safe=""),
        quote_plus(secret, safe=""),
    }
    for variant in sorted(variants, key=len, reverse=True):
        if variant:
            redacted = redacted.replace(variant, "***")
    return redacted


def _redact_metadata(value: Any, api_key: str) -> Any:
    if isinstance(value, dict):
        return {key: _redact_metadata(item, api_key) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_metadata(item, api_key) for item in value]
    if isinstance(value, str):
        return _redact_secret_text(value, api_key)
    return value


def _scrub_cached_metadata_secret(cache_root: Path, api_key: str) -> None:
    if not api_key.strip():
        return
    for path in cache_root.glob("*.json"):
        metadata = _read_metadata(path)
        if not metadata:
            continue
        redacted = _redact_metadata(metadata, api_key)
        if redacted != metadata:
            _write_metadata(path, redacted)


def safe_cache_name(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9_.-]+", "-", value.strip().lower())
    return normalized.strip("-") or "source"


def _read_metadata(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _write_metadata(path: Path, metadata: dict[str, Any]) -> None:
    payload = json.dumps(metadata, ensure_ascii=False, indent=2).encode("utf-8")
    _atomic_write(path, payload)


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", dir=path.parent, delete=False) as handle:
        handle.write(payload)
        temp_name = handle.name
    os.replace(temp_name, path)
