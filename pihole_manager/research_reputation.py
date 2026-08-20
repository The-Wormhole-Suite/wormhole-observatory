from __future__ import annotations

import time
from datetime import datetime, timezone

import requests

from pihole_manager.config import ResearchProviderOptions
from pihole_manager.models import ResearchFinding
from pihole_manager.research_common import (
    ResearchError,
    negative_finding,
    normalize_domain,
    request_headers,
    wait_for_provider,
)


def research_crtsh(
    domain: str,
    provider: ResearchProviderOptions,
) -> list[ResearchFinding]:
    normalized = normalize_domain(domain)
    base_url = (provider.base_url or "https://crt.sh/").rstrip("/") + "/"
    wait_for_provider(provider)
    response = requests.get(
        base_url,
        params={"q": normalized, "output": "json"},
        headers=request_headers(Accept="application/json"),
        timeout=provider.timeout_sec,
    )
    response.raise_for_status()
    payload = response.json()
    entries = payload if isinstance(payload, list) else []
    if not entries:
        return [
            negative_finding(
                normalized,
                provider,
                summary="No certificate-transparency entries were returned.",
            )
        ]

    names: set[str] = set()
    issuers: set[str] = set()
    active_count = 0
    newest_not_before = ""
    for item in entries:
        if not isinstance(item, dict):
            continue
        for value in str(item.get("name_value") or "").splitlines():
            candidate = normalize_domain(value.removeprefix("*."))
            if candidate and (
                candidate == normalized or candidate.endswith(f".{normalized}")
            ):
                names.add(candidate)
        issuer = str(item.get("issuer_name") or "").strip()
        if issuer:
            issuers.add(issuer)
        if _is_future_timestamp(str(item.get("not_after") or "")):
            active_count += 1
        not_before = str(item.get("not_before") or "").strip()
        if not_before > newest_not_before:
            newest_not_before = not_before

    summary_parts = [
        f"crt.sh returned {len(entries)} certificate entries",
        f"{len(names)} matching identities",
        f"{active_count} entries appear unexpired",
    ]
    if newest_not_before:
        summary_parts.append(f"newest issuance starts {newest_not_before}")
    if issuers:
        summary_parts.append(f"issuers include {', '.join(sorted(issuers)[:3])}")

    now = int(time.time())
    return [
        ResearchFinding(
            domain=normalized,
            provider=provider.name,
            kind="certificate_transparency",
            title="Certificate Transparency history",
            summary="; ".join(summary_parts) + ".",
            source_url=getattr(response, "url", base_url),
            confidence=0.94,
            signal_type="identity",
            verdict="certificate_transparency_context",
            decision_relevant=False,
            retrieved_at=now,
            expires_at=now + provider.refresh_interval_hours * 3600,
            raw_data={
                "entry_count": len(entries),
                "matching_names": sorted(names)[:100],
                "active_entry_count": active_count,
                "issuers": sorted(issuers)[:20],
                "newest_not_before": newest_not_before,
            },
        )
    ]


def research_google_safe_browsing(
    domain: str,
    provider: ResearchProviderOptions,
) -> list[ResearchFinding]:
    if not provider.api_key.strip():
        raise ResearchError("Google Safe Browsing requires an API key.")

    normalized = normalize_domain(domain)
    base_url = (provider.base_url or "https://safebrowsing.googleapis.com").rstrip("/")
    urls = [f"https://{normalized}/", f"http://{normalized}/"]
    params: list[tuple[str, str]] = [("key", provider.api_key.strip())]
    params.extend(("urls", url) for url in urls)
    wait_for_provider(provider)
    response = requests.get(
        f"{base_url}/v5/urls:search",
        params=params,
        headers=request_headers(Accept="application/json"),
        timeout=provider.timeout_sec,
    )
    response.raise_for_status()
    payload = response.json()
    threats = payload.get("threats") if isinstance(payload, dict) else None
    if not isinstance(threats, list) or not threats:
        return [
            negative_finding(
                normalized,
                provider,
                summary="Google Safe Browsing returned no known threat match.",
            )
        ]

    threat_types: set[str] = set()
    matched_urls: set[str] = set()
    for item in threats:
        if not isinstance(item, dict):
            continue
        matched_url = str(item.get("url") or "").strip()
        if matched_url:
            matched_urls.add(matched_url)
        for threat_type in item.get("threatTypes") or []:
            value = str(threat_type).strip().upper()
            if value and value != "THREAT_TYPE_UNSPECIFIED":
                threat_types.add(value)

    verdict = _safe_browsing_verdict(threat_types)
    now = int(time.time())
    return [
        ResearchFinding(
            domain=normalized,
            provider=provider.name,
            kind="threat_reputation",
            title="Google Safe Browsing threat match",
            summary=(
                "Google Safe Browsing matched the domain URL expressions as "
                f"{', '.join(sorted(threat_types)) or 'an unsafe resource'}."
            ),
            source_url="https://developers.google.com/safe-browsing/",
            confidence=0.99,
            signal_type="security",
            verdict=verdict,
            decision_relevant=True,
            retrieved_at=now,
            expires_at=now + provider.refresh_interval_hours * 3600,
            raw_data={
                "threat_types": sorted(threat_types),
                "matched_urls": sorted(matched_urls),
                "cache_duration": str(payload.get("cacheDuration") or ""),
            },
        )
    ]


def _safe_browsing_verdict(threat_types: set[str]) -> str:
    if "SOCIAL_ENGINEERING" in threat_types:
        return "phishing"
    if "MALWARE" in threat_types:
        return "malware"
    if threat_types & {"UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"}:
        return "suspicious"
    return "malicious"


def _is_future_timestamp(value: str) -> bool:
    if not value:
        return False
    candidate = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed > datetime.now(timezone.utc)
