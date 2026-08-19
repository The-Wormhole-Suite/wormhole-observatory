from __future__ import annotations

import time
from typing import Any

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


def research_urlhaus(
    domain: str,
    provider: ResearchProviderOptions,
) -> list[ResearchFinding]:
    auth_key = provider.api_key.strip()
    if not auth_key:
        raise ResearchError("URLhaus requires an Auth-Key")

    normalized = normalize_domain(domain)
    base_url = (provider.base_url or "https://urlhaus-api.abuse.ch/v1").rstrip("/")
    wait_for_provider(provider)
    response = requests.post(
        f"{base_url}/host/",
        data={"host": normalized},
        headers=request_headers(**{"Auth-Key": auth_key}),
        timeout=provider.timeout_sec,
    )
    response.raise_for_status()
    payload = response.json()
    query_status = str(payload.get("query_status") or payload.get("query_staus") or "")
    if query_status == "no_results":
        return [
            negative_finding(
                normalized,
                provider,
                summary=(
                    "URLhaus returned no host result. This is neutral evidence and does not "
                    "mean that the domain is safe."
                ),
            )
        ]
    if query_status != "ok":
        raise ResearchError(f"URLhaus host lookup failed with status: {query_status or 'unknown'}")

    urls = payload.get("urls")
    entries = [item for item in urls if isinstance(item, dict)] if isinstance(urls, list) else []
    active = [item for item in entries if str(item.get("url_status") or "") == "online"]
    unknown = [item for item in entries if str(item.get("url_status") or "") == "unknown"]
    offline = [item for item in entries if str(item.get("url_status") or "") == "offline"]

    if active:
        verdict = "malware"
        confidence = 0.99
        decision_relevant = True
        status_text = f"{len(active)} active malware URL(s)"
    elif unknown:
        verdict = "suspicious"
        confidence = 0.82
        decision_relevant = False
        status_text = f"{len(unknown)} URL(s) with unknown current status"
    else:
        verdict = "historical_malware"
        confidence = 0.9
        decision_relevant = False
        status_text = f"{len(offline)} historical/offline malware URL(s)"

    reference = str(payload.get("urlhaus_reference") or "https://urlhaus.abuse.ch/")
    url_count = _as_int(payload.get("url_count"), len(entries))
    tags = _collect_tags(entries)
    summary = (
        f"URLhaus host record: {status_text}; total observed URLs={url_count}; "
        f"first seen={payload.get('firstseen') or 'unknown'}."
    )
    if tags:
        summary += f" Tags: {', '.join(tags[:12])}."
    if not entries:
        summary += " The host record contains no URL details in this response."

    now = int(time.time())
    compact_payload = {
        "host": payload.get("host") or normalized,
        "firstseen": payload.get("firstseen"),
        "url_count": payload.get("url_count"),
        "blacklists": (
            payload.get("blacklists") if isinstance(payload.get("blacklists"), dict) else {}
        ),
        "active_url_count": len(active),
        "unknown_url_count": len(unknown),
        "offline_url_count": len(offline),
        "urls": entries[: provider.max_results],
    }
    return [
        ResearchFinding(
            domain=normalized,
            provider=provider.name,
            kind="malware_url_host",
            title="URLhaus host intelligence",
            summary=summary,
            source_url=reference,
            confidence=confidence,
            signal_type="security",
            verdict=verdict,
            decision_relevant=decision_relevant,
            retrieved_at=now,
            expires_at=now + provider.refresh_interval_hours * 3600,
            raw_data=compact_payload,
        )
    ]


def _collect_tags(entries: list[dict[str, Any]]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for item in entries:
        values = item.get("tags")
        if not isinstance(values, list):
            continue
        for value in values:
            tag = str(value or "").strip()
            key = tag.casefold()
            if tag and key not in seen:
                result.append(tag)
                seen.add(key)
    return result


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
