from __future__ import annotations

import ipaddress
import re
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from pihole_manager.config import ResearchProviderOptions
from pihole_manager.models import ResearchFinding
from pihole_manager.research_catalogs import _cached_index, _lookup_suffixes
from pihole_manager.research_common import fetch_cached_bytes, negative_finding, normalize_domain

_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class RepositoryListSource:
    source_id: str
    name: str
    repository: str
    repository_ref: str
    list_path: str
    raw_url: str
    license_id: str
    license_review_required: bool
    signal_type: str
    verdict: str
    confidence: float
    description: str

    @property
    def source_url(self) -> str:
        return f"{self.repository}/blob/{self.repository_ref}/{self.list_path}"


_REPOSITORY_LIST_SOURCES: tuple[RepositoryListSource, ...] = (
    RepositoryListSource(
        source_id="hagezi_tif_mini",
        name="HaGeZi Threat Intelligence Feeds Mini",
        repository="https://github.com/hagezi/dns-blocklists",
        repository_ref="main",
        list_path="adblock/tif.mini.txt",
        raw_url=(
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/"
            "main/adblock/tif.mini.txt"
        ),
        license_id="GPL-3.0",
        license_review_required=False,
        signal_type="security",
        verdict="suspicious",
        confidence=0.92,
        description=(
            "HaGeZi's size-optimized Threat Intelligence Feed list contains domains selected "
            "from security-focused feeds. A match is a strong risk signal, but is not treated "
            "as proof that the domain is currently malicious."
        ),
    ),
    RepositoryListSource(
        source_id="easyprivacy_trackingservers",
        name="EasyPrivacy tracking servers",
        repository="https://github.com/easylist/easylist",
        repository_ref="master",
        list_path="easyprivacy/easyprivacy_trackingservers.txt",
        raw_url=(
            "https://raw.githubusercontent.com/easylist/easylist/"
            "master/easyprivacy/easyprivacy_trackingservers.txt"
        ),
        license_id="UPSTREAM-LICENSE-PAGE",
        license_review_required=True,
        signal_type="privacy",
        verdict="tracker",
        confidence=0.9,
        description=(
            "EasyPrivacy identifies tracking infrastructure. Distribution remains disabled "
            "until the upstream licence terms have been reviewed for this application."
        ),
    ),
)


def research_repository_lists(
    domain: str,
    provider: ResearchProviderOptions,
) -> list[ResearchFinding]:
    normalized = normalize_domain(domain)
    matches: list[tuple[RepositoryListSource, dict[str, Any]]] = []

    for source in _REPOSITORY_LIST_SOURCES:
        payload = fetch_cached_bytes(provider, source.raw_url, accept="text/plain")
        index = _cached_index(
            f"repository-list:{source.source_id}",
            payload,
            _build_repository_list_index,
        )
        for item in _lookup_suffixes(normalized, index):
            matches.append((source, item))

    if not matches:
        return [
            negative_finding(
                normalized,
                provider,
                summary=(
                    "No match was found in the enabled locally cached repository lists. "
                    "A missing match is neutral evidence and does not imply that the domain is safe."
                ),
            )
        ]

    now = int(time.time())
    findings: list[ResearchFinding] = []
    for source, item in matches[: provider.max_results]:
        matched_domain = str(item.get("matched_domain") or normalized)
        line_number = int(item.get("line_number") or 0)
        raw_data = {
            **item,
            "source_id": source.source_id,
            "repository": source.repository,
            "repository_ref": source.repository_ref,
            "list_path": source.list_path,
            "list_url": source.raw_url,
            "license_id": source.license_id,
            "license_review_required": source.license_review_required,
            "wormhole_source_kind": source.source_id,
        }
        findings.append(
            ResearchFinding(
                domain=normalized,
                provider=provider.name,
                kind="repository_list",
                title=f"{source.name} match: {matched_domain}",
                summary=(
                    f"{source.description} Matched {matched_domain}"
                    + (f" at source line {line_number}." if line_number else ".")
                ),
                source_url=source.source_url,
                confidence=source.confidence,
                signal_type=source.signal_type,
                verdict=source.verdict,
                decision_relevant=True,
                retrieved_at=now,
                expires_at=now + provider.refresh_interval_hours * 3600,
                raw_data=raw_data,
            )
        )
    return findings


def _build_repository_list_index(payload: bytes) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    text = payload.decode("utf-8", errors="replace")
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        rule = raw_line.strip()
        domain = _domain_from_repository_rule(rule)
        if not domain:
            continue
        index[domain].append(
            {
                "matched_domain": domain,
                "rule": rule[:500],
                "line_number": line_number,
            }
        )
    return dict(index)


def _domain_from_repository_rule(rule: str) -> str:
    value = rule.strip()
    if not value or value.startswith(("!", "#", "[", "@@")):
        return ""

    if value.startswith("||"):
        candidate = value[2:].split("$", 1)[0]
        candidate = candidate.split("^", 1)[0].strip("|/")
        if not candidate or any(character in candidate for character in "*[]()\\"):
            return ""
        return _validated_domain(candidate)

    fields = value.split()
    if len(fields) >= 2 and _is_ip_address(fields[0]):
        return _validated_domain(fields[1])

    if len(fields) == 1 and not any(character in value for character in "/^$|*=,;()[]\\"):
        return _validated_domain(value)

    return ""


def _validated_domain(value: str) -> str:
    normalized = normalize_domain(value)
    if not normalized or len(normalized) > 253 or "." not in normalized:
        return ""
    if _is_ip_address(normalized):
        return ""
    try:
        ascii_domain = normalized.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    labels = ascii_domain.split(".")
    if any(not label or len(label) > 63 or not _HOST_LABEL_RE.fullmatch(label) for label in labels):
        return ""
    return normalized


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
