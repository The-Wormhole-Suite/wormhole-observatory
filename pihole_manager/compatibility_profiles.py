from __future__ import annotations

import json
import time
from collections.abc import Sequence
from dataclasses import dataclass, replace
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

from pihole_manager.behavior_change import apply_behavior_change_guard
from pihole_manager.models import Classification, Policy, ResearchFinding, ServiceRole

_DEFAULT_PROFILE_NAME = "compatibility_profiles_v1.json"
_SUPPORTED_SCHEMA_VERSION = 1
COMPATIBILITY_PROVIDER_NAME = "Wormhole compatibility profiles"


@dataclass(frozen=True, slots=True)
class CompatibilityProfile:
    profile_id: str
    name: str
    description: str
    service_role: ServiceRole
    min_breakage_risk: int
    protection: str
    exact_domains: tuple[str, ...]
    suffix_domains: tuple[str, ...]
    reason: str
    source_url: str = ""


@dataclass(frozen=True, slots=True)
class CompatibilityMatch:
    profile: CompatibilityProfile
    matched_pattern: str
    match_type: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile.profile_id,
            "name": self.profile.name,
            "description": self.profile.description,
            "service_role": self.profile.service_role.value,
            "min_breakage_risk": self.profile.min_breakage_risk,
            "protection": self.profile.protection,
            "reason": self.profile.reason,
            "source_url": self.profile.source_url,
            "matched_pattern": self.matched_pattern,
            "match_type": self.match_type,
        }


@lru_cache(maxsize=8)
def load_compatibility_profiles(
    path: str | Path | None = None,
) -> tuple[CompatibilityProfile, ...]:
    if path is None:
        payload = json.loads(
            resources.files("pihole_manager")
            .joinpath("data", _DEFAULT_PROFILE_NAME)
            .read_text(encoding="utf-8")
        )
    else:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Compatibility profile root must be a JSON object.")
    schema_version = _integer(payload.get("schema_version"), "schema_version")
    if schema_version != _SUPPORTED_SCHEMA_VERSION:
        raise ValueError(f"Unsupported compatibility profile schema version: {schema_version}")
    raw_profiles = payload.get("profiles")
    if not isinstance(raw_profiles, list) or not raw_profiles:
        raise ValueError("Compatibility profile file requires at least one profile.")

    profiles: list[CompatibilityProfile] = []
    seen_ids: set[str] = set()
    for raw_profile in raw_profiles:
        profile = _parse_profile(raw_profile)
        profile_key = profile.profile_id.casefold()
        if profile_key in seen_ids:
            raise ValueError(f"Duplicate compatibility profile id: {profile.profile_id}")
        seen_ids.add(profile_key)
        profiles.append(profile)
    return tuple(profiles)


def compatibility_matches(
    domain: str,
    profiles: Sequence[CompatibilityProfile] | None = None,
) -> tuple[CompatibilityMatch, ...]:
    normalized = _normalize_domain(domain)
    if not normalized:
        return ()
    selected = tuple(profiles) if profiles is not None else load_compatibility_profiles()
    matches: list[CompatibilityMatch] = []
    for profile in selected:
        for exact in profile.exact_domains:
            if normalized == exact:
                matches.append(CompatibilityMatch(profile, exact, "exact"))
        for suffix in profile.suffix_domains:
            if normalized == suffix or normalized.endswith(f".{suffix}"):
                matches.append(CompatibilityMatch(profile, suffix, "suffix"))
    role_order = {ServiceRole.CORE: 0, ServiceRole.SHARED: 1, ServiceRole.OPTIONAL: 2}
    matches.sort(
        key=lambda item: (
            0 if item.match_type == "exact" else 1,
            role_order.get(item.profile.service_role, 3),
            -item.profile.min_breakage_risk,
            -len(item.matched_pattern),
            item.profile.profile_id.casefold(),
        )
    )
    return tuple(matches)


def compatibility_match_for_domain(
    domain: str,
    profiles: Sequence[CompatibilityProfile] | None = None,
) -> CompatibilityMatch | None:
    matches = compatibility_matches(domain, profiles)
    return matches[0] if matches else None


def apply_compatibility_profile(
    classification: Classification,
    profiles: Sequence[CompatibilityProfile] | None = None,
) -> Classification:
    match = compatibility_match_for_domain(classification.domain, profiles)
    if match is None:
        return apply_behavior_change_guard(classification)
    profile = match.profile
    service_role = _stronger_service_role(classification.service_role, profile.service_role)
    needs_review = classification.needs_review
    review_reason = classification.review_reason
    if profile.protection == "deny_requires_review" and classification.policy is Policy.DENY:
        needs_review = True
        compatibility_reason = (
            f"Protected compatibility profile '{profile.name}' matched "
            f"{match.matched_pattern}. {profile.reason}"
        )
        if review_reason:
            if compatibility_reason not in review_reason:
                review_reason = f"{review_reason} {compatibility_reason}"
        else:
            review_reason = compatibility_reason
    enriched = replace(
        classification,
        service=classification.service or profile.name,
        service_role=service_role,
        breakage_risk=max(classification.breakage_risk, profile.min_breakage_risk),
        needs_review=needs_review,
        review_reason=review_reason,
    )
    return apply_behavior_change_guard(enriched)


def compatibility_finding(
    domain: str,
    profiles: Sequence[CompatibilityProfile] | None = None,
    *,
    now: int | None = None,
) -> ResearchFinding | None:
    normalized = _normalize_domain(domain)
    match = compatibility_match_for_domain(normalized, profiles)
    if match is None:
        return None
    profile = match.profile
    retrieved_at = int(time.time()) if now is None else int(now)
    return ResearchFinding(
        domain=normalized,
        provider=COMPATIBILITY_PROVIDER_NAME,
        kind="compatibility_profile",
        title=f"Protected service: {profile.name}",
        summary=profile.reason,
        source_url=profile.source_url,
        confidence=1.0,
        signal_type="function",
        verdict=f"protected_{profile.service_role.value}_service",
        decision_relevant=True,
        retrieved_at=retrieved_at,
        expires_at=retrieved_at + 365 * 86400,
        raw_data={
            "wormhole_source_kind": "compatibility_profile",
            "profile_id": profile.profile_id,
            "service_role": profile.service_role.value,
            "min_breakage_risk": profile.min_breakage_risk,
            "protection": profile.protection,
            "matched_pattern": match.matched_pattern,
            "match_type": match.match_type,
        },
    )


def _parse_profile(raw_profile: object) -> CompatibilityProfile:
    if not isinstance(raw_profile, dict):
        raise ValueError("Each compatibility profile must be a JSON object.")
    profile_id = str(raw_profile.get("profile_id") or "").strip()
    name = str(raw_profile.get("name") or "").strip()
    description = str(raw_profile.get("description") or "").strip()
    reason = str(raw_profile.get("reason") or "").strip()
    protection = str(raw_profile.get("protection") or "deny_requires_review").strip()
    if not profile_id or not name or not reason:
        raise ValueError("Compatibility profiles require profile_id, name, and reason.")
    if protection not in {"deny_requires_review"}:
        raise ValueError(f"Unsupported compatibility protection mode: {protection}")
    try:
        service_role = ServiceRole(str(raw_profile.get("service_role") or "core"))
    except ValueError as exc:
        raise ValueError(f"Invalid service_role for compatibility profile {profile_id}") from exc
    if service_role not in {ServiceRole.CORE, ServiceRole.SHARED, ServiceRole.OPTIONAL}:
        raise ValueError(f"Unsupported service_role for compatibility profile {profile_id}")
    min_breakage_risk = _integer(raw_profile.get("min_breakage_risk", 80), "min_breakage_risk")
    if not 0 <= min_breakage_risk <= 100:
        raise ValueError("min_breakage_risk must be between 0 and 100.")
    exact_domains = _domains(raw_profile.get("exact_domains"))
    suffix_domains = _domains(raw_profile.get("suffix_domains"))
    if not exact_domains and not suffix_domains:
        raise ValueError(f"Compatibility profile {profile_id} requires at least one domain.")
    return CompatibilityProfile(
        profile_id=profile_id,
        name=name,
        description=description,
        service_role=service_role,
        min_breakage_risk=min_breakage_risk,
        protection=protection,
        exact_domains=exact_domains,
        suffix_domains=suffix_domains,
        reason=reason,
        source_url=str(raw_profile.get("source_url") or "").strip(),
    )


def _domains(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(
        dict.fromkeys(
            normalized
            for item in value
            if (normalized := _normalize_domain(item))
        )
    )


def _stronger_service_role(current: ServiceRole, profile: ServiceRole) -> ServiceRole:
    order = {
        ServiceRole.CORE: 3,
        ServiceRole.SHARED: 2,
        ServiceRole.OPTIONAL: 1,
        ServiceRole.UNKNOWN: 0,
    }
    return profile if order[profile] > order[current] else current


def _normalize_domain(value: object) -> str:
    return str(value or "").strip().lower().rstrip(".")


def _integer(value: object, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer.")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be an integer.") from exc
