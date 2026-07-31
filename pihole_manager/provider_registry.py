from __future__ import annotations

import base64
import fnmatch
import json
import logging
import os
import tempfile
import time
from dataclasses import dataclass, field, replace
from datetime import date
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

from pihole_manager.config import (
    LLMProviderOptions,
    Options,
    ProviderLimitOptions,
    app_directory,
    load_options,
    save_options,
)

log = logging.getLogger(__name__)

_ALLOWED_METRICS = {
    "requests",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "units",
}
_MAX_REGISTRY_BYTES = 2_000_000


class ProviderRegistryError(RuntimeError):
    pass


class ProviderRegistrySignatureError(ProviderRegistryError):
    pass


@dataclass(frozen=True, slots=True)
class ProviderCapability:
    context_tokens: int = 0
    max_output_tokens: int = 0
    structured_output: str = "auto"
    native_browsing: bool = False
    local: bool = False
    deprecated: bool = False


@dataclass(frozen=True, slots=True)
class ProviderLimit:
    metric: str
    amount: float
    window_seconds: int
    scope: str = "provider_model"
    source: str = "bundled_registry"
    user_cap: float = 0.0
    reset_policy: str = "rolling"


@dataclass(frozen=True, slots=True)
class ProviderLimitProfile:
    entry_id: str = ""
    source: str = "unknown"
    free_tier: str = "unknown"
    free_tier_note: str = ""
    source_url: str = ""
    capability: ProviderCapability = field(default_factory=ProviderCapability)
    limits: tuple[ProviderLimit, ...] = ()
    input_units_per_million_tokens: float = 0.0
    output_units_per_million_tokens: float = 0.0
    max_domains_per_request: int = 0
    safety_margin_percent: float = 10.0
    quota_group: str = ""


@dataclass(frozen=True, slots=True)
class ProviderRegistry:
    schema_version: int
    registry_version: str
    generated_at: str
    entries: tuple[dict[str, Any], ...]
    source: str


def bundled_registry_path() -> Path:
    return Path(str(files("pihole_manager").joinpath("data/provider_registry.json")))


def registry_public_key_path() -> Path:
    return Path(str(files("pihole_manager").joinpath("data/provider_registry_public_key.pem")))


def cached_registry_path() -> Path:
    return app_directory() / "provider_registry.json"


def cached_registry_signature_path() -> Path:
    return app_directory() / "provider_registry.json.sig"


def parse_provider_registry(
    payload: bytes,
    *,
    source: str = "review",
) -> ProviderRegistry:
    return _parse_registry(payload, source=source)


def load_provider_registry(
    *,
    prefer_cached: bool = True,
    public_key_pem: bytes | None = None,
) -> ProviderRegistry:
    bundled = _parse_registry(
        bundled_registry_path().read_bytes(),
        source="bundled_registry",
    )
    if not prefer_cached:
        return bundled

    registry_path = cached_registry_path()
    signature_path = cached_registry_signature_path()
    if not registry_path.exists() or not signature_path.exists():
        return bundled
    key = public_key_pem or _load_public_key()
    if key is None:
        return bundled
    try:
        payload = registry_path.read_bytes()
        signature = signature_path.read_bytes()
        verify_registry_signature(payload, signature, key)
        cached = _parse_registry(payload, source="online_registry")
    except (OSError, ProviderRegistryError) as exc:
        log.warning("Ignoring invalid cached provider registry: %s", exc)
        return bundled
    if _registry_version_key(cached.registry_version) < _registry_version_key(
        bundled.registry_version
    ):
        return bundled
    return cached


def refresh_provider_registry(
    registry_url: str,
    signature_url: str,
    *,
    public_key_pem: bytes | None = None,
    timeout_sec: float = 15.0,
) -> ProviderRegistry:
    key = public_key_pem or _load_public_key()
    if key is None:
        raise ProviderRegistrySignatureError(
            "Remote provider registry updates require a reviewed Ed25519 public key."
        )
    _require_https_url(registry_url)
    _require_https_url(signature_url)
    registry_response = requests.get(registry_url, timeout=max(1.0, timeout_sec))
    registry_response.raise_for_status()
    signature_response = requests.get(signature_url, timeout=max(1.0, timeout_sec))
    signature_response.raise_for_status()
    payload = bytes(registry_response.content)
    signature = bytes(signature_response.content)
    if len(payload) > _MAX_REGISTRY_BYTES:
        raise ProviderRegistryError("Provider registry exceeds the maximum allowed size.")
    verify_registry_signature(payload, signature, key)
    registry = _parse_registry(payload, source="online_registry")
    current = load_provider_registry(prefer_cached=True, public_key_pem=key)
    if _registry_version_key(registry.registry_version) < _registry_version_key(
        current.registry_version
    ):
        raise ProviderRegistryError("Provider registry downgrade was rejected.")
    _atomic_write(cached_registry_path(), payload)
    _atomic_write(cached_registry_signature_path(), signature)
    return registry


def refresh_provider_registry_if_due(
    options: Options | None = None,
    *,
    now: float | None = None,
) -> ProviderRegistry | None:
    selected_options = options or load_options()
    settings = selected_options.provider_registry
    if not settings.auto_update:
        return None
    current_time = time.time() if now is None else float(now)
    interval = max(1, int(settings.refresh_interval_hours)) * 3600
    if current_time - max(0, int(settings.last_checked_at)) < interval:
        return None
    latest_options = load_options()
    latest_options.provider_registry.last_checked_at = int(current_time)
    save_options(latest_options)
    return refresh_provider_registry(
        settings.registry_url,
        settings.signature_url,
    )


def verify_registry_signature(
    payload: bytes,
    signature_payload: bytes,
    public_key_pem: bytes,
) -> None:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise ProviderRegistrySignatureError(
            "The cryptography package is required for registry verification."
        ) from exc

    signature = _decode_signature(signature_payload)
    try:
        key = serialization.load_pem_public_key(public_key_pem)
    except (TypeError, ValueError) as exc:
        raise ProviderRegistrySignatureError("Provider registry public key is invalid.") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ProviderRegistrySignatureError("Provider registry key is not Ed25519.")
    try:
        key.verify(signature, payload)
    except InvalidSignature as exc:
        raise ProviderRegistrySignatureError(
            "Provider registry signature verification failed."
        ) from exc


def resolve_provider_limit_profile(
    provider: LLMProviderOptions,
    *,
    registry: ProviderRegistry | None = None,
) -> ProviderLimitProfile:
    selected_registry = registry or load_provider_registry()
    registry_profile = _profile_from_registry(provider, selected_registry)
    limits = provider.limits
    if limits.mode == "manual":
        return _manual_profile(provider, source="user")
    if limits.mode == "auto_cap":
        return _apply_user_caps(registry_profile, provider)
    return ProviderLimitProfile(
        entry_id=registry_profile.entry_id,
        source=registry_profile.source,
        free_tier=registry_profile.free_tier,
        free_tier_note=registry_profile.free_tier_note,
        source_url=registry_profile.source_url,
        capability=registry_profile.capability,
        limits=registry_profile.limits,
        input_units_per_million_tokens=registry_profile.input_units_per_million_tokens,
        output_units_per_million_tokens=registry_profile.output_units_per_million_tokens,
        max_domains_per_request=registry_profile.max_domains_per_request,
        safety_margin_percent=limits.safety_margin_percent,
        quota_group=limits.quota_group or registry_profile.quota_group,
    )


def _profile_from_registry(
    provider: LLMProviderOptions,
    registry: ProviderRegistry,
) -> ProviderLimitProfile:
    if _is_local_provider(provider):
        capability = ProviderCapability(
            context_tokens=max(0, int(provider.limits.context_tokens)),
            max_output_tokens=max(1, int(provider.max_output_tokens)),
            structured_output=provider.structured_output,
            local=True,
        )
        return ProviderLimitProfile(
            source="local",
            capability=capability,
            max_domains_per_request=max(0, int(provider.limits.max_domains_per_request)),
            safety_margin_percent=provider.limits.safety_margin_percent,
            quota_group=provider.limits.quota_group,
        )

    matches = [
        (score, entry)
        for entry in registry.entries
        if (score := _entry_match_score(entry, provider)) > 0
    ]
    if not matches:
        return ProviderLimitProfile(
            source="unknown",
            capability=ProviderCapability(
                context_tokens=max(0, int(provider.limits.context_tokens)),
                max_output_tokens=max(1, int(provider.max_output_tokens)),
                structured_output=provider.structured_output,
            ),
            max_domains_per_request=max(0, int(provider.limits.max_domains_per_request)),
            safety_margin_percent=provider.limits.safety_margin_percent,
            quota_group=provider.limits.quota_group,
        )
    _, entry = max(matches, key=lambda item: item[0])
    capabilities = dict(entry.get("capabilities") or {})
    unit_costs = dict(entry.get("unit_costs") or {})
    capability = ProviderCapability(
        context_tokens=max(0, int(capabilities.get("context_tokens") or 0)),
        max_output_tokens=max(0, int(capabilities.get("max_output_tokens") or 0)),
        structured_output=str(capabilities.get("structured_output") or "auto"),
        native_browsing=bool(capabilities.get("native_browsing")),
        local=bool(capabilities.get("local")),
        deprecated=bool(capabilities.get("deprecated")),
    )
    parsed_limits = tuple(
        ProviderLimit(
            metric=str(item["metric"]),
            amount=float(item["amount"]),
            window_seconds=int(item["window_seconds"]),
            scope=str(item.get("scope") or "provider_model"),
            source=registry.source,
            reset_policy=str(item.get("reset_policy") or "rolling"),
        )
        for item in entry.get("limits") or []
    )
    return ProviderLimitProfile(
        entry_id=str(entry.get("entry_id") or ""),
        source=registry.source,
        free_tier=str(entry.get("free_tier") or "unknown"),
        free_tier_note=str(entry.get("free_tier_note") or ""),
        source_url=str(entry.get("source_url") or ""),
        capability=capability,
        limits=parsed_limits,
        input_units_per_million_tokens=max(
            0.0,
            float(unit_costs.get("input_tokens_per_million") or 0),
        ),
        output_units_per_million_tokens=max(
            0.0,
            float(unit_costs.get("output_tokens_per_million") or 0),
        ),
        max_domains_per_request=max(
            0,
            int(provider.limits.max_domains_per_request),
        ),
        safety_margin_percent=provider.limits.safety_margin_percent,
        quota_group=(provider.limits.quota_group or str(entry.get("quota_group") or "").strip()),
    )


def _manual_profile(provider: LLMProviderOptions, *, source: str) -> ProviderLimitProfile:
    configured = provider.limits
    return ProviderLimitProfile(
        source=source,
        capability=ProviderCapability(
            context_tokens=max(0, int(configured.context_tokens)),
            max_output_tokens=max(1, int(provider.max_output_tokens)),
            structured_output=provider.structured_output,
            local=_is_local_provider(provider),
        ),
        limits=tuple(_configured_limits(configured, source=source)),
        max_domains_per_request=max(0, int(configured.max_domains_per_request)),
        safety_margin_percent=configured.safety_margin_percent,
        quota_group=configured.quota_group,
    )


def _apply_user_caps(
    base: ProviderLimitProfile,
    provider: LLMProviderOptions,
) -> ProviderLimitProfile:
    manual = _manual_profile(provider, source="user")
    combined: dict[tuple[str, int], ProviderLimit] = {
        (limit.metric, limit.window_seconds): limit for limit in base.limits
    }
    for limit in manual.limits:
        key = (limit.metric, limit.window_seconds)
        existing = combined.get(key)
        if existing is None:
            combined[key] = replace(
                limit,
                source="user_cap",
                user_cap=limit.amount,
            )
        else:
            combined[key] = replace(
                existing,
                amount=min(existing.amount, limit.amount),
                user_cap=limit.amount,
            )
    context_tokens = _minimum_positive(
        base.capability.context_tokens,
        provider.limits.context_tokens,
    )
    max_domains = _minimum_positive(
        base.max_domains_per_request,
        provider.limits.max_domains_per_request,
    )
    return ProviderLimitProfile(
        entry_id=base.entry_id,
        source="user_cap+" + base.source,
        free_tier=base.free_tier,
        free_tier_note=base.free_tier_note,
        source_url=base.source_url,
        capability=ProviderCapability(
            context_tokens=context_tokens,
            max_output_tokens=base.capability.max_output_tokens,
            structured_output=base.capability.structured_output,
            native_browsing=base.capability.native_browsing,
            local=base.capability.local,
            deprecated=base.capability.deprecated,
        ),
        limits=tuple(
            sorted(
                combined.values(),
                key=lambda item: (item.metric, item.window_seconds),
            )
        ),
        input_units_per_million_tokens=base.input_units_per_million_tokens,
        output_units_per_million_tokens=base.output_units_per_million_tokens,
        max_domains_per_request=max_domains,
        safety_margin_percent=provider.limits.safety_margin_percent,
        quota_group=provider.limits.quota_group or base.quota_group,
    )


def _configured_limits(
    configured: ProviderLimitOptions,
    *,
    source: str,
) -> list[ProviderLimit]:
    fields = (
        ("requests", configured.requests_per_minute, 60),
        ("requests", configured.requests_per_hour, 3600),
        ("requests", configured.requests_per_day, 86400),
        ("input_tokens", configured.input_tokens_per_minute, 60),
        ("output_tokens", configured.output_tokens_per_minute, 60),
        ("total_tokens", configured.tokens_per_minute, 60),
        ("total_tokens", configured.tokens_per_hour, 3600),
        ("total_tokens", configured.tokens_per_day, 86400),
        ("units", configured.units_per_day, 86400),
    )
    return [
        ProviderLimit(
            metric=metric,
            amount=float(amount),
            window_seconds=window,
            scope="configured",
            source=source,
        )
        for metric, amount, window in fields
        if float(amount) > 0
    ]


def _entry_match_score(entry: dict[str, Any], provider: LLMProviderOptions) -> int:
    preset_ids = {str(item).strip().lower() for item in entry.get("preset_ids") or []}
    hosts = {str(item).strip().lower() for item in entry.get("base_url_hosts") or []}
    provider_host = (urlparse(provider.base_url).hostname or "").lower()
    identity_score = 0
    if provider.preset_id.strip().lower() in preset_ids:
        identity_score = 4
    elif provider_host and provider_host in hosts:
        identity_score = 2
    if identity_score == 0:
        return 0

    model = provider.model.strip().lower()
    model_score = 0
    for pattern_value in entry.get("models") or []:
        pattern = str(pattern_value).strip().lower()
        if not pattern:
            continue
        if pattern == model:
            model_score = max(model_score, 4)
        elif model and fnmatch.fnmatchcase(model, pattern):
            model_score = max(model_score, 1)
    return identity_score + model_score if model_score else 0


def _parse_registry(payload: bytes, *, source: str) -> ProviderRegistry:
    if len(payload) > _MAX_REGISTRY_BYTES:
        raise ProviderRegistryError("Provider registry exceeds the maximum allowed size.")
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProviderRegistryError("Provider registry is not valid UTF-8 JSON.") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ProviderRegistryError("Unsupported provider registry schema.")
    registry_version = str(data.get("registry_version") or "").strip()
    generated_at = str(data.get("generated_at") or "").strip()
    entries = data.get("entries")
    if not registry_version or not generated_at or not isinstance(entries, list):
        raise ProviderRegistryError("Provider registry metadata is incomplete.")
    _registry_version_key(registry_version)

    normalized_entries: list[dict[str, Any]] = []
    entry_ids: set[str] = set()
    for raw_entry in entries:
        if not isinstance(raw_entry, dict):
            raise ProviderRegistryError("Provider registry entry is not an object.")
        entry = dict(raw_entry)
        entry_id = str(entry.get("entry_id") or "").strip()
        if not entry_id or entry_id in entry_ids:
            raise ProviderRegistryError("Provider registry entry IDs must be unique.")
        entry_ids.add(entry_id)
        for limit in entry.get("limits") or []:
            if not isinstance(limit, dict):
                raise ProviderRegistryError(f"Invalid limit in registry entry {entry_id}.")
            metric = str(limit.get("metric") or "")
            try:
                amount = float(limit.get("amount") or 0)
                window = int(limit.get("window_seconds") or 0)
            except (TypeError, ValueError) as exc:
                raise ProviderRegistryError(
                    f"Invalid limit value in registry entry {entry_id}."
                ) from exc
            if metric not in _ALLOWED_METRICS or amount <= 0 or window <= 0:
                raise ProviderRegistryError(
                    f"Invalid limit definition in registry entry {entry_id}."
                )
            if str(limit.get("reset_policy") or "rolling") not in {
                "rolling",
                "utc_day",
            }:
                raise ProviderRegistryError(f"Invalid reset policy in registry entry {entry_id}.")
        normalized_entries.append(entry)
    return ProviderRegistry(
        schema_version=1,
        registry_version=registry_version,
        generated_at=generated_at,
        entries=tuple(normalized_entries),
        source=source,
    )


def _decode_signature(payload: bytes) -> bytes:
    stripped = payload.strip()
    try:
        decoded = json.loads(stripped.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        decoded = None
    if isinstance(decoded, dict):
        if str(decoded.get("algorithm") or "").lower() != "ed25519":
            raise ProviderRegistrySignatureError("Unsupported registry signature algorithm.")
        stripped = str(decoded.get("signature") or "").encode("ascii")
    try:
        signature = base64.b64decode(stripped, validate=True)
    except (ValueError, UnicodeError) as exc:
        raise ProviderRegistrySignatureError("Provider registry signature is invalid.") from exc
    if len(signature) != 64:
        raise ProviderRegistrySignatureError("Provider registry signature has an invalid length.")
    return signature


def _registry_version_key(value: str) -> tuple[int, ...]:
    parts = value.split(".")
    if (
        len(parts) not in {3, 4}
        or [len(part) for part in parts[:3]] != [4, 2, 2]
        or any(not part.isdigit() for part in parts)
    ):
        raise ProviderRegistryError("Provider registry version must use YYYY.MM.DD[.revision].")
    year, month, day = (int(part) for part in parts[:3])
    try:
        date(year, month, day)
    except ValueError as exc:
        raise ProviderRegistryError("Provider registry version contains an invalid date.") from exc
    revision = int(parts[3]) if len(parts) == 4 else 0
    return year, month, day, revision


def _load_public_key() -> bytes | None:
    configured = os.environ.get("PIHOLE_MANAGER_PROVIDER_REGISTRY_PUBLIC_KEY", "").strip()
    if configured:
        return configured.replace("\\n", "\n").encode("utf-8")
    try:
        payload = registry_public_key_path().read_bytes().strip()
    except OSError:
        return None
    return payload if payload.startswith(b"-----BEGIN PUBLIC KEY-----") else None


def _require_https_url(value: str) -> None:
    parsed = urlparse(value)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ProviderRegistryError("Provider registry URLs must use HTTPS.")


def _is_local_provider(provider: LLMProviderOptions) -> bool:
    host = (urlparse(provider.base_url).hostname or "").lower()
    return host in {"localhost", "127.0.0.1", "::1"}


def _minimum_positive(first: int, second: int) -> int:
    values = [int(value) for value in (first, second) if int(value) > 0]
    return min(values) if values else 0


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=path.parent, delete=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            temp_path = Path(handle.name)
        os.replace(temp_path, path)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
