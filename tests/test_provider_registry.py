from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pihole_manager.config import LLMProviderOptions, Options, ProviderLimitOptions
from pihole_manager.provider_registry import (
    ProviderRegistryError,
    ProviderRegistrySignatureError,
    load_provider_registry,
    parse_provider_registry,
    refresh_provider_registry_if_due,
    resolve_provider_limit_profile,
    verify_registry_signature,
)
from scripts.provider_registry import _generate_key


def _groq_provider(*, limits: ProviderLimitOptions | None = None) -> LLMProviderOptions:
    return LLMProviderOptions(
        preset_id="groq",
        base_url="https://api.groq.com/openai/v1",
        model="openai/gpt-oss-120b",
        limits=limits or ProviderLimitOptions(),
    )


def test_bundled_registry_resolves_current_groq_free_limits() -> None:
    registry = load_provider_registry(prefer_cached=False)

    profile = resolve_provider_limit_profile(_groq_provider(), registry=registry)

    limits = {(limit.metric, limit.window_seconds): limit.amount for limit in profile.limits}
    assert profile.entry_id == "groq-gpt-oss-120b-free"
    assert profile.source == "bundled_registry"
    assert profile.free_tier == "ongoing"
    assert limits[("requests", 60)] == 30
    assert limits[("requests", 86400)] == 1000
    assert limits[("total_tokens", 60)] == 8000
    assert limits[("total_tokens", 86400)] == 200000


def test_auto_with_own_caps_never_raises_registry_limits() -> None:
    provider = _groq_provider(
        limits=ProviderLimitOptions(
            mode="auto_cap",
            requests_per_minute=7,
            requests_per_day=1500,
            tokens_per_minute=5000,
        )
    )

    profile = resolve_provider_limit_profile(
        provider,
        registry=load_provider_registry(prefer_cached=False),
    )

    limits = {(limit.metric, limit.window_seconds): limit.amount for limit in profile.limits}
    assert profile.source == "user_cap+bundled_registry"
    assert limits[("requests", 60)] == 7
    assert limits[("requests", 86400)] == 1000
    assert limits[("total_tokens", 60)] == 5000


def test_manual_limits_do_not_inherit_registry_values() -> None:
    provider = _groq_provider(
        limits=ProviderLimitOptions(
            mode="manual",
            requests_per_hour=12,
            tokens_per_day=3456,
        )
    )

    profile = resolve_provider_limit_profile(
        provider,
        registry=load_provider_registry(prefer_cached=False),
    )

    assert profile.source == "user"
    assert {(limit.metric, limit.window_seconds, limit.amount) for limit in profile.limits} == {
        ("requests", 3600, 12),
        ("total_tokens", 86400, 3456),
    }


def test_registry_signature_accepts_exact_payload_and_rejects_tampering() -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    payload = json.dumps({"schema_version": 1}, separators=(",", ":")).encode()
    signature = base64.b64encode(private_key.sign(payload))

    verify_registry_signature(payload, signature, public_key)

    with pytest.raises(
        ProviderRegistrySignatureError,
        match="verification failed",
    ):
        verify_registry_signature(payload + b" ", signature, public_key)


def test_registry_signature_json_envelope_is_supported() -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    payload = b'{"schema_version":1}'
    signature = json.dumps(
        {
            "algorithm": "ed25519",
            "signature": base64.b64encode(private_key.sign(payload)).decode(),
        }
    ).encode()

    verify_registry_signature(payload, signature, public_key)


def test_registry_rejects_non_sortable_versions() -> None:
    payload = json.dumps(
        {
            "schema_version": 1,
            "registry_version": "2026.7.31",
            "generated_at": "2026-07-31T00:00:00Z",
            "entries": [],
        }
    ).encode()

    with pytest.raises(ProviderRegistryError, match="YYYY.MM.DD"):
        parse_provider_registry(payload)


def test_key_generator_replaces_only_the_bundled_placeholder(tmp_path) -> None:
    private_path = tmp_path / "registry-private.pem"
    public_path = tmp_path / "provider_registry_public_key.pem"
    public_path.write_text(
        "# Remote registry updates remain disabled until a reviewed Ed25519 public key "
        "is installed.\n",
        encoding="utf-8",
    )

    assert _generate_key(private_path, public_path) == 0

    assert private_path.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")
    assert public_path.read_bytes().startswith(b"-----BEGIN PUBLIC KEY-----")

    with pytest.raises(FileExistsError, match="Refusing to overwrite"):
        _generate_key(private_path, public_path)


def test_registry_refresh_runs_only_when_enabled_and_due(monkeypatch) -> None:
    options = Options()
    options.provider_registry.auto_update = True
    options.provider_registry.refresh_interval_hours = 24
    options.provider_registry.last_checked_at = 0
    registry = load_provider_registry(prefer_cached=False)
    saved: list[Options] = []

    monkeypatch.setattr(
        "pihole_manager.provider_registry.refresh_provider_registry",
        lambda *_args, **_kwargs: registry,
    )
    monkeypatch.setattr(
        "pihole_manager.provider_registry.load_options",
        lambda: options,
    )
    monkeypatch.setattr(
        "pihole_manager.provider_registry.save_options",
        saved.append,
    )

    assert refresh_provider_registry_if_due(options, now=100000) is registry
    assert saved[0].provider_registry.last_checked_at == 100000
    assert refresh_provider_registry_if_due(options, now=100001) is None

    options.provider_registry.auto_update = False
    options.provider_registry.last_checked_at = 0
    assert refresh_provider_registry_if_due(options, now=200000) is None


def test_registry_refresh_failure_is_still_rate_limited(monkeypatch) -> None:
    options = Options()
    options.provider_registry.auto_update = True
    options.provider_registry.refresh_interval_hours = 1
    options.provider_registry.last_checked_at = 0
    saved: list[Options] = []

    def fail_refresh(*_args, **_kwargs):
        raise OSError("offline")

    monkeypatch.setattr(
        "pihole_manager.provider_registry.refresh_provider_registry",
        fail_refresh,
    )
    monkeypatch.setattr(
        "pihole_manager.provider_registry.load_options",
        lambda: options,
    )
    monkeypatch.setattr(
        "pihole_manager.provider_registry.save_options",
        saved.append,
    )

    with pytest.raises(OSError, match="offline"):
        refresh_provider_registry_if_due(options, now=100000)

    assert saved[0].provider_registry.last_checked_at == 100000
