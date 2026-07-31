from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from pihole_manager.config import LLMOptions, LLMProviderOptions, ProviderLimitOptions
from pihole_manager.models import ProviderUsage
from pihole_manager.provider_registry import (
    ProviderCapability,
    ProviderLimit,
    ProviderLimitProfile,
    load_provider_registry,
    resolve_provider_limit_profile,
)
from pihole_manager.quota import (
    QuotaEstimate,
    QuotaUnavailableError,
    batch_fits_context,
    complete_quota,
    quota_runtime_states,
    reserve_quota,
)


def _provider(*, provider_id: str = "provider-test") -> LLMProviderOptions:
    return LLMProviderOptions(
        provider_id=provider_id,
        name="Test provider",
        preset_id="custom",
        base_url="https://api.example/v1",
        api_key="shared-key",
        model="model-a",
        limits=ProviderLimitOptions(safety_margin_percent=0),
    )


def _profile(*limits: ProviderLimit) -> ProviderLimitProfile:
    return ProviderLimitProfile(
        source="test",
        limits=tuple(limits),
        safety_margin_percent=0,
    )


def test_request_quota_is_reserved_atomically(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    provider = _provider()
    profile = _profile(
        ProviderLimit(
            metric="requests",
            amount=4,
            window_seconds=60,
            source="test",
        )
    )
    options = LLMOptions(realtime_quota_reserve_percent=0)

    def reserve_once() -> bool:
        try:
            reserve_quota(
                provider,
                profile,
                QuotaEstimate(),
                pool_id="realtime",
                llm_options=options,
                now=1000,
            )
        except QuotaUnavailableError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=8) as executor:
        accepted = list(executor.map(lambda _index: reserve_once(), range(8)))

    assert accepted.count(True) == 4
    assert accepted.count(False) == 4


def test_background_pool_preserves_realtime_reserve(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    provider = _provider()
    profile = _profile(
        ProviderLimit(
            metric="requests",
            amount=10,
            window_seconds=60,
            source="test",
        )
    )
    options = LLMOptions(realtime_quota_reserve_percent=20)

    for _index in range(8):
        reserve_quota(
            provider,
            profile,
            QuotaEstimate(),
            pool_id="background",
            llm_options=options,
            now=1000,
        )

    with pytest.raises(QuotaUnavailableError):
        reserve_quota(
            provider,
            profile,
            QuotaEstimate(),
            pool_id="background",
            llm_options=options,
            now=1000,
        )
    reserve_quota(
        provider,
        profile,
        QuotaEstimate(),
        pool_id="realtime",
        llm_options=options,
        now=1000,
    )


def test_utc_day_quota_resets_at_midnight_instead_of_rolling(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    provider = _provider()
    profile = _profile(
        ProviderLimit(
            metric="requests",
            amount=1,
            window_seconds=86400,
            source="test",
            reset_policy="utc_day",
        )
    )
    options = LLMOptions(realtime_quota_reserve_percent=0)
    reserve_quota(
        provider,
        profile,
        QuotaEstimate(),
        pool_id="realtime",
        llm_options=options,
        now=86390,
    )

    with pytest.raises(QuotaUnavailableError) as error:
        reserve_quota(
            provider,
            profile,
            QuotaEstimate(),
            pool_id="realtime",
            llm_options=options,
            now=86395,
        )
    assert error.value.retry_at == 86400

    reserve_quota(
        provider,
        profile,
        QuotaEstimate(),
        pool_id="realtime",
        llm_options=options,
        now=86401,
    )


def test_actual_usage_reconciles_a_conservative_reservation(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    provider = _provider()
    profile = _profile(
        ProviderLimit(
            metric="total_tokens",
            amount=100,
            window_seconds=60,
            source="test",
        )
    )
    options = LLMOptions(realtime_quota_reserve_percent=0)
    first = reserve_quota(
        provider,
        profile,
        QuotaEstimate(input_tokens=40, output_tokens=40),
        pool_id="realtime",
        llm_options=options,
        now=1000,
    )

    complete_quota(
        first,
        usage=ProviderUsage(input_tokens=10, output_tokens=10, total_tokens=20),
        profile=profile,
        now=1001,
    )
    reserve_quota(
        provider,
        profile,
        QuotaEstimate(input_tokens=35, output_tokens=35),
        pool_id="realtime",
        llm_options=options,
        now=1002,
    )


def test_live_limit_replaces_a_stale_lower_registry_limit(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    provider = _provider()
    profile = _profile(
        ProviderLimit(
            metric="requests",
            amount=2,
            window_seconds=60,
            source="bundled_registry",
        )
    )
    options = LLMOptions(realtime_quota_reserve_percent=0)
    first = reserve_quota(
        provider,
        profile,
        QuotaEstimate(),
        pool_id="realtime",
        llm_options=options,
        now=1000,
    )
    complete_quota(
        first,
        usage=ProviderUsage(),
        profile=profile,
        response_headers={
            "x-ratelimit-limit-requests": "10",
            "x-ratelimit-remaining-requests": "9",
            "x-ratelimit-reset-requests": "60s",
        },
        now=1001,
    )

    reserve_quota(
        provider,
        profile,
        QuotaEstimate(),
        pool_id="realtime",
        llm_options=options,
        now=1002,
    )
    reserve_quota(
        provider,
        profile,
        QuotaEstimate(),
        pool_id="realtime",
        llm_options=options,
        now=1002,
    )


def test_user_cap_remains_stricter_than_live_limit(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    provider = _provider()
    profile = _profile(
        ProviderLimit(
            metric="requests",
            amount=2,
            window_seconds=60,
            source="bundled_registry",
            user_cap=2,
        )
    )
    options = LLMOptions(realtime_quota_reserve_percent=0)
    first = reserve_quota(
        provider,
        profile,
        QuotaEstimate(),
        pool_id="realtime",
        llm_options=options,
        now=1000,
    )
    complete_quota(
        first,
        usage=ProviderUsage(),
        profile=profile,
        response_headers={
            "x-ratelimit-limit-requests": "10",
            "x-ratelimit-remaining-requests": "9",
            "x-ratelimit-reset-requests": "60s",
        },
        now=1001,
    )
    reserve_quota(
        provider,
        profile,
        QuotaEstimate(),
        pool_id="realtime",
        llm_options=options,
        now=1002,
    )

    with pytest.raises(QuotaUnavailableError):
        reserve_quota(
            provider,
            profile,
            QuotaEstimate(),
            pool_id="realtime",
            llm_options=options,
            now=1002,
        )


def test_empty_manual_profile_does_not_add_unknown_provider_limits(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    provider = _provider()
    profile = ProviderLimitProfile(source="user", safety_margin_percent=0)
    options = LLMOptions(realtime_quota_reserve_percent=0)

    for _index in range(5):
        reserve_quota(
            provider,
            profile,
            QuotaEstimate(),
            pool_id="realtime",
            llm_options=options,
            now=1000,
        )


def test_live_headers_override_the_bundled_remaining_quota(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    provider = LLMProviderOptions(
        provider_id="provider-groq",
        preset_id="groq",
        base_url="https://api.groq.com/openai/v1",
        api_key="key",
        model="openai/gpt-oss-120b",
        limits=ProviderLimitOptions(safety_margin_percent=0),
    )
    profile = resolve_provider_limit_profile(
        provider,
        registry=load_provider_registry(prefer_cached=False),
    )
    options = LLMOptions(realtime_quota_reserve_percent=0)
    first = reserve_quota(
        provider,
        profile,
        QuotaEstimate(input_tokens=10, output_tokens=10),
        pool_id="realtime",
        llm_options=options,
        now=1000,
    )
    complete_quota(
        first,
        usage=ProviderUsage(input_tokens=10, output_tokens=10, total_tokens=20),
        profile=profile,
        response_headers={
            "x-ratelimit-limit-requests": "1000",
            "x-ratelimit-remaining-requests": "0",
            "x-ratelimit-reset-requests": "20s",
        },
        now=1001,
    )

    with pytest.raises(QuotaUnavailableError) as error:
        reserve_quota(
            provider,
            profile,
            QuotaEstimate(),
            pool_id="realtime",
            llm_options=options,
            now=1002,
        )

    assert error.value.retry_at == 1021
    states = quota_runtime_states(first.scope_key, now=1002)
    assert states[0].remaining_amount == 0
    assert states[0].window_seconds == 86400


def test_context_guard_accounts_for_input_and_expected_output() -> None:
    provider = _provider()
    provider.limits.context_tokens = 1000
    profile = ProviderLimitProfile(
        source="test",
        capability=ProviderCapability(context_tokens=2000),
        safety_margin_percent=10,
    )

    assert batch_fits_context(
        QuotaEstimate(input_tokens=400, output_tokens=450),
        provider=provider,
        profile=profile,
    )
    assert not batch_fits_context(
        QuotaEstimate(input_tokens=500, output_tokens=450),
        provider=provider,
        profile=profile,
    )
