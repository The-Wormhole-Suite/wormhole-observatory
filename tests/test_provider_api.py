from __future__ import annotations

import threading
import time
from typing import Any

import pytest
import requests

from pihole_manager.cancellation import CancellationToken, OperationCancelledError
from pihole_manager.config import LLMOptions, LLMProviderOptions
from pihole_manager.http_retry import retry_delay_from_headers
from pihole_manager.provider_api import (
    ProviderRequestContext,
    chat_url,
    list_provider_models,
    models_url,
    request_provider,
    request_provider_text,
)
from pihole_manager.provider_presets import provider_presets
from pihole_manager.provider_registry import ProviderLimit, ProviderLimitProfile
from pihole_manager.quota import QuotaEstimate, QuotaUnavailableError


class _Response:
    def __init__(
        self,
        payload: dict[str, Any],
        *,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        reason: str = "",
    ) -> None:
        self.payload = payload
        self.status_code = status_code
        self.headers = headers or {}
        self.reason = reason

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            response = requests.Response()
            response.status_code = self.status_code
            response.headers.update(self.headers)
            response.reason = self.reason
            response._content = b"{}"
            raise requests.HTTPError(
                f"{self.status_code} {self.reason}".strip(),
                response=response,
            )

    def json(self) -> dict[str, Any]:
        return self.payload


def test_provider_presets_have_unique_ids_and_urls() -> None:
    presets = provider_presets()
    assert len(presets) >= 23
    assert len({item.preset_id for item in presets}) == len(presets)
    assert all(item.base_url.startswith(("http://", "https://")) for item in presets)
    assert list(presets) == sorted(presets, key=lambda item: item.name.casefold())
    assert any(item.preset_id == "anthropic" for item in presets)
    assert any(item.preset_id == "ollama" for item in presets)
    free_ids = {
        "cerebras_free_gpt_oss",
        "groq_free_gpt_oss",
        "openrouter_free",
    }
    assert free_ids.issubset({item.preset_id for item in presets})
    assert all(
        item.recommended_min_request_interval_sec for item in presets if item.preset_id in free_ids
    )


def test_retry_delay_parses_provider_headers() -> None:
    assert retry_delay_from_headers({"Retry-After": "7"}) == 7
    assert retry_delay_from_headers({"X-RateLimit-Reset-After": "1m30s"}) == 90
    assert (
        retry_delay_from_headers(
            {
                "Retry-After": "3",
                "X-RateLimit-Reset-Requests": "7",
                "X-RateLimit-Reset-Tokens": "11",
            }
        )
        == 11
    )
    assert (
        retry_delay_from_headers(
            {"X-RateLimit-Reset": "2000"},
            wall_time=1_990,
        )
        == 10
    )


def test_openai_compatible_urls() -> None:
    provider = LLMProviderOptions(base_url="https://api.example/v1")
    assert chat_url(provider) == "https://api.example/v1/chat/completions"
    assert models_url(provider) == "https://api.example/v1/models"


def test_provider_rate_wait_is_cooperatively_cancelled_before_http(monkeypatch) -> None:
    from pihole_manager import provider_api
    from pihole_manager.config import Options

    provider_api._RATE_STATES.clear()
    options = Options()
    options.llm.min_request_interval_sec = 0
    options.llm.max_retries = 0
    monkeypatch.setattr(provider_api, "load_options", lambda: options)
    called = threading.Event()

    def unexpected_post(*_args, **_kwargs):
        called.set()
        raise AssertionError("HTTP must not start after cancellation")

    monkeypatch.setattr(provider_api.requests, "post", unexpected_post)
    provider = LLMProviderOptions(
        provider_id="cancel-wait",
        base_url="https://api.example/v1",
        model="test",
    )
    provider_api._RATE_STATES[provider_api._provider_key(provider)] = (
        provider_api._ProviderRateState(next_request_at=time.monotonic() + 30)
    )
    wait_started = threading.Event()

    class ObservedToken(CancellationToken):
        def wait(self, timeout: float) -> bool:
            wait_started.set()
            return super().wait(timeout)

    token = ObservedToken()
    errors: list[BaseException] = []

    def run() -> None:
        try:
            request_provider_text(
                provider,
                [{"role": "user", "content": "Classify"}],
                cancel_token=token,
            )
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=run)
    thread.start()
    assert wait_started.wait(1)
    token.cancel()
    thread.join(2)

    assert not thread.is_alive()
    assert not called.is_set()
    assert len(errors) == 1
    assert isinstance(errors[0], OperationCancelledError)


def test_anthropic_urls() -> None:
    provider = LLMProviderOptions(
        api_style="anthropic_messages",
        base_url="https://api.anthropic.com/v1",
    )
    assert chat_url(provider) == "https://api.anthropic.com/v1/messages"
    assert models_url(provider) == "https://api.anthropic.com/v1/models"


def test_model_listing_uses_live_provider_response(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    def fake_get(url: str, **kwargs: Any) -> _Response:
        captured["url"] = url
        captured["headers"] = kwargs["headers"]
        return _Response({"data": [{"id": "model-b"}, {"id": "model-a"}]})

    monkeypatch.setattr("pihole_manager.provider_api.requests.get", fake_get)
    provider = LLMProviderOptions(
        base_url="https://api.example/v1",
        api_key="secret",
    )

    assert list_provider_models(provider) == ["model-a", "model-b"]
    assert captured["url"] == "https://api.example/v1/models"
    assert captured["headers"]["Authorization"] == "Bearer secret"


def test_anthropic_request_uses_messages_api(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    def fake_post(url: str, **kwargs: Any) -> _Response:
        captured["url"] = url
        captured["headers"] = kwargs["headers"]
        captured["json"] = kwargs["json"]
        return _Response({"content": [{"type": "text", "text": '{"ok":true}'}]})

    monkeypatch.setattr("pihole_manager.provider_api.requests.post", fake_post)
    provider = LLMProviderOptions(
        api_style="anthropic_messages",
        base_url="https://api.anthropic.com/v1",
        api_key="secret",
        model="claude-test",
        max_output_tokens=1234,
    )
    text = request_provider_text(
        provider,
        [
            {"role": "system", "content": "System contract"},
            {"role": "user", "content": "Classify"},
        ],
    )

    assert text == '{"ok":true}'
    assert captured["url"] == "https://api.anthropic.com/v1/messages"
    assert captured["headers"]["x-api-key"] == "secret"
    assert captured["json"]["system"] == "System contract"
    assert captured["json"]["max_tokens"] == 1234


def test_openai_request_respects_token_and_temperature_settings(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    def fake_post(url: str, **kwargs: Any) -> _Response:
        captured["url"] = url
        captured["json"] = kwargs["json"]
        return _Response({"choices": [{"message": {"content": "ok"}}]})

    monkeypatch.setattr("pihole_manager.provider_api.requests.post", fake_post)
    provider = LLMProviderOptions(
        base_url="https://api.example/v1",
        model="example-model",
        max_output_tokens=777,
        max_tokens_parameter="max_completion_tokens",
        send_temperature=False,
    )

    assert (
        request_provider_text(
            provider,
            [{"role": "user", "content": "Classify"}],
        )
        == "ok"
    )
    assert captured["json"]["max_completion_tokens"] == 777
    assert "max_tokens" not in captured["json"]
    assert "temperature" not in captured["json"]


def test_provider_request_reserves_quota_before_http_attempt(monkeypatch, tmp_path) -> None:
    from pihole_manager import provider_api

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    provider_api._RATE_STATES.clear()
    calls = 0

    def fake_post(_url: str, **_kwargs: Any) -> _Response:
        nonlocal calls
        calls += 1
        return _Response(
            {
                "choices": [{"message": {"content": "ok"}}],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 5,
                    "total_tokens": 15,
                },
            }
        )

    monkeypatch.setattr(provider_api.requests, "post", fake_post)
    provider = LLMProviderOptions(
        provider_id="quota-provider",
        base_url="https://quota.example/v1",
        model="model",
    )
    profile = ProviderLimitProfile(
        source="test",
        limits=(
            ProviderLimit(
                metric="requests",
                amount=1,
                window_seconds=60,
                source="test",
            ),
        ),
        safety_margin_percent=0,
    )
    context = ProviderRequestContext(
        pool_id="realtime",
        profile=profile,
        llm_options=LLMOptions(
            min_request_interval_sec=0,
            max_retries=0,
            quota_wait_timeout_sec=0,
            realtime_quota_reserve_percent=0,
        ),
        estimate=QuotaEstimate(input_tokens=12, output_tokens=8),
    )

    result = request_provider(
        provider,
        [{"role": "user", "content": "Classify"}],
        request_context=context,
    )

    assert result.usage.total_tokens == 15
    with pytest.raises(QuotaUnavailableError):
        request_provider(
            provider,
            [{"role": "user", "content": "Classify again"}],
            request_context=context,
        )
    assert calls == 1


def test_rate_limit_retries_after_server_delay(monkeypatch, tmp_path) -> None:
    from pihole_manager import provider_api
    from pihole_manager.config import load_options, save_options

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    options = load_options()
    options.llm.max_retries = 1
    options.llm.min_request_interval_sec = 0
    save_options(options)
    provider_api._RATE_STATES.clear()

    responses = [
        _Response(
            {"error": {"message": "slow down"}},
            status_code=429,
            headers={"Retry-After": "7"},
            reason="Too Many Requests",
        ),
        _Response({"choices": [{"message": {"content": "ok"}}]}),
    ]
    calls = 0

    def fake_post(_url: str, **_kwargs: Any) -> _Response:
        nonlocal calls
        calls += 1
        return responses.pop(0)

    clock = [100.0]
    sleeps: list[float] = []

    def fake_sleep(delay: float) -> None:
        sleeps.append(delay)
        clock[0] += delay

    monkeypatch.setattr(provider_api.requests, "post", fake_post)
    monkeypatch.setattr(provider_api.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(provider_api.time, "sleep", fake_sleep)

    provider = LLMProviderOptions(
        name="Rate-limited provider",
        base_url="https://api.example/v1",
        model="test",
    )
    result = request_provider_text(
        provider,
        [{"role": "user", "content": "Classify"}],
    )

    assert result == "ok"
    assert calls == 2
    assert sum(sleeps) >= 7


def test_non_retryable_provider_error_is_not_repeated(monkeypatch, tmp_path) -> None:
    from pihole_manager import provider_api
    from pihole_manager.config import load_options, save_options

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    options = load_options()
    options.llm.max_retries = 3
    options.llm.min_request_interval_sec = 0
    save_options(options)
    provider_api._RATE_STATES.clear()
    calls = 0

    def fake_post(_url: str, **_kwargs: Any) -> _Response:
        nonlocal calls
        calls += 1
        return _Response(
            {"error": {"message": "invalid key"}},
            status_code=401,
            reason="Unauthorized",
        )

    monkeypatch.setattr(provider_api.requests, "post", fake_post)
    provider = LLMProviderOptions(
        name="Unauthorized provider",
        base_url="https://api.example/v1",
        model="test",
    )

    with pytest.raises(requests.HTTPError):
        request_provider_text(
            provider,
            [{"role": "user", "content": "Classify"}],
        )
    assert calls == 1


def test_final_connection_failure_updates_provider_backoff(monkeypatch, tmp_path) -> None:
    from pihole_manager import provider_api
    from pihole_manager.config import load_options, save_options

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    options = load_options()
    options.llm.max_retries = 0
    options.llm.min_request_interval_sec = 0
    save_options(options)
    failures: list[int] = []

    def fail_request(*_args, **_kwargs):
        raise requests.ConnectionError("offline")

    monkeypatch.setattr(provider_api.requests, "post", fail_request)
    monkeypatch.setattr(
        provider_api,
        "_register_transient_failure",
        lambda _provider, attempt: failures.append(attempt) or 1.0,
    )
    provider = LLMProviderOptions(
        name="Offline provider",
        base_url="https://api.example/v1",
        model="test",
    )

    with pytest.raises(requests.ConnectionError):
        request_provider_text(
            provider,
            [{"role": "user", "content": "Classify"}],
        )

    assert failures == [0]
