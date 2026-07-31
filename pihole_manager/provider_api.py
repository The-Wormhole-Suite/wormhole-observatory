from __future__ import annotations

import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import requests

from pihole_manager.config import LLMProviderOptions, load_options
from pihole_manager.http_retry import retry_delay_from_headers

_RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}
_RATE_LOCK = threading.RLock()


@dataclass(slots=True)
class _ProviderRateState:
    next_request_at: float = 0.0
    adaptive_interval: float = 0.0
    consecutive_limits: int = 0


_RATE_STATES: dict[str, _ProviderRateState] = {}


class ProviderRateLimitError(requests.HTTPError):
    def __init__(
        self,
        message: str,
        *,
        retry_after: float | None = None,
        response: requests.Response | None = None,
    ) -> None:
        super().__init__(message, response=response)
        self.retry_after = retry_after


def _append_path(base_url: str, path: str) -> str:
    base = base_url.strip().rstrip("/")
    if not base:
        raise ValueError("LLM provider base URL is empty")
    suffix = path.strip()
    if not suffix:
        return base
    normalized_suffix = "/" + suffix.lstrip("/")
    if base.endswith(normalized_suffix):
        return base
    return base + normalized_suffix


def chat_url(provider: LLMProviderOptions) -> str:
    if provider.api_style == "anthropic_messages":
        return _append_path(provider.base_url, "messages")
    return _append_path(provider.base_url, "chat/completions")


def models_url(provider: LLMProviderOptions) -> str:
    return _append_path(provider.base_url, "models")


def list_provider_models(provider: LLMProviderOptions) -> list[str]:
    response = _request_with_retries(
        provider,
        requests.get,
        models_url(provider),
        headers=_headers(provider),
    )
    data = response.json()
    items = data.get("data") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise ValueError("Provider model response contains no data array")
    models = sorted(
        {
            str(item.get("id") or "").strip()
            for item in items
            if isinstance(item, dict) and str(item.get("id") or "").strip()
        },
        key=str.casefold,
    )
    if not models:
        raise ValueError("Provider returned no model IDs")
    return models


def request_provider_text(
    provider: LLMProviderOptions,
    messages: Sequence[Mapping[str, str]],
    *,
    response_format: dict[str, Any] | None = None,
) -> str:
    if provider.api_style == "anthropic_messages":
        return _request_anthropic(provider, messages)
    return _request_openai_compatible(provider, messages, response_format=response_format)


def _request_openai_compatible(
    provider: LLMProviderOptions,
    messages: Sequence[Mapping[str, str]],
    *,
    response_format: dict[str, Any] | None,
) -> str:
    payload: dict[str, Any] = {
        "model": provider.model,
        "messages": [dict(item) for item in messages],
    }
    if provider.send_temperature:
        payload["temperature"] = float(provider.temperature)
    if provider.max_tokens_parameter != "none":
        payload[provider.max_tokens_parameter] = max(1, int(provider.max_output_tokens))
    if response_format is not None:
        payload["response_format"] = response_format
    response = _request_with_retries(
        provider,
        requests.post,
        chat_url(provider),
        json=payload,
        headers=_headers(provider),
    )
    return _extract_openai_text(response.json())


def _request_anthropic(
    provider: LLMProviderOptions,
    messages: Sequence[Mapping[str, str]],
) -> str:
    system_parts = [
        str(item.get("content") or "") for item in messages if item.get("role") == "system"
    ]
    conversation = [
        {"role": item.get("role", "user"), "content": item.get("content", "")}
        for item in messages
        if item.get("role") != "system"
    ]
    payload: dict[str, Any] = {
        "model": provider.model,
        "max_tokens": max(1, int(provider.max_output_tokens)),
        "messages": conversation,
    }
    if provider.send_temperature:
        payload["temperature"] = float(provider.temperature)
    if system_parts:
        payload["system"] = "\n\n".join(system_parts)
    response = _request_with_retries(
        provider,
        requests.post,
        chat_url(provider),
        json=payload,
        headers=_headers(provider),
    )
    return _extract_anthropic_text(response.json())


def _request_with_retries(
    provider: LLMProviderOptions,
    request: Any,
    url: str,
    **kwargs: Any,
) -> requests.Response:
    options = load_options().llm
    attempts = max(1, int(options.max_retries) + 1)
    kwargs["timeout"] = max(1.0, float(provider.timeout_sec))
    last_error: Exception | None = None

    for attempt in range(attempts):
        _wait_for_request_slot(provider, options.min_request_interval_sec)
        try:
            response = request(url, **kwargs)
        except (requests.ConnectionError, requests.Timeout) as exc:
            last_error = exc
            _register_transient_failure(provider, attempt)
            if attempt + 1 >= attempts:
                raise
            continue

        status_code = int(getattr(response, "status_code", 200))
        if status_code in _RETRYABLE_STATUS_CODES:
            delay = _register_response_failure(provider, response, attempt)
            if attempt + 1 < attempts:
                continue
            if status_code == 429:
                raise ProviderRateLimitError(
                    _response_error_message(response) or "LLM provider rate limit exceeded",
                    retry_after=delay,
                    response=response,
                )
            response.raise_for_status()

        response.raise_for_status()
        _register_success(provider)
        return response

    if last_error is not None:
        raise last_error
    raise RuntimeError("Provider request failed without a response")


def _wait_for_request_slot(provider: LLMProviderOptions, configured_minimum: float) -> None:
    key = _provider_key(provider)
    base_interval = max(0.0, float(configured_minimum))
    while True:
        with _RATE_LOCK:
            state = _RATE_STATES.setdefault(key, _ProviderRateState())
            now = time.monotonic()
            delay = max(0.0, state.next_request_at - now)
            if delay <= 0:
                interval = max(base_interval, state.adaptive_interval)
                state.next_request_at = now + interval
                return
        time.sleep(delay)


def _register_transient_failure(provider: LLMProviderOptions, attempt: int) -> float:
    delay = min(300.0, max(1.0, 2.0**attempt))
    _increase_backoff(provider, delay)
    return delay


def _register_response_failure(
    provider: LLMProviderOptions,
    response: requests.Response,
    attempt: int,
) -> float:
    headers = getattr(response, "headers", {})
    delay = retry_delay_from_headers(headers)
    if delay is None:
        delay = min(300.0, max(1.0, 2.0**attempt))
    _increase_backoff(provider, delay, rate_limited=response.status_code == 429)
    return delay


def _increase_backoff(
    provider: LLMProviderOptions,
    delay: float,
    *,
    rate_limited: bool = False,
) -> None:
    key = _provider_key(provider)
    configured = max(0.0, float(load_options().llm.min_request_interval_sec))
    with _RATE_LOCK:
        state = _RATE_STATES.setdefault(key, _ProviderRateState())
        adaptive = state.adaptive_interval * 2 if state.adaptive_interval else max(1.0, configured)
        state.adaptive_interval = min(60.0, max(configured, adaptive))
        state.next_request_at = max(
            state.next_request_at,
            time.monotonic() + max(delay, state.adaptive_interval),
        )
        if rate_limited:
            state.consecutive_limits += 1


def _register_success(provider: LLMProviderOptions) -> None:
    key = _provider_key(provider)
    configured = max(0.0, float(load_options().llm.min_request_interval_sec))
    with _RATE_LOCK:
        state = _RATE_STATES.setdefault(key, _ProviderRateState())
        state.adaptive_interval = max(configured, state.adaptive_interval / 2)
        state.consecutive_limits = 0


def _provider_key(provider: LLMProviderOptions) -> str:
    return "|".join(
        (
            provider.api_style.strip().lower(),
            provider.base_url.strip().lower().rstrip("/"),
            provider.name.strip().lower(),
        )
    )


def _response_error_message(response: requests.Response) -> str:
    try:
        payload = response.json()
    except (requests.JSONDecodeError, ValueError):
        payload = None
    if isinstance(payload, dict):
        error = payload.get("error")
        if isinstance(error, dict):
            return str(error.get("message") or error.get("type") or "")
        if error:
            return str(error)
        if payload.get("message"):
            return str(payload["message"])
    return str(getattr(response, "reason", "") or "")


def _headers(provider: LLMProviderOptions) -> dict[str, str]:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if provider.api_style == "anthropic_messages":
        if provider.api_key:
            headers["x-api-key"] = provider.api_key
        headers["anthropic-version"] = "2023-06-01"
    elif provider.api_key:
        headers["Authorization"] = f"Bearer {provider.api_key}"
    return headers


def _extract_openai_text(data: Any) -> str:
    if not isinstance(data, dict):
        raise ValueError("LLM response is not a JSON object")
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("LLM response contains no choices")
    first = choices[0]
    if not isinstance(first, dict):
        raise ValueError("LLM response choice is invalid")
    message = first.get("message")
    if not isinstance(message, dict):
        raise ValueError("LLM response contains no message")
    if message.get("refusal"):
        raise ValueError(f"LLM refused the request: {message['refusal']}")
    content = message.get("content")
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts = [str(item.get("text") or "") for item in content if isinstance(item, dict)]
        return "\n".join(part for part in parts if part).strip()
    raise ValueError("LLM response message contains no text")


def _extract_anthropic_text(data: Any) -> str:
    if not isinstance(data, dict):
        raise ValueError("Anthropic response is not a JSON object")
    content = data.get("content")
    if not isinstance(content, list):
        raise ValueError("Anthropic response contains no content array")
    parts = [
        str(item.get("text") or "")
        for item in content
        if isinstance(item, dict) and item.get("type") == "text"
    ]
    text = "\n".join(part for part in parts if part).strip()
    if not text:
        raise ValueError("Anthropic response contains no text block")
    return text
