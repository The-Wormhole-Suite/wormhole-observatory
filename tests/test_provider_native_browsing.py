from __future__ import annotations

from typing import Any

from pihole_manager.config import LLMProviderOptions
from pihole_manager.provider_api import (
    ProviderCitation,
    request_provider,
    responses_url,
)
from pihole_manager.provider_presets import preset_by_id


class _Response:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload
        self.status_code = 200
        self.headers: dict[str, str] = {}
        self.reason = ""

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self.payload


def test_openai_web_search_preset_is_additive() -> None:
    standard = preset_by_id("openai")
    browsing = preset_by_id("openai_web_search")

    assert standard is not None
    assert browsing is not None
    assert standard.api_style == "openai_compatible"
    assert standard.structured_output == "json_schema"
    assert browsing.api_style == "openai_responses_web_search"
    assert browsing.structured_output == "prompt_only"
    assert browsing.max_tokens_parameter == "max_output_tokens"
    assert browsing.send_temperature is False


def test_openai_responses_url() -> None:
    provider = LLMProviderOptions(base_url="https://api.example/v1")
    assert responses_url(provider) == "https://api.example/v1/responses"


def test_openai_responses_web_search_request_collects_citations(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    def fake_post(url: str, **kwargs: Any) -> _Response:
        captured["url"] = url
        captured["headers"] = kwargs["headers"]
        captured["json"] = kwargs["json"]
        return _Response(
            {
                "output": [
                    {
                        "type": "web_search_call",
                        "id": "search_1",
                        "status": "completed",
                    },
                    {
                        "type": "message",
                        "content": [
                            {
                                "type": "output_text",
                                "text": '{"domains":[]}',
                                "annotations": [
                                    {
                                        "type": "url_citation",
                                        "url": "https://example.com/source",
                                        "title": "Primary source",
                                        "start_index": 0,
                                        "end_index": 7,
                                    }
                                ],
                            }
                        ],
                    },
                ],
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 5,
                    "total_tokens": 15,
                },
            }
        )

    monkeypatch.setattr("pihole_manager.provider_api.requests.post", fake_post)
    provider = LLMProviderOptions(
        name="OpenAI web search",
        api_style="openai_responses_web_search",
        base_url="https://api.openai.com/v1",
        api_key="secret",
        model="gpt-5",
        max_output_tokens=777,
        send_temperature=False,
    )
    result = request_provider(
        provider,
        [
            {
                "role": "system",
                "content": (
                    "System contract. Pi-hole Manager does not currently invoke "
                    "provider-specific web-search tools. Never claim to have searched the "
                    "web when browsing is not available. Include useful source URLs."
                ),
            },
            {"role": "user", "content": "Classify"},
        ],
    )

    assert result.text == '{"domains":[]}'
    assert result.usage.total_tokens == 15
    assert result.web_search_used is True
    assert result.citations == (
        ProviderCitation(
            url="https://example.com/source",
            title="Primary source",
            start_index=0,
            end_index=7,
        ),
    )
    assert captured["url"] == "https://api.openai.com/v1/responses"
    assert captured["headers"]["Authorization"] == "Bearer secret"
    assert captured["json"]["tools"] == [{"type": "web_search"}]
    assert captured["json"]["max_output_tokens"] == 777
    assert captured["json"]["store"] is False
    assert "temperature" not in captured["json"]
    system_prompt = captured["json"]["input"][0]["content"]
    assert "Provider-native web search is enabled for this request" in system_prompt
    assert "does not currently invoke provider-specific web-search tools" not in system_prompt
