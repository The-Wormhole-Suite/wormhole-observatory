from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any

import requests

from pihole_manager.config import (
    LLMProviderOptions,
    PromptProfileOptions,
    load_options,
)
from pihole_manager.models import Classification, Policy

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class PromptContext:
    categories: list[str]
    category_policies: dict[str, str]


def _active_provider() -> LLMProviderOptions | None:
    options = load_options()
    if not options.llm_providers:
        return None
    return options.llm_providers[options.llm.active_provider_index]


def _active_profile() -> PromptProfileOptions:
    options = load_options()
    return options.prompt_profiles[options.llm.active_profile_index]


def _chat_url(base_url: str) -> str:
    value = base_url.strip().rstrip("/")
    if not value:
        raise ValueError("LLM provider base URL is empty")
    if value.endswith("/chat/completions"):
        return value
    if value.endswith("/v1"):
        return f"{value}/chat/completions"
    return f"{value}/v1/chat/completions"


def build_messages(profile: PromptProfileOptions, domain: str) -> list[dict[str, str]]:
    options = load_options().llm
    context = PromptContext(options.categories, options.category_policies)
    policy_lines = [
        f"- {category}: {context.category_policies.get(category, 'manual_review')}"
        for category in context.categories
    ]
    dynamic = (
        "\n\nAllowed categories:\n- "
        + "\n- ".join(context.categories)
        + "\n\nDefault policy by category:\n"
        + "\n".join(policy_lines)
        + "\n\nReturn one JSON object with exactly these keys: "
        '"policy", "category", "short", "details". '
        "policy must be allow, deny, or manual_review. "
        "Use manual_review whenever the evidence is uncertain."
    )
    try:
        user = profile.user_template.format(domain=domain)
    except (KeyError, ValueError) as exc:
        raise ValueError(f"Invalid user prompt template: {exc}") from exc
    return [
        {"role": "system", "content": profile.system.strip() + dynamic},
        {"role": "user", "content": user},
    ]


def classify_domain(
    domain: str,
    provider: LLMProviderOptions | None = None,
    profile: PromptProfileOptions | None = None,
) -> Classification:
    selected_provider = provider or _active_provider()
    if selected_provider is None or not selected_provider.base_url.strip():
        raise RuntimeError("No LLM provider is configured")
    if not selected_provider.model.strip():
        raise RuntimeError("The active LLM provider has no model configured")

    selected_profile = profile or _active_profile()
    payload = {
        "model": selected_provider.model,
        "messages": build_messages(selected_profile, domain),
        "temperature": float(selected_provider.temperature),
    }
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if selected_provider.api_key:
        headers["Authorization"] = f"Bearer {selected_provider.api_key}"

    response = requests.post(
        _chat_url(selected_provider.base_url),
        json=payload,
        headers=headers,
        timeout=max(1.0, float(selected_provider.timeout_sec)),
    )
    response.raise_for_status()
    data = response.json()
    text = _extract_response_text(data)
    parsed = parse_classification(text, load_options().llm.categories)
    return Classification(
        domain=domain.strip().lower(),
        policy=parsed.policy,
        category=parsed.category,
        short=parsed.short,
        details=parsed.details,
        provider=selected_provider.name,
        raw_text=text,
    )


def _extract_response_text(data: Any) -> str:
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
    content = message.get("content")
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts = [
            str(item.get("text") or "")
            for item in content
            if isinstance(item, dict)
        ]
        return "\n".join(part for part in parts if part).strip()
    raise ValueError("LLM response message contains no text")


def parse_classification(text: str, categories: list[str]) -> Classification:
    raw = text.strip()
    if not raw:
        raise ValueError("LLM returned an empty response")

    payload = _parse_json_object(raw)
    if payload is None:
        payload = _parse_labeled_lines(raw)

    policy = _normalize_policy(str(payload.get("policy") or ""))
    category = str(payload.get("category") or "unknown").strip().lower()
    allowed = {item.strip().lower() for item in categories}
    if category not in allowed:
        category = "unknown" if "unknown" in allowed else next(iter(allowed), "unknown")
    short = str(payload.get("short") or "").strip()[:500]
    details = str(payload.get("details") or "").strip()
    if not short:
        short = details[:180] or raw[:180]
    if not details:
        details = raw
    return Classification(
        domain="",
        policy=policy,
        category=category,
        short=short,
        details=details,
        provider="",
        raw_text=raw,
    )


def _parse_json_object(text: str) -> dict[str, Any] | None:
    candidates = [text]
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL | re.IGNORECASE)
    if fenced:
        candidates.insert(0, fenced.group(1))
    first = text.find("{")
    last = text.rfind("}")
    if first >= 0 and last > first:
        candidates.append(text[first : last + 1])
    for candidate in candidates:
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def _parse_labeled_lines(text: str) -> dict[str, str]:
    output: dict[str, str] = {}
    current_key: str | None = None
    for line in text.splitlines():
        match = re.match(r"^\s*(policy|category|short|details)\s*:\s*(.*)$", line, re.I)
        if match:
            current_key = match.group(1).lower()
            output[current_key] = match.group(2).strip()
        elif current_key == "details" and line.strip():
            output["details"] = f"{output.get('details', '')}\n{line.strip()}".strip()
    if "policy" not in output:
        lowered = text.lower()
        for candidate in ("manual_review", "deny", "allow"):
            if candidate in lowered:
                output["policy"] = candidate
                break
    return output


def _normalize_policy(value: str) -> Policy:
    normalized = value.strip().lower().replace(" ", "_")
    if normalized in {"allow", "allowed", "permit", "permitted", "whitelist"}:
        return Policy.ALLOW
    if normalized in {"deny", "denied", "block", "blocked", "blacklist"}:
        return Policy.DENY
    if normalized in {"manual", "review", "manual_review", "needs_review"}:
        return Policy.MANUAL_REVIEW
    return Policy.UNKNOWN
