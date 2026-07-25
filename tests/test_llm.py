from __future__ import annotations

import json

import pytest

from pihole_manager.config import PromptProfileOptions
from pihole_manager.llm import _chat_url, build_messages, parse_classification
from pihole_manager.models import Classification, Policy
from pihole_manager.workers import resolve_automatic_action


def test_parse_json_classification() -> None:
    result = parse_classification(
        '```json\n{"policy":"deny","category":"tracker","short":"Cross-site tracker",'
        '"details":"Observed tracking endpoint"}\n```',
        ["tracker", "unknown"],
    )

    assert result.policy is Policy.DENY
    assert result.category == "tracker"
    assert result.short == "Cross-site tracker"
    assert result.details == "Observed tracking endpoint"


def test_parse_labeled_classification_and_unknown_category() -> None:
    result = parse_classification(
        (
            "policy: allow\ncategory: not-configured\nshort: Essential API\n"
            "details: First line\nSecond line"
        ),
        ["essential", "unknown"],
    )

    assert result.policy is Policy.ALLOW
    assert result.category == "unknown"
    assert result.details == "First line\nSecond line"


def test_prompt_includes_categories_and_policies(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    profile = PromptProfileOptions(
        system="System instruction",
        user_template="Inspect {domain}",
    )

    messages = build_messages(profile, "example.com")

    assert messages[1]["content"] == "Inspect example.com"
    assert "Allowed categories" in messages[0]["content"]
    assert '"policy", "category", "short", "details"' in messages[0]["content"]


def test_invalid_prompt_template_is_rejected(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    profile = PromptProfileOptions(user_template="Inspect {missing}")

    with pytest.raises(ValueError, match="Invalid user prompt template"):
        build_messages(profile, "example.com")


@pytest.mark.parametrize(
    ("base_url", "expected"),
    [
        ("http://localhost:11434", "http://localhost:11434/v1/chat/completions"),
        ("https://api.example/v1", "https://api.example/v1/chat/completions"),
        ("https://api.example/v1/chat/completions", "https://api.example/v1/chat/completions"),
    ],
)
def test_chat_url(base_url: str, expected: str) -> None:
    assert _chat_url(base_url) == expected


def _classification(policy: Policy, category: str) -> Classification:
    return Classification(
        domain="example.com",
        policy=policy,
        category=category,
        short="reason",
        details="details",
        provider="provider",
    )


def test_hybrid_mode_requires_model_and_category_policy_agreement(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    config = {
        "llm": {
            "automation_mode": "hybrid",
            "categories": ["tracker", "unknown"],
            "category_policies": {"tracker": "deny", "unknown": "manual_review"},
        }
    }
    (tmp_path / "options.json").write_text(json.dumps(config), encoding="utf-8")

    assert resolve_automatic_action(_classification(Policy.DENY, "tracker")) is Policy.DENY
    assert resolve_automatic_action(_classification(Policy.ALLOW, "tracker")) is None
    assert resolve_automatic_action(_classification(Policy.DENY, "unknown")) is None
