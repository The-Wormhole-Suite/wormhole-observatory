from __future__ import annotations

import json

import pytest
import requests

from pihole_manager.config import LLMProviderOptions, PromptProfileOptions
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
    assert "Allowed tags" in messages[0]["content"]
    assert "Required JSON schema" in messages[0]["content"]
    assert "breakage_risk" in messages[0]["content"]


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
        tags=(category,),
        short="reason",
        details="details",
        provider="provider",
        confidence=0.99,
        breakage_risk=10,
        needs_review=False,
    )


def test_hybrid_mode_requires_model_and_category_policy_agreement(monkeypatch, tmp_path) -> None:
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


def test_parse_batch_requires_exact_domain_set() -> None:
    from pihole_manager.llm import LLMResponseError, parse_batch_classifications

    payload = {
        "schema_version": 1,
        "results": [
            {
                "domain": "one.example",
                "policy": "manual_review",
                "category": "unknown",
                "tags": ["unknown"],
                "service": "",
                "service_role": "unknown",
                "privacy_risk": 0,
                "security_risk": 0,
                "breakage_risk": 50,
                "confidence": 0.4,
                "needs_review": True,
                "review_reason": "Insufficient evidence",
                "recheck_after_days": 7,
                "short": "Unknown endpoint",
                "details": "No reliable evidence found.",
            }
        ],
    }
    with pytest.raises(LLMResponseError, match="omitted domains"):
        parse_batch_classifications(
            json.dumps(payload),
            ["one.example", "two.example"],
            ["unknown"],
        )


def test_parse_batch_preserves_tags_risks_and_service() -> None:
    from pihole_manager.llm import parse_batch_classifications
    from pihole_manager.models import ServiceRole

    payload = {
        "schema_version": 1,
        "results": [
            {
                "domain": "telemetry.example",
                "policy": "deny",
                "category": "telemetry",
                "tags": ["telemetry", "analytics"],
                "service": "Example App",
                "service_role": "optional",
                "privacy_risk": 80,
                "security_risk": 5,
                "breakage_risk": 20,
                "confidence": 0.93,
                "needs_review": False,
                "review_reason": "",
                "recheck_after_days": 30,
                "short": "Optional telemetry",
                "details": "Telemetry endpoint for Example App.",
            }
        ],
    }
    result = parse_batch_classifications(
        json.dumps(payload),
        ["telemetry.example"],
        ["telemetry", "analytics", "unknown"],
        provider="test",
    )[0]
    assert result.tags == ("telemetry", "analytics")
    assert result.service_role is ServiceRole.OPTIONAL
    assert result.privacy_risk == 80
    assert result.needs_review is False


def test_parse_batch_rejects_missing_required_field() -> None:
    from pihole_manager.llm import LLMResponseError, parse_batch_classifications

    payload = {
        "schema_version": 1,
        "results": [
            {
                "domain": "example.com",
                "policy": "deny",
                "category": "advertising",
                "tags": ["advertising"],
                "service": "Example",
                "service_role": "optional",
                "privacy_risk": 80,
                "security_risk": 0,
                "breakage_risk": 10,
                "confidence": 0.99,
                "needs_review": False,
                "review_reason": "",
                "recheck_after_days": 30,
                "short": "Advertising endpoint",
            }
        ],
    }

    with pytest.raises(LLMResponseError, match="missing fields: details"):
        parse_batch_classifications(
            json.dumps(payload),
            ["example.com"],
            ["advertising", "unknown"],
        )


def test_parse_batch_rejects_wrong_field_type() -> None:
    from pihole_manager.llm import LLMResponseError, parse_batch_classifications

    payload = {
        "schema_version": 1,
        "results": [
            {
                "domain": "example.com",
                "policy": "deny",
                "category": "advertising",
                "tags": ["advertising"],
                "service": "Example",
                "service_role": "optional",
                "privacy_risk": "80",
                "security_risk": 0,
                "breakage_risk": 10,
                "confidence": 0.99,
                "needs_review": False,
                "review_reason": "",
                "recheck_after_days": 30,
                "short": "Advertising endpoint",
                "details": "Advertising infrastructure.",
            }
        ],
    }

    with pytest.raises(LLMResponseError, match="privacy_risk"):
        parse_batch_classifications(
            json.dumps(payload),
            ["example.com"],
            ["advertising", "unknown"],
        )


def test_conflicting_tag_policies_require_review(monkeypatch, tmp_path) -> None:
    from pihole_manager.workers import resolve_automatic_decision

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    config = {
        "llm": {
            "automation_mode": "auto",
            "tags": ["advertising", "authentication", "unknown"],
            "tag_policies": {
                "advertising": "deny",
                "authentication": "manual_review",
                "unknown": "manual_review",
            },
        }
    }
    (tmp_path / "options.json").write_text(json.dumps(config), encoding="utf-8")
    classification = Classification(
        domain="mixed.example",
        policy=Policy.DENY,
        category="advertising",
        tags=("advertising", "authentication"),
        short="Mixed-purpose endpoint",
        details="Advertising and authentication evidence.",
        provider="provider",
        confidence=0.99,
        breakage_risk=10,
        needs_review=False,
    )

    decision = resolve_automatic_decision(classification)

    assert decision.action is None
    assert "authentication" in decision.review_reason


def test_confidence_between_review_and_auto_is_stored_without_auto_review(
    monkeypatch, tmp_path
) -> None:
    from pihole_manager.workers import resolve_automatic_decision

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    config = {
        "llm": {
            "automation_mode": "auto",
            "review_confidence_threshold": 0.70,
            "auto_action_min_confidence": 0.95,
            "require_research_for_auto_action": False,
            "tags": ["advertising", "unknown"],
            "tag_policies": {
                "advertising": "deny",
                "unknown": "manual_review",
            },
        }
    }
    (tmp_path / "options.json").write_text(json.dumps(config), encoding="utf-8")
    classification = Classification(
        domain="ads.example",
        policy=Policy.DENY,
        category="advertising",
        tags=("advertising",),
        short="Advertising",
        details="Advertising endpoint.",
        provider="provider",
        confidence=0.85,
        breakage_risk=10,
        needs_review=False,
    )

    decision = resolve_automatic_decision(classification, evidence_count=1)

    assert decision.action is None
    assert decision.review_reason == ""


def test_shortest_tag_recheck_age_wins(monkeypatch, tmp_path) -> None:
    from pihole_manager.workers import _configured_recheck_days

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    config = {
        "llm": {
            "tags": ["telemetry", "malware", "unknown"],
            "tag_recheck_days": {
                "telemetry": 30,
                "malware": 7,
                "unknown": 3,
            },
        }
    }
    (tmp_path / "options.json").write_text(json.dumps(config), encoding="utf-8")
    classification = Classification(
        domain="mixed.example",
        policy=Policy.MANUAL_REVIEW,
        category="telemetry",
        tags=("telemetry", "malware"),
        short="Mixed",
        details="Mixed evidence.",
        provider="provider",
        recheck_after_days=90,
    )

    assert _configured_recheck_days(classification) == 7


def test_rate_limit_does_not_trigger_output_mode_fallback(monkeypatch, tmp_path) -> None:
    from pihole_manager.llm import classify_domains

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    calls = 0
    response = requests.Response()
    response.status_code = 429

    def fail_request(*_args, **_kwargs) -> str:
        nonlocal calls
        calls += 1
        raise requests.HTTPError("rate limited", response=response)

    monkeypatch.setattr("pihole_manager.llm.request_provider_text", fail_request)
    provider = LLMProviderOptions(
        name="Test",
        base_url="https://api.example/v1",
        model="test",
        structured_output="auto",
    )

    with pytest.raises(RuntimeError, match="rate limited"):
        classify_domains(["example.com"], provider=provider)
    assert calls == 1


def test_incompatible_output_mode_can_fall_back(monkeypatch, tmp_path) -> None:
    from pihole_manager.llm import classify_domains

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    calls = 0
    response = requests.Response()
    response.status_code = 400
    valid = {
        "schema_version": 1,
        "results": [
            {
                "domain": "example.com",
                "policy": "manual_review",
                "category": "unknown",
                "tags": ["unknown"],
                "service": "",
                "service_role": "unknown",
                "privacy_risk": 0,
                "security_risk": 0,
                "breakage_risk": 50,
                "confidence": 0.5,
                "needs_review": True,
                "review_reason": "Insufficient evidence",
                "recheck_after_days": 3,
                "short": "Unknown domain",
                "details": "No reliable evidence is available.",
            }
        ],
    }

    def request_with_fallback(*_args, **_kwargs) -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise requests.HTTPError("unsupported schema", response=response)
        return json.dumps(valid)

    monkeypatch.setattr(
        "pihole_manager.llm.request_provider_text",
        request_with_fallback,
    )
    provider = LLMProviderOptions(
        name="Test",
        base_url="https://api.example/v1",
        model="test",
        structured_output="auto",
    )

    results = classify_domains(["example.com"], provider=provider)

    assert len(results) == 1
    assert calls == 2


def test_ten_domains_use_one_provider_request(monkeypatch, tmp_path) -> None:
    from pihole_manager.llm import classify_domains

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    domains = [f"domain-{index}.example" for index in range(10)]
    payload = {
        "schema_version": 1,
        "results": [
            {
                "domain": domain,
                "policy": "manual_review",
                "category": "unknown",
                "tags": ["unknown"],
                "service": "",
                "service_role": "unknown",
                "privacy_risk": 0,
                "security_risk": 0,
                "breakage_risk": 50,
                "confidence": 0.5,
                "needs_review": True,
                "review_reason": "Insufficient evidence",
                "recheck_after_days": 3,
                "short": "Unknown domain",
                "details": "No reliable evidence is available.",
            }
            for domain in domains
        ],
    }
    calls = 0

    def fake_request(*_args, **_kwargs) -> str:
        nonlocal calls
        calls += 1
        return json.dumps(payload)

    monkeypatch.setattr("pihole_manager.llm.request_provider_text", fake_request)
    provider = LLMProviderOptions(
        name="Cerebras Free",
        base_url="https://api.cerebras.ai/v1",
        model="gpt-oss-120b",
        structured_output="prompt_only",
    )

    results = classify_domains(domains, provider=provider)

    assert [result.domain for result in results] == domains
    assert calls == 1


def test_classification_uses_one_configuration_snapshot(monkeypatch) -> None:
    from pihole_manager import llm
    from pihole_manager.config import Options

    payload = {
        "schema_version": 1,
        "results": [
            {
                "domain": "example.com",
                "policy": "manual_review",
                "category": "unknown",
                "tags": ["unknown"],
                "service": "",
                "service_role": "unknown",
                "privacy_risk": 0,
                "security_risk": 0,
                "breakage_risk": 50,
                "confidence": 0.5,
                "needs_review": True,
                "review_reason": "Insufficient evidence",
                "recheck_after_days": 3,
                "short": "Unknown domain",
                "details": "No reliable evidence is available.",
            }
        ],
    }
    options = Options()
    calls = 0

    def load_once() -> Options:
        nonlocal calls
        calls += 1
        return options

    monkeypatch.setattr(llm, "load_options", load_once)
    monkeypatch.setattr(
        llm,
        "request_provider_text",
        lambda *_args, **_kwargs: json.dumps(payload),
    )
    provider = LLMProviderOptions(
        name="Test",
        base_url="https://api.example/v1",
        model="test",
        structured_output="prompt_only",
    )
    profile = PromptProfileOptions()

    result = llm.classify_domains(
        ["example.com"],
        provider=provider,
        profile=profile,
    )

    assert result[0].domain == "example.com"
    assert calls == 1
