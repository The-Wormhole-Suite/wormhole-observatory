from __future__ import annotations

from dataclasses import replace

from pihole_manager.config import LLMOptions
from pihole_manager.models import Classification, Policy, ServiceRole


def _classification(domain: str = "telemetry.example.test") -> Classification:
    return Classification(
        domain=domain,
        policy=Policy.DENY,
        category="advertising",
        short="Advertising telemetry",
        details="Synthetic classification for manual-tag override tests.",
        provider="fixture",
        tags=("advertising", "cross_site_tracking"),
        service="Example telemetry",
        service_role=ServiceRole.OPTIONAL,
        privacy_risk=90,
        security_risk=5,
        breakage_risk=10,
        confidence=0.99,
        needs_review=False,
        raw_text="{}",
    )


def test_manual_tags_override_current_view_but_preserve_model_history(
    monkeypatch, tmp_path
) -> None:
    from pihole_manager.database import (
        classification_history,
        init_db,
        manual_tags,
        review_get,
        save_classification_run,
        set_manual_tags,
    )

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    classification = _classification()
    save_classification_run(classification)

    set_manual_tags(classification.domain, ["authentication", "payments"])

    assert manual_tags(classification.domain) == ["authentication", "payments"]
    history = classification_history(classification.domain)
    assert history[0]["tags"] == ["advertising", "cross_site_tracking"]
    current = review_get()[0]
    assert current["tags"] == ["authentication", "payments"]
    assert current["tags_source"] == "manual"


def test_domain_browser_uses_manual_tags_for_display_and_filtering(
    monkeypatch, tmp_path
) -> None:
    from pihole_manager.database import (
        domain_browser_search,
        init_db,
        save_classification_run,
        set_manual_tags,
    )

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    classification = _classification()
    save_classification_run(classification)
    set_manual_tags(classification.domain, ["authentication"])

    rows, total = domain_browser_search(search=classification.domain)
    assert total == 1
    assert rows[0]["tags"] == ["authentication"]
    assert rows[0]["tags_source"] == "manual"

    rows, total = domain_browser_search(tag="authentication")
    assert total == 1
    assert rows[0]["domain"] == classification.domain

    rows, total = domain_browser_search(tag="advertising")
    assert total == 0
    assert rows == []


def test_clearing_manual_override_restores_classification_tags(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import (
        domain_browser_search,
        init_db,
        review_get,
        save_classification_run,
        set_manual_tags,
    )

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    classification = _classification()
    save_classification_run(classification)
    set_manual_tags(classification.domain, ["authentication"])
    set_manual_tags(classification.domain, [])

    current = review_get()[0]
    assert current["tags"] == ["advertising", "cross_site_tracking"]
    assert current["tags_source"] == "classification"
    rows, total = domain_browser_search(tag="advertising")
    assert total == 1
    assert rows[0]["domain"] == classification.domain
    assert rows[0]["tags_source"] == "classification"


def test_manual_override_drives_auto_policy_without_mutating_llm_result(
    monkeypatch, tmp_path
) -> None:
    from pihole_manager.database import init_db, set_manual_tags
    from pihole_manager.workers import apply_manual_tag_override, resolve_automatic_decision

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    classification = _classification()
    set_manual_tags(classification.domain, ["authentication"])

    effective = apply_manual_tag_override(classification)
    options = LLMOptions(
        automation_mode="auto",
        auto_action_min_confidence=0.0,
        require_research_for_auto_action=False,
        tag_policies={
            "advertising": Policy.DENY.value,
            "cross_site_tracking": Policy.DENY.value,
            "authentication": Policy.ALLOW.value,
        },
    )
    decision = resolve_automatic_decision(
        effective,
        evidence_count=1,
        llm_options=options,
    )

    assert classification.tags == ("advertising", "cross_site_tracking")
    assert effective.tags == ("authentication",)
    assert decision.action is Policy.ALLOW


def test_reanalysis_does_not_remove_manual_override(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import (
        init_db,
        manual_tags,
        review_get,
        save_classification_run,
        set_manual_tags,
    )

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    classification = _classification()
    save_classification_run(classification)
    set_manual_tags(classification.domain, ["authentication"])

    save_classification_run(
        replace(
            classification,
            tags=("advertising", "analytics"),
            short="Second model result",
        )
    )

    assert manual_tags(classification.domain) == ["authentication"]
    current = review_get()[0]
    assert current["tags"] == ["authentication"]
    assert current["tags_source"] == "manual"
