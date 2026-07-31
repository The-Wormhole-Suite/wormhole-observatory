from __future__ import annotations

from pihole_manager.config import load_options, save_options
from pihole_manager.database import init_db, review_get
from pihole_manager.models import Classification, Policy, ServiceRole
from pihole_manager.workers import Classifier


def test_simulation_mode_does_not_change_pihole(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    options = load_options()
    options.llm.simulation_mode = True
    options.llm.automation_mode = "hybrid"
    options.llm.require_research_for_auto_action = True
    options.llm.auto_action_min_confidence = 0.95
    options.llm.tag_policies["advertising"] = "deny"
    save_options(options)
    init_db()

    applied: list[tuple[str, Policy, str]] = []
    monkeypatch.setattr(
        "pihole_manager.workers.add_exact_domain",
        lambda domain, policy, comment: applied.append((domain, policy, comment)),
    )

    classification = Classification(
        domain="ads.example.com",
        policy=Policy.DENY,
        category="advertising",
        tags=("advertising",),
        service="Example Ads",
        service_role=ServiceRole.OPTIONAL,
        privacy_risk=90,
        security_risk=5,
        breakage_risk=10,
        confidence=0.99,
        needs_review=False,
        review_reason="",
        recheck_after_days=30,
        short="Advertising endpoint",
        details="Used for advertising.",
        provider="test provider",
        raw_text="{}",
    )

    Classifier()._handle_classification(
        classification,
        {"research": {"decision_relevant_count": 1}},
    )

    assert applied == []
    row = review_get(needs_review=True)[0]
    assert row["planned_action"] == "deny"
    assert row["action_status"] == "simulated"
    assert row["status"] == "simulation_deny"


def test_disabled_simulation_applies_automatic_action(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    options = load_options()
    options.llm.simulation_mode = False
    options.llm.automation_mode = "hybrid"
    options.llm.require_research_for_auto_action = True
    options.llm.auto_action_min_confidence = 0.95
    options.llm.tag_policies["advertising"] = "deny"
    save_options(options)
    init_db()

    applied: list[tuple[str, Policy, str]] = []
    monkeypatch.setattr(
        "pihole_manager.workers.add_exact_domain",
        lambda domain, policy, comment: applied.append((domain, policy, comment)),
    )

    classification = Classification(
        domain="ads.example.com",
        policy=Policy.DENY,
        category="advertising",
        tags=("advertising",),
        service="Example Ads",
        service_role=ServiceRole.OPTIONAL,
        privacy_risk=90,
        security_risk=5,
        breakage_risk=10,
        confidence=0.99,
        needs_review=False,
        review_reason="",
        recheck_after_days=30,
        short="Advertising endpoint",
        details="Used for advertising.",
        provider="test provider",
        raw_text="{}",
    )

    Classifier()._handle_classification(
        classification,
        {"research": {"decision_relevant_count": 1}},
    )

    assert applied == [("ads.example.com", Policy.DENY, "Advertising endpoint")]
    row = review_get()[0]
    assert row["planned_action"] == "deny"
    assert row["action_status"] == "applied"
    assert row["status"] == "auto_deny"
