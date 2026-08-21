from __future__ import annotations

from dataclasses import replace

from pihole_manager.behavior_change import (
    apply_behavior_change_guard,
    behavior_change_for_classification,
    historical_behavior_change,
)
from pihole_manager.models import Classification, Policy, ServiceRole


def _classification(
    domain: str = "telemetry.example.test",
    *,
    policy: Policy = Policy.ALLOW,
    tags: tuple[str, ...] = ("analytics",),
    service: str = "Example Analytics",
    role: ServiceRole = ServiceRole.OPTIONAL,
    privacy_risk: int = 25,
    security_risk: int = 5,
    breakage_risk: int = 10,
) -> Classification:
    return Classification(
        domain=domain,
        policy=policy,
        category=tags[0],
        short="Synthetic behavior fixture",
        details="Synthetic behavior-change fixture.",
        provider="fixture",
        tags=tags,
        service=service,
        service_role=role,
        privacy_risk=privacy_risk,
        security_risk=security_risk,
        breakage_risk=breakage_risk,
        confidence=0.95,
        needs_review=False,
    )


def test_first_classification_has_no_behavior_change(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import init_db

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()

    report = behavior_change_for_classification(_classification())

    assert report.has_history is False
    assert report.score == 0
    assert report.requires_review is False


def test_policy_flip_and_security_jump_require_review(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import init_db, save_classification_run

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    baseline = _classification()
    save_classification_run(baseline)
    candidate = replace(
        baseline,
        policy=Policy.DENY,
        tags=("malware",),
        category="malware",
        security_risk=80,
    )

    report = behavior_change_for_classification(candidate)
    guarded = apply_behavior_change_guard(candidate, report)

    assert report.requires_review is True
    assert report.severity in {"high", "critical"}
    fields = {signal.field for signal in report.signals}
    assert {"policy", "security_risk", "tags"} <= fields
    assert guarded.needs_review is True
    assert "Historical behavior-change signal" in guarded.review_reason


def test_minor_risk_drift_does_not_force_review(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import init_db, save_classification_run

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    baseline = _classification()
    save_classification_run(baseline)
    candidate = replace(baseline, privacy_risk=32, security_risk=9, breakage_risk=15)

    report = behavior_change_for_classification(candidate)

    assert report.requires_review is False
    assert report.score == 0


def test_secondary_benchmark_runs_are_ignored(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import init_db, save_classification_run

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    baseline = _classification()
    save_classification_run(baseline)
    save_classification_run(
        replace(baseline, policy=Policy.DENY, tags=("malware",), category="malware"),
        is_primary=False,
        update_current=False,
    )

    report = behavior_change_for_classification(baseline)

    assert report.has_history is True
    assert report.score == 0
    assert report.requires_review is False


def test_historical_report_compares_latest_two_primary_runs(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import init_db, save_classification_run

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    baseline = _classification()
    save_classification_run(baseline)
    save_classification_run(
        replace(
            baseline,
            service="Example Identity",
            service_role=ServiceRole.CORE,
            breakage_risk=90,
        )
    )

    report = historical_behavior_change(baseline.domain)

    assert report.has_history is True
    assert report.requires_review is True
    fields = {signal.field for signal in report.signals}
    assert {"service", "service_role", "breakage_risk"} <= fields


def test_domain_details_exposes_historical_behavior_report(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import domain_details, init_db, save_classification_run

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    baseline = _classification()
    save_classification_run(baseline)
    save_classification_run(
        replace(baseline, policy=Policy.DENY, tags=("malware",), category="malware")
    )

    details = domain_details(baseline.domain)

    assert details["behavior_change"]["has_history"] is True
    assert details["behavior_change"]["requires_review"] is True
    assert details["behavior_change"]["signals"]


def test_existing_pre_policy_guard_applies_behavior_change(monkeypatch, tmp_path) -> None:
    from pihole_manager.compatibility_profiles import apply_compatibility_profile
    from pihole_manager.database import init_db, save_classification_run

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    baseline = _classification()
    save_classification_run(baseline)
    candidate = replace(baseline, policy=Policy.DENY)

    guarded = apply_compatibility_profile(candidate)

    assert guarded.needs_review is True
    assert "Historical behavior-change signal" in guarded.review_reason
