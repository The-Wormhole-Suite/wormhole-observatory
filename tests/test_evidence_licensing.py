from __future__ import annotations

from pihole_manager.config import Options
from pihole_manager.evidence_licensing import (
    distribution_license_issues,
    repository_list_license_policies,
    source_license_policy,
)


def test_current_release_defaults_pass_evidence_license_gate() -> None:
    enabled = [
        provider.kind
        for provider in Options().research_providers
        if provider.enabled
    ]

    assert distribution_license_issues(enabled) == []


def test_noncommercial_disconnect_catalog_cannot_become_release_default() -> None:
    issues = distribution_license_issues(["disconnect_tracking"])

    assert len(issues) == 1
    assert "opt-in" in issues[0]
    assert "restricted-noncommercial" in issues[0]


def test_conditional_commercial_api_cannot_become_release_default() -> None:
    issues = distribution_license_issues(["urlhaus"])

    assert len(issues) == 1
    assert "conditional-commercial-api" in issues[0]


def test_repository_lists_have_completed_per_source_review() -> None:
    policies = repository_list_license_policies()

    assert set(policies) == {"hagezi_tif_mini", "easyprivacy_trackingservers"}
    assert all(not item.review_required for item in policies.values())
    assert all(item.release_default_eligible for item in policies.values())


def test_easyprivacy_review_records_dual_commercially_usable_license() -> None:
    policy = repository_list_license_policies()["easyprivacy_trackingservers"]

    assert policy.license_id == "GPL-3.0-or-later OR CC-BY-SA-3.0-or-later"
    assert policy.commercial_use == "allowed-with-license-obligations"
    assert policy.license_url == "https://easylist.to/pages/licence.html"


def test_phishtank_data_policy_records_commercial_use_permission() -> None:
    policy = source_license_policy("phishtank")

    assert policy is not None
    assert policy.commercial_use == "allowed"
    assert policy.release_default_eligible is True


def test_unknown_enabled_source_fails_closed() -> None:
    issues = distribution_license_issues(["future_unreviewed_source"])

    assert len(issues) == 1
    assert "no reviewed" in issues[0]
