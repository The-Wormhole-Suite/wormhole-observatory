from __future__ import annotations

from types import SimpleNamespace

import pytest

from pihole_manager.compatibility_profiles import (
    COMPATIBILITY_PROVIDER_NAME,
    apply_compatibility_profile,
    compatibility_finding,
    compatibility_match_for_domain,
    load_compatibility_profiles,
)
from pihole_manager.config import LLMOptions
from pihole_manager.evidence_quality import score_finding
from pihole_manager.models import Classification, Policy, ServiceRole
from pihole_manager.workers import resolve_automatic_decision


def _classification(
    domain: str,
    *,
    policy: Policy = Policy.DENY,
    role: ServiceRole = ServiceRole.UNKNOWN,
    breakage_risk: int = 10,
) -> Classification:
    return Classification(
        domain=domain,
        policy=policy,
        category="advertising",
        short="Synthetic result",
        details="Synthetic result for compatibility testing.",
        provider="fixture",
        tags=("advertising",),
        service_role=role,
        privacy_risk=80,
        security_risk=5,
        breakage_risk=breakage_risk,
        confidence=0.99,
        needs_review=False,
    )


def test_bundled_profiles_cover_verified_core_services() -> None:
    profiles = load_compatibility_profiles()
    profile_ids = {profile.profile_id for profile in profiles}

    assert {
        "microsoft-entra-identity",
        "google-oauth",
        "apple-sign-in",
        "mozilla-account-sync",
        "windows-ncsi",
    }.issubset(profile_ids)
    assert compatibility_match_for_domain("login.microsoftonline.com") is not None
    assert compatibility_match_for_domain("accounts.google.com") is not None
    assert compatibility_match_for_domain("appleid.apple.com") is not None
    assert compatibility_match_for_domain("accounts.firefox.com") is not None


def test_suffix_matching_respects_dns_label_boundaries() -> None:
    match = compatibility_match_for_domain("ipv6.msftconnecttest.com")

    assert match is not None
    assert match.profile.profile_id == "windows-ncsi"
    assert match.match_type == "suffix"
    assert compatibility_match_for_domain("evilmsftconnecttest.com") is None


def test_deny_recommendation_is_hardened_for_protected_service() -> None:
    result = apply_compatibility_profile(_classification("login.microsoftonline.com"))

    assert result.service == "Microsoft Entra identity"
    assert result.service_role is ServiceRole.CORE
    assert result.breakage_risk == 95
    assert result.needs_review is True
    assert "Protected compatibility profile" in result.review_reason
    assert "Microsoft Entra identity" in result.review_reason


def test_compatible_allow_result_is_enriched_without_forcing_review() -> None:
    result = apply_compatibility_profile(
        _classification("accounts.google.com", policy=Policy.ALLOW)
    )

    assert result.service_role is ServiceRole.CORE
    assert result.breakage_risk == 95
    assert result.needs_review is False


def test_profile_prevents_auto_deny_even_when_tag_policy_requests_it() -> None:
    classification = apply_compatibility_profile(
        _classification("accounts.google.com", policy=Policy.ALLOW)
    )
    options = LLMOptions(
        automation_mode="auto",
        auto_action_min_confidence=0.0,
        require_research_for_auto_action=False,
        tag_policies={"advertising": Policy.DENY.value},
    )

    decision = resolve_automatic_decision(
        classification,
        evidence_count=1,
        llm_options=options,
    )

    assert decision.action is None
    assert "Core or shared service infrastructure" in decision.review_reason


def test_compatibility_finding_is_decision_relevant_and_high_quality() -> None:
    finding = compatibility_finding("appleid.apple.com", now=1_700_000_000)

    assert finding is not None
    assert finding.provider == COMPATIBILITY_PROVIDER_NAME
    assert finding.kind == "compatibility_profile"
    assert finding.decision_relevant is True
    assert finding.verdict == "protected_core_service"
    assert finding.raw_data["profile_id"] == "apple-sign-in"
    quality = score_finding(finding, now=1_700_000_001)
    assert quality.source_kind == "compatibility_profile"
    assert quality.source_score == 0.98
    assert quality.evidence_score > 0.98


def test_research_many_persists_local_profile_without_network_sources(
    monkeypatch, tmp_path
) -> None:
    import pihole_manager.research as research_module
    from pihole_manager.database import init_db, research_findings_get

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    monkeypatch.setattr(
        research_module,
        "load_options",
        lambda: SimpleNamespace(
            research_providers=[],
            research=SimpleNamespace(max_age_days=30),
        ),
    )
    init_db()

    output = research_module.research_many(["www.msftconnecttest.com"])

    assert len(output["www.msftconnecttest.com"]) == 1
    assert output["www.msftconnecttest.com"][0].provider == COMPATIBILITY_PROVIDER_NAME
    stored = research_findings_get("www.msftconnecttest.com", fresh_only=True)
    assert len(stored) == 1
    assert stored[0]["kind"] == "compatibility_profile"
    assert stored[0]["verdict"] == "protected_core_service"


def test_pihole_write_guard_requires_explicit_override(monkeypatch) -> None:
    import pihole_manager.pihole_service as pihole_service

    calls: list[dict[str, object]] = []

    class _DomainManagement:
        def add_domain(self, **kwargs):
            calls.append(kwargs)
            return {"ok": True}

    client = SimpleNamespace(domain_management=_DomainManagement())
    monkeypatch.setattr(pihole_service, "get_domain_lock", lambda _domain: None)
    monkeypatch.setattr(pihole_service, "get_client", lambda: client)

    with pytest.raises(RuntimeError, match="explicit compatibility override"):
        pihole_service.add_exact_domain("accounts.google.com", Policy.DENY)
    assert calls == []

    result = pihole_service.add_exact_domain(
        "accounts.google.com",
        Policy.DENY,
        compatibility_override=True,
    )
    assert result == {"ok": True}
    assert calls[0]["domain"] == "accounts.google.com"
    assert calls[0]["domain_type"] == Policy.DENY.value
