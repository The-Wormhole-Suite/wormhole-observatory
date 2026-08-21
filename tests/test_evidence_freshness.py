from __future__ import annotations

import time

from pihole_manager.evidence_freshness import (
    EvidenceFreshnessContext,
    build_freshness_context,
    freshness_decision_for_finding,
)
from pihole_manager.models import Classification, Policy, ResearchFinding, ServiceRole


def _context(
    *,
    tags: tuple[str, ...] = (),
    provider_hours: dict[str, int] | None = None,
) -> EvidenceFreshnessContext:
    return EvidenceFreshnessContext(
        domain="example.test",
        tags=tags,
        global_max_age_hours=30 * 24,
        provider_hours=provider_hours or {"rdap registration data": 168},
        provider_kinds={"rdap registration data": "rdap"},
        tag_max_age_hours={
            "malware": 6,
            "phishing": 6,
            "authentication": 72,
            "unknown": 24,
        },
    )


def _finding(
    *,
    retrieved_at: int = 1_700_000_000,
    expires_at: int = 0,
    provider: str = "RDAP registration data",
    kind: str = "registration",
    source_kind: str = "rdap",
) -> ResearchFinding:
    return ResearchFinding(
        domain="example.test",
        provider=provider,
        kind=kind,
        title="Evidence",
        summary="Synthetic evidence.",
        confidence=0.9,
        retrieved_at=retrieved_at,
        expires_at=expires_at,
        raw_data={"wormhole_source_kind": source_kind},
    )


def test_source_refresh_interval_is_freshness_ceiling() -> None:
    finding = _finding()

    decision = freshness_decision_for_finding(finding, _context())

    assert decision.source_kind == "rdap"
    assert decision.source_max_age_hours == 168
    assert decision.tag_max_age_hours is None
    assert decision.effective_expires_at == finding.retrieved_at + 168 * 3600


def test_existing_shorter_provider_expiry_is_never_extended() -> None:
    finding = _finding(expires_at=1_700_000_000 + 3600)

    decision = freshness_decision_for_finding(finding, _context())

    assert decision.effective_expires_at == finding.expires_at
    assert decision.original_expires_at == finding.expires_at


def test_security_tag_shortens_long_lived_source() -> None:
    finding = _finding()

    decision = freshness_decision_for_finding(
        finding,
        _context(tags=("malware", "analytics")),
    )

    assert decision.tag_max_age_hours == 6
    assert decision.matched_tags == ("malware",)
    assert decision.effective_expires_at == finding.retrieved_at + 6 * 3600


def test_compatibility_profile_ignores_domain_tag_ceiling() -> None:
    retrieved_at = 1_700_000_000
    finding = _finding(
        retrieved_at=retrieved_at,
        expires_at=retrieved_at + 365 * 86400,
        provider="Wormhole compatibility profiles",
        kind="compatibility_profile",
        source_kind="compatibility_profile",
    )

    decision = freshness_decision_for_finding(finding, _context(tags=("malware",)))

    assert decision.source_max_age_hours == 8760
    assert decision.tag_max_age_hours is None
    assert decision.matched_tags == ()
    assert decision.effective_expires_at == finding.expires_at


def test_manual_tags_are_used_before_llm_tags(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import init_db, save_classification_run, set_manual_tags

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    classification = Classification(
        domain="example.test",
        policy=Policy.ALLOW,
        category="analytics",
        short="Synthetic",
        details="Synthetic",
        provider="fixture",
        tags=("analytics",),
        service_role=ServiceRole.OPTIONAL,
        confidence=0.9,
    )
    save_classification_run(classification)
    set_manual_tags(classification.domain, ["malware"])

    context = build_freshness_context(classification.domain)

    assert context.tags == ("malware",)


def test_save_persists_effective_freshness_metadata(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import (
        init_db,
        research_findings_get,
        save_research_findings,
        set_manual_tags,
    )

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    set_manual_tags("example.test", ["malware"])
    retrieved_at = int(time.time())

    save_research_findings([_finding(retrieved_at=retrieved_at)])
    rows = research_findings_get("example.test", fresh_only=False)

    assert len(rows) == 1
    policy = rows[0]["raw_data"]["freshness_policy"]
    assert policy["source_kind"] == "rdap"
    assert policy["tag_max_age_hours"] == 6
    assert policy["matched_tags"] == ["malware"]
    assert rows[0]["expires_at"] == retrieved_at + 6 * 3600


def test_fresh_only_retroactively_rejects_legacy_row(monkeypatch, tmp_path) -> None:
    from pihole_manager import database_features
    from pihole_manager.database import init_db, research_findings_get, set_manual_tags

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    set_manual_tags("example.test", ["malware"])
    now = int(time.time())
    legacy = _finding(
        retrieved_at=now - 7 * 3600,
        expires_at=now + 7 * 86400,
    )
    database_features.save_research_findings([legacy], default_max_age_days=30)

    all_rows = research_findings_get("example.test", fresh_only=False)
    fresh_rows = research_findings_get("example.test", fresh_only=True)

    assert len(all_rows) == 1
    assert fresh_rows == []


def test_first_seen_domain_without_tags_uses_source_policy(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import init_db

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()

    context = build_freshness_context("new.example.test")
    decision = freshness_decision_for_finding(
        _finding(provider="RDAP registration data"),
        context,
    )

    assert context.tags == ()
    assert decision.source_max_age_hours == 168
    assert decision.tag_max_age_hours is None
