from __future__ import annotations

from pihole_manager.evidence_quality import (
    annotate_source_kind,
    detect_contradictions,
    quality_summary,
    score_finding,
)
from pihole_manager.models import ResearchFinding


def _finding(
    provider: str,
    verdict: str,
    *,
    kind: str = "threat_intelligence",
    signal_type: str = "security",
    confidence: float = 0.9,
    source_kind: str = "virustotal",
) -> ResearchFinding:
    finding = ResearchFinding(
        domain="example.com",
        provider=provider,
        kind=kind,
        title=f"{provider}: {verdict}",
        summary="Synthetic evidence used by the quality tests.",
        confidence=confidence,
        signal_type=signal_type,
        verdict=verdict,
        decision_relevant=True,
        retrieved_at=100,
        expires_at=10_000_000_000,
    )
    return annotate_source_kind(finding, source_kind)


def test_source_quality_distinguishes_verified_feed_from_experimental_html() -> None:
    verified = _finding(
        "PhishTank",
        "phishing",
        kind="phishing_database",
        confidence=0.98,
        source_kind="phishtank",
    )
    experimental = _finding(
        "Netcraft",
        "site_context",
        kind="site_infrastructure",
        signal_type="infrastructure",
        confidence=0.95,
        source_kind="netcraft",
    )

    verified_score = score_finding(verified, now=200)
    experimental_score = score_finding(experimental, now=200)

    assert verified_score.source_score > experimental_score.source_score
    assert verified_score.evidence_score > experimental_score.evidence_score
    assert verified_score.tier == "very_high"


def test_source_kind_annotation_preserves_provider_payload() -> None:
    original = ResearchFinding(
        domain="example.com",
        provider="Source",
        kind="test",
        title="Title",
        summary="Summary",
        raw_data={"provider_field": "value"},
    )

    annotated = annotate_source_kind(original, "rdap")

    assert annotated.raw_data["provider_field"] == "value"
    assert annotated.raw_data["wormhole_source_kind"] == "rdap"
    assert original.raw_data == {"provider_field": "value"}


def test_missing_detection_does_not_contradict_malicious_evidence() -> None:
    findings = [
        _finding("Threat feed", "malicious", source_kind="threatfox"),
        _finding("Scanner", "no_detection", confidence=0.6, source_kind="virustotal"),
    ]

    assert detect_contradictions(findings) == []


def test_explicit_safe_and_malicious_claims_are_reported_as_contradiction() -> None:
    findings = [
        _finding("Threat feed", "malicious", confidence=0.98, source_kind="threatfox"),
        _finding("Trust feed", "benign", confidence=0.96, source_kind="phishtank"),
    ]

    contradictions = detect_contradictions(findings)

    assert len(contradictions) == 1
    contradiction = contradictions[0]
    assert contradiction.dimension == "security"
    assert contradiction.severity == "high"
    assert contradiction.confidence >= 0.8
    assert "Threat feed" in contradiction.reason
    assert "Trust feed" in contradiction.reason


def test_quality_summary_counts_high_quality_and_conflicts() -> None:
    findings = [
        _finding("Threat feed", "malicious", source_kind="threatfox"),
        _finding("Trust feed", "safe", source_kind="phishtank"),
    ]

    summary = quality_summary(findings)

    assert summary["high_quality_count"] == 2
    assert summary["contradiction_count"] == 1
    assert summary["high_severity_contradiction_count"] == 1


def test_research_context_exposes_scores_and_contradictions_to_llm_dossier() -> None:
    from pihole_manager.research import research_context

    findings = [
        _finding("Threat feed", "malicious", source_kind="threatfox"),
        _finding("Trust feed", "safe", source_kind="phishtank"),
    ]

    context = research_context("example.com", findings=findings)

    assert context["quality"]["contradiction_count"] == 1
    assert context["contradictions"][0]["severity"] == "high"
    assert context["findings"][0]["source_quality"] > 0
    assert context["findings"][0]["evidence_quality"] > 0
    assert context["findings"][0]["quality_tier"] in {"high", "very_high"}
