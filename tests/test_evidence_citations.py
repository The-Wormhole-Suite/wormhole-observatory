from __future__ import annotations

import time

from pihole_manager.evidence_citations import attach_evidence_citations
from pihole_manager.models import Classification, Policy, ResearchFinding
from pihole_manager.provider_api import ProviderCitation


def _classification(domain: str, *, needs_review: bool = False) -> Classification:
    return Classification(
        domain=domain,
        policy=Policy.ALLOW,
        category="unknown",
        short="Example endpoint",
        details="Generated explanation.",
        provider="test",
        needs_review=needs_review,
    )


def test_domain_specific_findings_are_attached_without_cross_contamination() -> None:
    classifications = [_classification("one.example"), _classification("two.example")]
    dossiers = [
        {
            "domain": "one.example",
            "findings": [
                {
                    "provider": "RDAP",
                    "title": "Registration record",
                    "source_url": "https://rdap.example/one",
                }
            ],
        },
        {
            "domain": "two.example",
            "findings": [
                {
                    "provider": "Threat feed",
                    "title": "Threat record",
                    "source_url": "https://threat.example/two",
                }
            ],
        },
    ]

    result = attach_evidence_citations(
        classifications,
        dossiers,
        provider_citations=(
            ProviderCitation(url="https://web.example/batch", title="Batch web source"),
        ),
    )

    assert "https://rdap.example/one" in result[0].details
    assert "https://threat.example/two" not in result[0].details
    assert "https://web.example/batch" not in result[0].details
    assert "https://threat.example/two" in result[1].details
    assert "https://rdap.example/one" not in result[1].details


def test_single_domain_includes_provider_native_web_citations() -> None:
    result = attach_evidence_citations(
        [_classification("one.example")],
        [
            {
                "domain": "one.example",
                "findings": [
                    {
                        "provider": "RDAP",
                        "title": "Registration record",
                        "source_url": "https://rdap.example/one",
                    }
                ],
            }
        ],
        provider_citations=(
            ProviderCitation(url="https://primary.example/doc", title="Primary documentation"),
        ),
    )[0]

    assert "Evidence citations:" in result.details
    assert "[E1] RDAP — Registration record — https://rdap.example/one" in result.details
    assert "Web — Primary documentation — https://primary.example/doc" in result.details


def test_source_without_url_is_still_a_traceable_evidence_reference() -> None:
    result = attach_evidence_citations(
        [_classification("one.example")],
        [
            {
                "domain": "one.example",
                "findings": [
                    {
                        "provider": "Local list index",
                        "title": "Matched curated list",
                        "source_url": "",
                    }
                ],
            }
        ],
    )[0]

    assert "[E1] Local list index — Matched curated list" in result.details
    assert result.needs_review is False


def test_missing_evidence_marks_generated_description_for_review() -> None:
    result = attach_evidence_citations(
        [_classification("empty.example")],
        [{"domain": "empty.example", "findings": []}],
    )[0]

    assert "Evidence citations:\n[none] No evidence finding was supplied." in result.details
    assert result.needs_review is True
    assert "No citable evidence finding" in result.review_reason


def test_citation_section_is_idempotent() -> None:
    dossier = {
        "domain": "one.example",
        "findings": [
            {
                "provider": "RDAP",
                "title": "Registration record",
                "source_url": "https://rdap.example/one",
            }
        ],
    }
    first = attach_evidence_citations([_classification("one.example")], [dossier])[0]
    second = attach_evidence_citations([first], [dossier])[0]

    assert second.details == first.details
    assert second.details.count("Evidence citations:") == 1


def test_classification_persistence_attaches_fresh_domain_evidence(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import (
        classification_history,
        init_db,
        review_get,
        save_classification_run,
        save_research_findings,
    )

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    now = int(time.time())
    save_research_findings(
        [
            ResearchFinding(
                domain="persist.example",
                provider="RDAP",
                kind="registration",
                title="Registration record",
                summary="Registration evidence",
                source_url="https://rdap.example/persist",
                confidence=0.9,
                retrieved_at=now,
                expires_at=now + 3600,
            )
        ]
    )

    save_classification_run(_classification("persist.example"))

    history = classification_history("persist.example")
    review = review_get()[0]
    assert "Evidence citations:" in history[0]["details"]
    assert "https://rdap.example/persist" in history[0]["details"]
    assert review["details"] == history[0]["details"]


def test_benchmark_persistence_attaches_fresh_domain_evidence(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import (
        benchmark_result_save,
        benchmark_run_get,
        benchmark_run_start,
        init_db,
        save_research_findings,
    )

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    now = int(time.time())
    save_research_findings(
        [
            ResearchFinding(
                domain="benchmark.example",
                provider="Threat feed",
                kind="threat_intelligence",
                title="Threat record",
                summary="Threat evidence",
                source_url="https://threat.example/benchmark",
                confidence=0.95,
                retrieved_at=now,
                expires_at=now + 3600,
            )
        ]
    )
    run_id = benchmark_run_start(
        "benchmark.example",
        "background",
        {"domain": "benchmark.example"},
        "dossier-hash",
    )

    benchmark_result_save(
        run_id,
        provider_id="provider",
        provider_name="Provider",
        model="model",
        status="completed",
        classification=_classification("benchmark.example"),
    )

    run = benchmark_run_get(run_id)
    assert run is not None
    details = run["results"][0]["classification"]["details"]
    assert "Evidence citations:" in details
    assert "https://threat.example/benchmark" in details
