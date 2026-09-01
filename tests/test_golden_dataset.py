from __future__ import annotations

import json

import pytest

from pihole_manager.golden_dataset import (
    compare_variants,
    evaluate_benchmark_run,
    evaluate_classification,
    evaluate_sources,
    load_golden_dataset,
)
from pihole_manager.models import Classification, Policy, ServiceRole


def _good_advertising_classification() -> Classification:
    return Classification(
        domain="ads.cross-site.test",
        policy=Policy.DENY,
        category="advertising",
        short="Advertising tracker",
        details="Synthetic golden result.",
        provider="fixture",
        tags=("advertising", "cross_site_tracking"),
        service_role=ServiceRole.OPTIONAL,
        privacy_risk=95,
        security_risk=10,
        breakage_risk=15,
        confidence=0.97,
        needs_review=False,
    )


def _bad_advertising_classification() -> Classification:
    return Classification(
        domain="ads.cross-site.test",
        policy=Policy.ALLOW,
        category="authentication",
        short="Incorrect result",
        details="Synthetic negative control.",
        provider="fixture",
        tags=("authentication",),
        service_role=ServiceRole.CORE,
        privacy_risk=5,
        security_risk=90,
        breakage_risk=95,
        confidence=0.99,
        needs_review=True,
    )


def test_bundled_dataset_is_versioned_and_source_consistent() -> None:
    dataset = load_golden_dataset()

    assert dataset.schema_version == 1
    assert dataset.dataset_id == "wormhole-domain-intelligence-core-v1"
    assert len(dataset.cases) == 4
    assert dataset.case_for_domain("ADS.CROSS-SITE.TEST.") is not None
    for case in dataset.cases:
        score = evaluate_sources(case)
        assert score.total > 0
        assert score.score == 1.0, (case.case_id, score.failures)


def test_classification_score_accepts_expected_variant() -> None:
    dataset = load_golden_dataset()
    case = dataset.case_by_id("cross-site-advertising")
    assert case is not None

    score = evaluate_classification(case, _good_advertising_classification())

    assert score.total > 0
    assert score.score == 1.0
    assert score.failures == ()


def test_classification_score_reports_actionable_regressions() -> None:
    dataset = load_golden_dataset()
    case = dataset.case_by_id("cross-site-advertising")
    assert case is not None

    score = evaluate_classification(case, _bad_advertising_classification())

    assert score.score < 0.5
    assert any("policy=" in failure for failure in score.failures)
    assert any("missing required tag" in failure for failure in score.failures)
    assert any("forbidden tag present" in failure for failure in score.failures)
    assert any("privacy_risk=" in failure for failure in score.failures)


def test_compare_variants_ranks_prompt_or_model_variants() -> None:
    dataset = load_golden_dataset()
    case = dataset.case_by_id("cross-site-advertising")
    assert case is not None

    results = compare_variants(
        case,
        {
            "prompt-v2 / model-good": _good_advertising_classification(),
            "prompt-v1 / model-bad": _bad_advertising_classification(),
        },
    )

    assert results[0].variant_id == "prompt-v2 / model-good"
    assert results[0].score == 1.0
    assert results[1].variant_id == "prompt-v1 / model-bad"
    assert results[1].score < results[0].score


def test_existing_benchmark_run_shape_can_be_scored_directly() -> None:
    dataset = load_golden_dataset()
    case = dataset.case_by_id("cross-site-advertising")
    assert case is not None
    good = _good_advertising_classification()
    bad = _bad_advertising_classification()

    run = {
        "domain": case.domain,
        "dossier": case.dossier,
        "results": [
            {
                "provider_name": "Provider Good",
                "model": "model-a",
                "status": "completed",
                "classification": {
                    "policy": good.policy.value,
                    "category": good.category,
                    "tags": list(good.tags),
                    "service_role": good.service_role.value,
                    "privacy_risk": good.privacy_risk,
                    "security_risk": good.security_risk,
                    "breakage_risk": good.breakage_risk,
                    "needs_review": good.needs_review,
                },
            },
            {
                "provider_name": "Provider Bad",
                "model": "model-b",
                "status": "completed",
                "classification": {
                    "policy": bad.policy.value,
                    "category": bad.category,
                    "tags": list(bad.tags),
                    "service_role": bad.service_role.value,
                    "privacy_risk": bad.privacy_risk,
                    "security_risk": bad.security_risk,
                    "breakage_risk": bad.breakage_risk,
                    "needs_review": bad.needs_review,
                },
            },
            {
                "provider_name": "Failed Provider",
                "model": "model-c",
                "status": "failed",
                "classification": {},
            },
        ],
    }

    results = evaluate_benchmark_run(dataset, run)

    assert [item.variant_id for item in results] == [
        "Provider Good / model-a",
        "Provider Bad / model-b",
    ]
    assert results[0].score == 1.0
    assert results[1].score < results[0].score


def test_custom_dataset_rejects_unsupported_schema(tmp_path) -> None:
    path = tmp_path / "golden.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 99,
                "dataset_id": "future",
                "cases": [
                    {
                        "case_id": "case",
                        "domain": "example.test",
                        "dossier": {"domain": "example.test", "findings": []},
                        "expected": {},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Unsupported golden dataset schema version"):
        load_golden_dataset(path)
