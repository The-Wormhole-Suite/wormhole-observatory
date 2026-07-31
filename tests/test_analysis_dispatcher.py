from __future__ import annotations

from dataclasses import replace

import pytest

from pihole_manager import analysis_dispatcher
from pihole_manager.analysis_dispatcher import (
    ProviderAnalysisResult,
    ProviderPartialAnalysisError,
    dispatch_analysis,
)
from pihole_manager.config import (
    AnalysisPoolOptions,
    LLMProviderOptions,
    Options,
    ProviderPoolMembershipOptions,
)
from pihole_manager.database import init_db, provider_health_failure
from pihole_manager.models import Classification, Policy, ProviderUsage
from pihole_manager.quota import QuotaUnavailableError


def _classification(
    domain: str,
    provider_name: str,
    *,
    policy: Policy = Policy.DENY,
    category: str = "advertising",
) -> Classification:
    return Classification(
        domain=domain,
        policy=policy,
        category=category,
        tags=(category,),
        short="result",
        details="details",
        provider=provider_name,
        confidence=0.99,
        needs_review=False,
        breakage_risk=10,
    )


def _options(mode: str, *, roles: tuple[str, ...] = ("primary", "fallback")) -> Options:
    options = Options()
    options.llm_providers = [
        LLMProviderOptions(
            provider_id=f"provider-{index}",
            name=f"Provider {index}",
            base_url=f"https://provider-{index}.example/v1",
            model=f"model-{index}",
            structured_output="prompt_only",
        )
        for index in range(len(roles))
    ]
    memberships = [
        ProviderPoolMembershipOptions(
            provider_id=provider.provider_id,
            role=roles[index],
            priority=index,
        )
        for index, provider in enumerate(options.llm_providers)
    ]
    options.analysis_pools = [
        AnalysisPoolOptions(
            pool_id="realtime",
            name="Realtime",
            mode=mode,
            max_parallel_requests=4,
            memberships=memberships,
        ),
        AnalysisPoolOptions(
            pool_id="background",
            name="Background",
            mode=mode,
            max_parallel_requests=4,
            memberships=memberships,
        ),
    ]
    return options


def _provider_result(candidate, domains, *, is_primary: bool) -> ProviderAnalysisResult:
    return ProviderAnalysisResult(
        provider_id=candidate.provider.provider_id,
        provider_name=candidate.provider.name,
        model=candidate.provider.model,
        profile_name="Balanced",
        limit_source="test",
        classifications=tuple(
            _classification(domain, candidate.provider.name) for domain in domains
        ),
        latency_ms=10,
        usage=ProviderUsage(input_tokens=5, output_tokens=5, total_tokens=10),
        is_primary=is_primary,
    )


def test_distribute_sends_each_domain_to_exactly_one_provider(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    options = _options("distribute", roles=("primary", "primary"))

    def execute(_pool, candidate, domains, _dossiers, _options, *, is_primary):
        return _provider_result(candidate, domains, is_primary=is_primary)

    monkeypatch.setattr(analysis_dispatcher, "_execute_provider", execute)
    domains = [f"domain-{index}.example" for index in range(20)]

    result = dispatch_analysis(
        "background",
        domains,
        [{"domain": domain, "evidence": "same snapshot"} for domain in domains],
        options=options,
    )

    returned = [
        classification.domain
        for provider_result in result.provider_results
        for classification in provider_result.classifications
    ]
    assert sorted(returned) == sorted(domains)
    assert len(returned) == len(set(returned))
    assert all(provider_result.is_primary for provider_result in result.provider_results)


def test_fallback_only_uses_second_provider_for_operational_failure(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    options = _options("fallback")
    calls: list[str] = []

    def execute(_pool, candidate, domains, _dossiers, _options, *, is_primary):
        calls.append(candidate.provider.provider_id)
        if len(calls) == 1:
            raise QuotaUnavailableError("quota", retry_at=2000)
        return _provider_result(candidate, domains, is_primary=is_primary)

    monkeypatch.setattr(analysis_dispatcher, "_execute_provider", execute)

    result = dispatch_analysis(
        "realtime",
        ["example.com"],
        [{"domain": "example.com"}],
        options=options,
    )

    assert calls == ["provider-0", "provider-1"]
    assert result.provider_results[0].provider_id == "provider-1"
    assert len(result.errors) == 1


def test_dispatch_defers_when_every_provider_is_in_cooldown(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    options = _options("fallback")
    provider_health_failure(
        "provider-0",
        "temporarily unavailable",
        cooldown_until=2000,
    )
    provider_health_failure(
        "provider-1",
        "temporarily unavailable",
        cooldown_until=3000,
    )
    monkeypatch.setattr(analysis_dispatcher.time, "time", lambda: 1000)

    with pytest.raises(analysis_dispatcher.AnalysisUnavailableError) as error:
        dispatch_analysis(
            "realtime",
            ["example.com"],
            [{"domain": "example.com"}],
            options=options,
        )

    assert error.value.retry_at == 2000


def test_fallback_does_not_multiply_invalid_output_requests(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    options = _options("fallback")
    calls: list[str] = []

    def execute(_pool, candidate, _domains, _dossiers, _options, *, is_primary):
        calls.append(candidate.provider.provider_id)
        raise ValueError("invalid structured output")

    monkeypatch.setattr(analysis_dispatcher, "_execute_provider", execute)

    with pytest.raises(ValueError, match="invalid structured output"):
        dispatch_analysis(
            "realtime",
            ["example.com"],
            [{"domain": "example.com"}],
            options=options,
        )
    assert calls == ["provider-0"]


def test_fallback_continues_only_unfinished_domains_after_partial_result(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    options = _options("fallback")
    calls: list[tuple[str, tuple[str, ...]]] = []

    def execute(_pool, candidate, domains, _dossiers, _options, *, is_primary):
        calls.append((candidate.provider.provider_id, tuple(domains)))
        if candidate.provider.provider_id == "provider-0":
            partial = _provider_result(
                candidate,
                [domains[0]],
                is_primary=is_primary,
            )
            raise ProviderPartialAnalysisError(
                partial,
                domains[1:],
                QuotaUnavailableError("quota", retry_at=2000),
            )
        return _provider_result(candidate, domains, is_primary=is_primary)

    monkeypatch.setattr(analysis_dispatcher, "_execute_provider", execute)

    result = dispatch_analysis(
        "realtime",
        ["one.example", "two.example"],
        [{"domain": "one.example"}, {"domain": "two.example"}],
        options=options,
    )

    assert calls == [
        ("provider-0", ("one.example", "two.example")),
        ("provider-1", ("two.example",)),
    ]
    assert result.primary_classifications().keys() == {
        "one.example",
        "two.example",
    }


def test_compare_keeps_all_results_side_by_side_without_a_primary(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    options = _options("compare", roles=("primary", "primary"))
    dossier_ids: list[int] = []

    def execute(_pool, candidate, domains, dossiers, _options, *, is_primary):
        dossier_ids.append(id(dossiers))
        return _provider_result(candidate, domains, is_primary=is_primary)

    monkeypatch.setattr(analysis_dispatcher, "_execute_provider", execute)

    result = dispatch_analysis(
        "background",
        ["example.com"],
        [{"domain": "example.com", "evidence": {"stable": True}}],
        options=options,
    )

    assert len(result.provider_results) == 2
    assert not result.primary_classifications()
    assert all(not item.is_primary for item in result.provider_results)
    assert len(dossier_ids) == 2


def test_verify_marks_disagreement_for_manual_review(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    options = _options("verify", roles=("primary", "verifier"))
    options.analysis_pools[1].verification_sample_percent = 100

    def execute(_pool, candidate, domains, _dossiers, _options, *, is_primary):
        result = _provider_result(candidate, domains, is_primary=is_primary)
        if candidate.membership.role == "verifier":
            return replace(
                result,
                classifications=tuple(
                    _classification(
                        domain,
                        candidate.provider.name,
                        policy=Policy.ALLOW,
                        category="api_backend",
                    )
                    for domain in domains
                ),
            )
        return result

    monkeypatch.setattr(analysis_dispatcher, "_execute_provider", execute)

    result = dispatch_analysis(
        "background",
        ["example.com"],
        [{"domain": "example.com"}],
        options=options,
    )

    primary = result.primary_classifications()["example.com"]
    assert primary.needs_review is True
    assert "disagreed" in primary.review_reason
    assert len(result.provider_results) == 2


def test_verify_keeps_partial_secondary_results_and_marks_only_missing_domains(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    options = _options("verify", roles=("primary", "verifier"))
    options.analysis_pools[1].verification_sample_percent = 100

    def execute(_pool, candidate, domains, _dossiers, _options, *, is_primary):
        result = _provider_result(candidate, domains, is_primary=is_primary)
        if candidate.membership.role == "verifier":
            partial = replace(
                result,
                classifications=(
                    _classification(
                        domains[0],
                        candidate.provider.name,
                        policy=Policy.ALLOW,
                        category="api_backend",
                    ),
                ),
            )
            raise ProviderPartialAnalysisError(
                partial,
                domains[1:],
                QuotaUnavailableError("quota", retry_at=2000),
            )
        return result

    monkeypatch.setattr(analysis_dispatcher, "_execute_provider", execute)

    result = dispatch_analysis(
        "background",
        ["verified.example", "missing.example"],
        [
            {"domain": "verified.example"},
            {"domain": "missing.example"},
        ],
        options=options,
    )

    primary = result.primary_classifications()
    assert primary["verified.example"].needs_review is True
    assert "disagreed" in primary["verified.example"].review_reason
    assert primary["missing.example"].needs_review is True
    assert "unavailable" in primary["missing.example"].review_reason
    assert len(result.provider_results) == 2
    assert [item.domain for item in result.provider_results[1].classifications] == [
        "verified.example"
    ]
    assert len(result.errors) == 1
