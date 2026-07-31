from __future__ import annotations

from types import SimpleNamespace


def test_worker_batch_is_split_into_llm_request_batches() -> None:
    from pihole_manager.workers import _chunks

    domains = [f"domain-{index}.example" for index in range(25)]
    batches = list(_chunks(domains, 10))

    assert [len(batch) for batch in batches] == [10, 10, 5]
    assert [domain for batch in batches for domain in batch] == domains


def test_scanner_collects_domains_and_keeps_fractional_cursor(monkeypatch) -> None:
    from pihole_manager import workers

    options = SimpleNamespace(
        scans=SimpleNamespace(
            enabled=True,
            interval_sec=1,
            batch_size=200,
            initial_lookback_sec=300,
            history_backfill_enabled=False,
            history_idle_after_sec=300,
        )
    )
    states: dict[str, str] = {}
    queued: list[set[str]] = []
    rows = [
        {"time": 1000.125, "domain": "one.example"},
        {"time": 1000.875, "domain": "two.example"},
    ]

    monkeypatch.setattr(workers, "load_options", lambda: options)
    monkeypatch.setattr(workers.time, "time", lambda: 1001.0)
    monkeypatch.setattr(
        workers,
        "get_state",
        lambda key, default="": "1000.124" if key == "scanner_from_ts" else default,
    )
    monkeypatch.setattr(workers, "set_state", lambda key, value: states.__setitem__(key, value))
    monkeypatch.setattr(
        workers,
        "test_connection",
        lambda: SimpleNamespace(success=True, summary="OK"),
    )
    requested_from: list[float] = []

    def fetch_rows(_length: int, from_ts: float):
        requested_from.append(from_ts)
        return rows

    monkeypatch.setattr(workers, "fetch_queries", fetch_rows)
    monkeypatch.setattr(workers, "record_query_observations", lambda _rows: 2)
    monkeypatch.setattr(
        workers,
        "queue_domains_needing_analysis",
        lambda domains: queued.append(set(domains)) or len(domains),
    )
    monkeypatch.setattr(workers, "queue_due_rechecks", lambda **_kwargs: 0)

    scanner = workers.Scanner()

    def stop_after_cycle(_seconds: float) -> bool:
        scanner.stop()
        return True

    monkeypatch.setattr(scanner, "wait", stop_after_cycle)
    scanner.run()

    assert requested_from == [1000.0]
    assert queued == [{"one.example", "two.example"}]
    assert float(states["scanner_from_ts"]) == 1000.876


def test_manual_queue_source_forces_review(monkeypatch, tmp_path) -> None:
    from pihole_manager import workers
    from pihole_manager.config import Options
    from pihole_manager.database import init_db, review_get
    from pihole_manager.models import Classification, Policy, ServiceRole

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    options = Options()
    options.llm.automation_mode = "hybrid"
    options.llm.simulation_mode = True
    monkeypatch.setattr(workers, "load_options", lambda: options)

    classification = Classification(
        domain="manual.example",
        policy=Policy.ALLOW,
        category="content_media",
        tags=("content_media",),
        service="Example",
        service_role=ServiceRole.OPTIONAL,
        privacy_risk=0,
        security_risk=0,
        breakage_risk=0,
        confidence=0.99,
        needs_review=False,
        review_reason="",
        recheck_after_days=30,
        short="Legitimate content endpoint",
        details="Serves content.",
        provider="test",
        raw_text="{}",
    )

    classifier = workers.Classifier()
    classifier._handle_classification(
        classification,
        {"domain": "manual.example", "research": {"decision_relevant_count": 1}},
        queue_source="manual_live_query",
    )

    rows = review_get(needs_review=True)
    assert len(rows) == 1
    assert rows[0]["domain"] == "manual.example"
    assert rows[0]["review_reason"] == "Manually queued for review."
    assert rows[0]["planned_action"] == ""


def test_compare_result_is_history_only(monkeypatch, tmp_path) -> None:
    from pihole_manager import workers
    from pihole_manager.analysis_dispatcher import (
        AnalysisDispatchResult,
        ProviderAnalysisResult,
    )
    from pihole_manager.config import load_options
    from pihole_manager.database import (
        classification_history,
        domains_without_classification,
        init_db,
        review_get,
    )
    from pihole_manager.models import Classification, Policy, ProviderUsage

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    options = load_options()
    provider = options.llm_providers[0]
    provider.base_url = "https://provider.example/v1"
    provider.model = "model"
    init_db()
    classification = Classification(
        domain="compare.example",
        policy=Policy.DENY,
        category="advertising",
        tags=("advertising",),
        short="Comparison",
        details="History only",
        provider=provider.name,
        confidence=0.99,
        needs_review=False,
    )
    result = AnalysisDispatchResult(
        run_id="compare-run",
        pool_id="background",
        mode="compare",
        dossier_hash="hash",
        provider_results=(
            ProviderAnalysisResult(
                provider_id=provider.provider_id,
                provider_name=provider.name,
                model=provider.model,
                profile_name=options.prompt_profiles[0].name,
                limit_source="test",
                classifications=(classification,),
                latency_ms=10,
                usage=ProviderUsage(input_tokens=8, output_tokens=4, total_tokens=12),
                is_primary=False,
            ),
        ),
    )

    completed = workers.Classifier()._handle_dispatch_result(
        result,
        [{"domain": "compare.example"}],
        queue_sources={},
        options=options,
    )

    assert completed == {"compare.example"}
    assert review_get() == []
    history = classification_history("compare.example")
    assert len(history) == 1
    assert history[0]["is_primary"] == 0
    assert history[0]["provider_id"] == provider.provider_id
    assert domains_without_classification(["compare.example"]) == {"compare.example"}
    assert workers.queue_domains_needing_analysis(["compare.example"]) == 0
