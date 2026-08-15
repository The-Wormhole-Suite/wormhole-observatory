from __future__ import annotations

from pihole_manager.database import (
    init_db,
    review_get,
    review_save,
    staging_ack,
    staging_claim,
    staging_enqueue,
    staging_fail,
    staging_list,
    staging_requeue_processing,
)


def test_staging_queue_uses_claim_ack_and_retry(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()

    assert staging_enqueue(["Example.COM.", "example.com", "tracker.test"]) == 2
    assert staging_claim(1) == ["example.com"]
    assert staging_list()[0]["state"] == "processing"

    staging_fail("example.com", "temporary failure", max_attempts=3)
    rows = {row["domain"]: row for row in staging_list()}
    assert rows["example.com"]["state"] == "queued"
    assert rows["example.com"]["attempts"] == 1

    claimed = staging_claim(10)
    assert claimed == ["example.com", "tracker.test"]
    staging_ack("example.com")
    assert staging_requeue_processing() == 1
    rows = staging_list()
    assert [row["domain"] for row in rows] == ["tracker.test"]
    assert rows[0]["state"] == "queued"


def test_staging_defer_hides_item_until_provider_reset(monkeypatch, tmp_path) -> None:
    from time import time

    from pihole_manager.database import staging_defer, staging_ready

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    staging_enqueue(["quota.example"], pool_id="background")
    assert staging_claim(1, pool_id="background") == ["quota.example"]

    retry_at = time() + 60
    staging_defer("quota.example", "quota exhausted", retry_at)

    row = staging_list()[0]
    assert row["state"] == "queued"
    assert row["attempts"] == 0
    assert row["available_at"] >= int(retry_at)
    assert not staging_ready(1, 1, pool_id="background")
    assert staging_claim(1, pool_id="background") == []


def test_legacy_staging_table_migrates_before_pool_index_creation(
    monkeypatch,
    tmp_path,
) -> None:
    import sqlite3

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    connection = sqlite3.connect(tmp_path / "pihole_manager.sqlite3")
    connection.executescript(
        """
        CREATE TABLE schema_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        INSERT INTO schema_meta(key, value) VALUES ('schema_version', '7');
        CREATE TABLE staging_domains (
            domain TEXT PRIMARY KEY,
            state TEXT NOT NULL DEFAULT 'queued',
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            last_error TEXT NOT NULL DEFAULT ''
        );
        INSERT INTO staging_domains(
            domain, state, attempts, created_at, updated_at, last_error
        ) VALUES ('legacy.example', 'queued', 0, 1, 1, '');
        """
    )
    connection.commit()
    connection.close()

    init_db()

    row = staging_list()[0]
    assert row["pool_id"] == "background"
    assert row["available_at"] == 0

    connection = sqlite3.connect(tmp_path / "pihole_manager.sqlite3")
    version = connection.execute(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
    ).fetchone()[0]
    connection.close()
    assert version == "11"


def test_schema_migration_rolls_back_on_failure(monkeypatch, tmp_path) -> None:
    import sqlite3

    import pytest

    import pihole_manager.database_core as database_core

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()

    database = tmp_path / "pihole_manager.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute(
        "UPDATE schema_meta SET value = '10' WHERE key = 'schema_version'"
    )
    connection.commit()
    connection.close()

    def failing_migration(connection):
        connection.execute("CREATE TABLE migration_should_rollback (id INTEGER)")
        raise RuntimeError("simulated migration failure")

    monkeypatch.setitem(database_core.SCHEMA_MIGRATIONS, 11, failing_migration)

    with pytest.raises(RuntimeError, match="simulated migration failure"):
        init_db()

    connection = sqlite3.connect(database)
    version = connection.execute(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
    ).fetchone()[0]
    table = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
        ("migration_should_rollback",),
    ).fetchone()
    connection.close()

    assert version == "10"
    assert table is None


def test_review_fields_remain_separate(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()

    review_save(
        "cdn.example",
        ["CDN", "content"],
        "Detailed rationale",
        status="classified",
        policy="allow",
        short="Required content delivery network",
        provider="Local model",
    )

    row = review_get()[0]
    assert row["domain"] == "cdn.example"
    assert row["categories"] == ["cdn", "content"]
    assert row["policy"] == "allow"
    assert row["short"] == "Required content delivery network"
    assert row["details"] == "Detailed rationale"
    assert row["provider"] == "Local model"


def test_classification_history_tags_and_lock(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import (
        classification_history,
        get_domain_lock,
        remove_domain_lock,
        save_classification_run,
        set_domain_lock,
    )
    from pihole_manager.models import Classification, Policy, ServiceRole

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    classification = Classification(
        domain="telemetry.example.com",
        policy=Policy.DENY,
        category="telemetry",
        tags=("telemetry", "analytics"),
        service="Example App",
        service_role=ServiceRole.OPTIONAL,
        privacy_risk=80,
        security_risk=5,
        breakage_risk=20,
        confidence=0.92,
        needs_review=False,
        review_reason="",
        recheck_after_days=14,
        short="Optional telemetry endpoint",
        details="Used for application telemetry.",
        provider="test provider",
        raw_text="{}",
    )

    run_id = save_classification_run(classification, model="model", profile="profile")
    assert run_id > 0
    history = classification_history("telemetry.example.com")
    assert history[0]["tags"] == ["telemetry", "analytics"]
    assert history[0]["privacy_risk"] == 80

    set_domain_lock("telemetry.example.com", "deny", "User confirmed")
    assert get_domain_lock("telemetry.example.com")["list_type"] == "deny"
    assert remove_domain_lock("telemetry.example.com") == 1
    assert get_domain_lock("telemetry.example.com") is None


def test_query_observations_only_queue_unclassified_domains(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import (
        queue_domains_needing_analysis,
        record_query_observations,
    )

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    rows = [
        {
            "domain": "api.example.com",
            "client": "phone",
            "type": "A",
            "status": "FORWARDED",
            "time": 1_700_000_000,
        }
    ]
    assert record_query_observations(rows) == 1
    assert queue_domains_needing_analysis(["api.example.com"]) == 1
    assert queue_domains_needing_analysis(["api.example.com"]) == 0


def test_queue_trigger_and_manual_priority(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import staging_ready

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()

    assert staging_enqueue(["one.example"], source="live_query") == 1
    assert staging_ready(trigger_size=2, max_wait_sec=300) is False
    assert staging_enqueue(["two.example"], source="live_query") == 1
    assert staging_ready(trigger_size=2, max_wait_sec=300) is True

    staging_claim(10)
    staging_ack("one.example")
    staging_ack("two.example")
    assert staging_enqueue(["manual.example"], priority=100, source="manual_live_query") == 1
    assert staging_ready(trigger_size=100, max_wait_sec=300) is True


def test_domain_browser_searches_and_filters_classifications(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import domain_browser_search, save_classification_run
    from pihole_manager.models import Classification, Policy, ServiceRole

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    save_classification_run(
        Classification(
            domain="telemetry.example.com",
            policy=Policy.DENY,
            category="telemetry",
            tags=("telemetry", "analytics"),
            service="Example App",
            service_role=ServiceRole.OPTIONAL,
            privacy_risk=80,
            security_risk=5,
            breakage_risk=20,
            confidence=0.92,
            needs_review=False,
            review_reason="",
            recheck_after_days=14,
            short="Optional telemetry endpoint",
            details="Used for application telemetry.",
            provider="test provider",
            raw_text="{}",
        )
    )
    save_classification_run(
        Classification(
            domain="login.example.com",
            policy=Policy.MANUAL_REVIEW,
            category="authentication",
            tags=("authentication",),
            service="Example Login",
            service_role=ServiceRole.CORE,
            privacy_risk=10,
            security_risk=10,
            breakage_risk=90,
            confidence=0.70,
            needs_review=True,
            review_reason="Core authentication endpoint",
            recheck_after_days=7,
            short="Required login endpoint",
            details="Used for authentication.",
            provider="test provider",
            raw_text="{}",
        )
    )

    rows, total = domain_browser_search(search="Example App")
    assert total == 1
    assert rows[0]["domain"] == "telemetry.example.com"
    assert rows[0]["tags"] == ["telemetry", "analytics"]

    rows, total = domain_browser_search(tag="authentication", review_state="required")
    assert total == 1
    assert rows[0]["domain"] == "login.example.com"

    rows, total = domain_browser_search(policy="deny", service_role="optional")
    assert total == 1
    assert rows[0]["domain"] == "telemetry.example.com"


def test_domain_browser_includes_legacy_review_rows(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import domain_browser_search

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    review_save(
        "legacy.example.com",
        ["analytics"],
        "Imported legacy classification",
        status="imported",
        policy="manual_review",
        short="Legacy review row",
        provider="import",
    )

    rows, total = domain_browser_search(search="legacy.example.com")
    assert total == 1
    assert rows[0]["domain"] == "legacy.example.com"
    assert rows[0]["tags"] == ["analytics"]


def test_locked_domains_are_removed_from_automatic_analysis_queue(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import (
        queue_domains_needing_analysis,
        set_domain_lock,
        staging_list,
    )

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    assert staging_enqueue(["locked.example"], source="live_query") == 1

    set_domain_lock("locked.example", "deny", "User protected")

    assert staging_list() == []
    assert queue_domains_needing_analysis(["locked.example"]) == 0
    assert staging_enqueue(["locked.example"], source="manual") == 0


def test_research_signal_metadata_round_trips(monkeypatch, tmp_path) -> None:
    import time

    from pihole_manager.database import research_findings_get, save_research_findings
    from pihole_manager.models import ResearchFinding

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    now = int(time.time())
    save_research_findings(
        [
            ResearchFinding(
                domain="ioc.example",
                provider="Threat source",
                kind="ioc_database",
                title="Known tracker",
                summary="Listed by a threat source",
                source_url="https://example.invalid/ioc",
                confidence=0.9,
                retrieved_at=now,
                expires_at=now + 3600,
                raw={"listed": True},
                signal_type="reputation",
                verdict="deny",
                decision_relevant=True,
            )
        ]
    )

    rows = research_findings_get("ioc.example")
    assert rows[0]["signal_type"] == "reputation"
    assert rows[0]["verdict"] == "deny"
    assert rows[0]["decision_relevant"] is True
    assert rows[0]["raw"]["listed"] is True


def test_analysis_and_benchmark_round_trip(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import (
        analysis_run_create,
        analysis_run_get,
        analysis_run_update,
        benchmark_run_create,
        benchmark_run_get,
        benchmark_run_save_result,
        benchmark_run_update,
    )

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()

    analysis_run_create("run-1", "background", "single", source="test", dossier_hash="hash")
    analysis_run_update("run-1", status="completed")
    analysis = analysis_run_get("run-1")
    assert analysis is not None
    assert analysis["status"] == "completed"

    benchmark_run_create("bench-1", "example.com", "balanced", "prompt-hash")
    benchmark_run_save_result(
        "bench-1",
        provider_id="provider-1",
        provider_name="Provider 1",
        model="model-1",
        status="completed",
        latency_ms=10,
        input_tokens=12,
        output_tokens=8,
        classification={"policy": "allow"},
    )
    benchmark_run_update("bench-1", status="completed")
    benchmark = benchmark_run_get("bench-1")
    assert benchmark is not None
    assert benchmark["status"] == "completed"
    assert benchmark["results"][0]["classification"]["policy"] == "allow"
