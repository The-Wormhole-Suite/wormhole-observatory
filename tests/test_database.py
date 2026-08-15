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
                title="Confirmed IOC",
                summary="Exact match",
                signal_type="security",
                verdict="command_and_control",
                decision_relevant=True,
                confidence=0.99,
                retrieved_at=now,
                expires_at=now + 3600,
            )
        ]
    )

    finding = research_findings_get("ioc.example")[0]
    assert finding["signal_type"] == "security"
    assert finding["verdict"] == "command_and_control"
    assert finding["decision_relevant"] == 1


def test_simulated_action_can_be_applied_later(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import (
        classification_history,
        domain_browser_search,
        mark_action_applied,
        review_get,
        save_classification_run,
    )
    from pihole_manager.models import Classification, Policy, ServiceRole

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    classification = Classification(
        domain="ads.example.com",
        policy=Policy.DENY,
        category="advertising",
        tags=("advertising",),
        service="Example Ads",
        service_role=ServiceRole.OPTIONAL,
        privacy_risk=90,
        security_risk=5,
        breakage_risk=10,
        confidence=0.99,
        needs_review=False,
        review_reason="",
        recheck_after_days=30,
        short="Advertising endpoint",
        details="Used for advertising.",
        provider="test provider",
        raw_text="{}",
    )

    save_classification_run(
        classification,
        status="simulation_deny",
        planned_action="deny",
        action_status="simulated",
    )

    review = review_get(needs_review=True)[0]
    assert review["planned_action"] == "deny"
    assert review["action_status"] == "simulated"
    assert review["needs_review"] is True

    rows, total = domain_browser_search(search="ads.example.com")
    assert total == 1
    assert rows[0]["planned_action"] == "deny"
    assert rows[0]["action_status"] == "simulated"

    history = classification_history("ads.example.com")
    assert history[0]["planned_action"] == "deny"
    assert history[0]["action_status"] == "simulated"

    mark_action_applied("ads.example.com", "deny")
    review = review_get()[0]
    assert review["action_status"] == "applied"
    assert review["needs_review"] is False


def test_manual_review_queue_reports_pending_and_requeues_failed(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import queue_domains_for_review

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()

    first = queue_domains_for_review(["Example.COM", "example.com"], source="test")
    assert first.requested == 1
    assert first.queued == 1
    assert first.accepted == 1

    second = queue_domains_for_review(["example.com"], source="test")
    assert second.already_pending == 1
    assert second.accepted == 1

    staging_claim(1)
    staging_fail("example.com", "failed", max_attempts=1)
    third = queue_domains_for_review(["example.com"], source="test")
    assert third.requeued == 1
    assert staging_list()[0]["state"] == "queued"


def test_domains_without_classification(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import (
        domains_without_classification,
        save_classification_run,
    )
    from pihole_manager.models import Classification, Policy, ServiceRole

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    save_classification_run(
        Classification(
            domain="classified.example",
            policy=Policy.MANUAL_REVIEW,
            category="unknown",
            tags=("unknown",),
            service="",
            service_role=ServiceRole.UNKNOWN,
            privacy_risk=0,
            security_risk=0,
            breakage_risk=0,
            confidence=0.5,
            needs_review=True,
            review_reason="Unknown",
            recheck_after_days=3,
            short="Unknown domain",
            details="",
            provider="test",
            raw_text="{}",
        )
    )

    assert domains_without_classification(["classified.example", "new.example"]) == {"new.example"}


def test_review_queue_includes_pending_analysis_items(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import (
        queue_domains_for_review,
        review_queue_get,
        staging_remove,
    )

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()

    result = queue_domains_for_review(
        ["pending.example", "pending.example"],
        source="manual_live_query",
    )
    assert result.queued == 1

    rows = review_queue_get()
    assert len(rows) == 1
    assert rows[0]["domain"] == "pending.example"
    assert rows[0]["status"] == "queued"
    assert rows[0]["queue_source"] == "manual_live_query"
    assert rows[0]["short"] == "Not analyzed."
    assert rows[0]["breakage_risk"] is None

    assert staging_remove(["pending.example"]) == 1
    assert review_queue_get() == []


def test_queue_filters_configured_domain_suffixes(monkeypatch, tmp_path) -> None:
    from pihole_manager.config import load_options, save_options
    from pihole_manager.database import queue_domains_for_review, staging_list

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    options = load_options()
    options.scans.excluded_domain_suffixes = [".arpa", ".internal"]
    save_options(options)
    init_db()

    result = queue_domains_for_review(
        ["1.0.0.127.in-addr.arpa", "router.internal", "example.com"],
        source="manual_test",
    )

    assert result.queued == 1
    assert result.skipped_filtered == 2
    assert [row["domain"] for row in staging_list()] == ["example.com"]


def test_filter_unclassified_domains(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import filter_unclassified_domains, save_classification_run
    from pihole_manager.models import Classification, Policy, ServiceRole

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    save_classification_run(
        Classification(
            domain="reviewed.example",
            policy=Policy.ALLOW,
            category="authentication",
            tags=("authentication",),
            service="Reviewed",
            service_role=ServiceRole.CORE,
            privacy_risk=0,
            security_risk=0,
            breakage_risk=10,
            confidence=0.99,
            needs_review=False,
            review_reason="",
            recheck_after_days=30,
            short="Reviewed",
            details="Reviewed",
            provider="test",
            raw_text="{}",
        )
    )

    assert filter_unclassified_domains(["reviewed.example", "new.example"]) == ["new.example"]


def test_research_refresh_replaces_previous_provider_rows(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import init_db, research_findings_get, save_research_findings
    from pihole_manager.models import ResearchFinding

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    save_research_findings(
        [
            ResearchFinding(
                domain="example.com",
                provider="Test source",
                kind="test",
                title="Old finding",
                summary="Old",
                retrieved_at=1,
                expires_at=100,
            )
        ]
    )
    save_research_findings(
        [
            ResearchFinding(
                domain="example.com",
                provider="Test source",
                kind="test",
                title="New finding",
                summary="New",
                retrieved_at=2,
                expires_at=200,
            )
        ]
    )

    findings = research_findings_get("example.com")
    assert len(findings) == 1
    assert findings[0]["title"] == "New finding"


def test_legacy_research_raw_data_column_is_migrated(monkeypatch, tmp_path) -> None:
    import sqlite3

    from pihole_manager.database import research_findings_get

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    path = tmp_path / "pihole_manager.sqlite3"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE research_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            provider TEXT NOT NULL,
            kind TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            summary TEXT NOT NULL DEFAULT '',
            source_url TEXT NOT NULL DEFAULT '',
            confidence REAL NOT NULL DEFAULT 0,
            retrieved_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            raw_data TEXT NOT NULL DEFAULT '{}'
        );
        INSERT INTO research_findings(
            domain, provider, kind, title, summary, source_url,
            confidence, retrieved_at, expires_at, raw_data
        ) VALUES (
            'legacy.example', 'Legacy', 'test', 'Legacy finding', 'Stored',
            '', 0.5, 1, 9999999999, '{"legacy": true}'
        );
        """
    )
    connection.commit()
    connection.close()

    init_db()

    finding = research_findings_get("legacy.example")[0]
    assert finding["raw_data"] == {"legacy": True}
    assert finding["signal_type"] == "context"


def test_newer_database_schema_is_not_downgraded(monkeypatch, tmp_path) -> None:
    import sqlite3

    import pytest

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    path = tmp_path / "pihole_manager.sqlite3"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE schema_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        INSERT INTO schema_meta(key, value) VALUES ('schema_version', '999');
        """
    )
    connection.commit()
    connection.close()

    with pytest.raises(RuntimeError, match="newer Pi-hole Manager"):
        init_db()

    connection = sqlite3.connect(path)
    version = connection.execute(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
    ).fetchone()[0]
    connection.close()
    assert version == "999"


def test_research_fallback_expiry_uses_configured_max_age(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import research_findings_get, save_research_findings
    from pihole_manager.models import ResearchFinding

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    save_research_findings(
        [
            ResearchFinding(
                domain="fallback.example",
                provider="Test",
                kind="test",
                title="Fallback expiry",
                summary="No provider expiry",
                retrieved_at=1_000,
            )
        ],
        default_max_age_days=7,
    )

    finding = research_findings_get("fallback.example")[0]
    assert finding["expires_at"] == 1_000 + 7 * 86400


def test_classification_and_review_are_saved_atomically(monkeypatch, tmp_path) -> None:
    import pytest

    from pihole_manager import database_review
    from pihole_manager.database import classification_history
    from pihole_manager.models import Classification, Policy, ServiceRole

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    classification = Classification(
        domain="atomic.example",
        policy=Policy.DENY,
        category="tracking",
        short="Tracker",
        details="Tracking endpoint",
        provider="test",
        service_role=ServiceRole.OPTIONAL,
    )

    def fail_review(*_args, **_kwargs) -> None:
        raise RuntimeError("review write failed")

    monkeypatch.setattr(database_review, "_review_save", fail_review)

    with pytest.raises(RuntimeError, match="review write failed"):
        database_review.save_classification_run(classification)

    assert classification_history("atomic.example") == []
