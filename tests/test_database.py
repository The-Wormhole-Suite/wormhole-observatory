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
