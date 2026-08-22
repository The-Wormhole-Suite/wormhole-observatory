from __future__ import annotations

import time

import pytest

from pihole_manager import database as db
from pihole_manager import database_review, review_decisions, review_preferences
from pihole_manager.database import init_db
from pihole_manager.review_decisions import apply_review_decision
from pihole_manager.review_preferences import (
    clear_review_preference,
    preference_database_path,
    review_preference_get,
    set_review_preference,
)


def _save_pending(domain: str) -> None:
    db.review_save(
        domain,
        "tracking",
        "Needs review",
        policy="unknown",
        short="Pending",
        needs_review=True,
        review_reason="manual check",
    )


def test_postpone_hides_then_automatically_resurfaces(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    _save_pending("postpone.example")
    now = int(time.time())

    apply_review_decision("postpone.example", "postpone", postpone_until=now + 3600)

    assert db.review_queue_get() == []
    base = database_review.review_get(needs_review=True)
    assert [row["domain"] for row in base] == ["postpone.example"]
    assert db.create_review_task("postpone.example", "again") == 0

    monkeypatch.setattr(review_preferences.time, "time", lambda: now + 3601)
    assert [row["domain"] for row in db.review_queue_get()] == ["postpone.example"]
    assert db.create_review_task("postpone.example", "again") > 0


def test_never_ask_survives_new_analyzer_review_and_can_be_cleared(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    _save_pending("quiet.example")

    apply_review_decision("quiet.example", "never_ask")
    assert db.review_queue_get() == []
    assert db.create_review_task("quiet.example", "new model result") == 0

    _save_pending("quiet.example")
    assert db.review_queue_get() == []
    assert review_preference_get("quiet.example")["never_ask"] is True

    assert clear_review_preference("quiet.example") is True
    assert [row["domain"] for row in db.review_queue_get()] == ["quiet.example"]


def test_ignore_only_resolves_current_review(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    _save_pending("ignore.example")

    apply_review_decision("ignore.example", "ignore")

    row = database_review.review_get(limit=1)[0]
    assert row["domain"] == "ignore.example"
    assert row["needs_review"] is False
    preference = review_preference_get("ignore.example")
    assert preference is not None
    assert preference["never_ask"] is False
    assert preference["postponed_until"] is None

    _save_pending("ignore.example")
    assert [item["domain"] for item in db.review_queue_get()] == ["ignore.example"]


def test_allow_applies_rule_then_removes_opposite_and_marks_review(monkeypatch) -> None:
    calls: list[tuple] = []

    def fetch(policy: str):
        if policy == "deny":
            return [{"domain": "example.com"}]
        return []

    monkeypatch.setattr(review_decisions, "fetch_exact_domains", fetch)
    monkeypatch.setattr(
        review_decisions,
        "add_exact_domain",
        lambda domain, policy, comment="": calls.append(("add", domain, policy.value, comment)),
    )
    monkeypatch.setattr(
        review_decisions,
        "delete_exact_domain",
        lambda domain, policy: calls.append(("delete", domain, policy)),
    )
    monkeypatch.setattr(
        review_decisions,
        "mark_action_applied",
        lambda domain, action: calls.append(("mark", domain, action)),
    )
    monkeypatch.setattr(review_decisions, "staging_remove", lambda domains: 0)
    monkeypatch.setattr(
        review_decisions,
        "set_review_preference",
        lambda domain, **kwargs: {"domain": domain, **kwargs},
    )

    result = apply_review_decision("Example.COM.", "allow", comment="manual")

    assert result["decision"] == "allow"
    assert calls == [
        ("add", "example.com", "allow", "manual"),
        ("delete", "example.com", "deny"),
        ("mark", "example.com", "allow"),
    ]


def test_failed_rule_write_does_not_mark_review_applied(monkeypatch) -> None:
    marked: list[str] = []
    monkeypatch.setattr(review_decisions, "fetch_exact_domains", lambda _policy: [])
    monkeypatch.setattr(
        review_decisions,
        "add_exact_domain",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("Pi-hole offline")),
    )
    monkeypatch.setattr(
        review_decisions,
        "mark_action_applied",
        lambda domain, action: marked.append(f"{domain}:{action}"),
    )

    with pytest.raises(RuntimeError, match="offline"):
        apply_review_decision("example.com", "deny")
    assert marked == []


def test_review_preference_database_is_versioned(monkeypatch, tmp_path) -> None:
    import sqlite3

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    set_review_preference("example.com", never_ask=True, last_decision="never_ask")
    connection = sqlite3.connect(preference_database_path())
    version = connection.execute(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
    ).fetchone()[0]
    connection.close()
    assert version == str(review_preferences.PREFERENCE_SCHEMA_VERSION)
