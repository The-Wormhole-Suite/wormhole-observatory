from __future__ import annotations

import time

from pihole_manager.models import ResearchFinding
from pihole_manager.research import research_context


def test_research_context_exposes_compact_service_graph(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import init_db

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    now = int(time.time())
    finding = ResearchFinding(
        domain="api.example.test",
        provider="Primary service documentation",
        kind="service_dependency",
        title="Authentication dependency",
        summary="Structured dependency evidence.",
        source_url="https://docs.example.test/auth",
        confidence=0.96,
        signal_type="function",
        verdict="authentication",
        decision_relevant=True,
        retrieved_at=now,
        expires_at=now + 3600,
        raw_data={
            "service_relationship": {
                "target_type": "domain",
                "target": "login.example.test",
                "relation": "authentication_dependency",
            }
        },
    )

    context = research_context("api.example.test", [finding])
    graph = context["service_graph"]

    assert graph["services"] == []
    assert graph["related_domains"] == ["login.example.test"]
    assert graph["dependencies"] == [
        {
            "target_type": "domain",
            "target": "login.example.test",
            "relation": "authentication_dependency",
            "confidence": 0.96,
            "provenance": "evidence",
            "provider": "Primary service documentation",
            "source_url": "https://docs.example.test/auth",
        }
    ]
