from __future__ import annotations

import time

from pihole_manager.models import Classification, Policy, ResearchFinding, ServiceRole
from pihole_manager.service_graph import service_dependency_graph


def _classification(
    domain: str,
    *,
    service: str = "Example Cloud",
    role: ServiceRole = ServiceRole.CORE,
    confidence: float = 0.9,
) -> Classification:
    return Classification(
        domain=domain,
        policy=Policy.ALLOW,
        category="authentication",
        short="Example service endpoint",
        details="Synthetic graph fixture.",
        provider="fixture",
        tags=("authentication",),
        service=service,
        service_role=role,
        privacy_risk=10,
        security_risk=5,
        breakage_risk=80,
        confidence=confidence,
        needs_review=True,
    )


def test_graph_groups_domains_by_classified_service(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import init_db, save_classification_run

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    save_classification_run(_classification("api.example.test", confidence=0.95))
    save_classification_run(_classification("cdn.example.test", confidence=0.85))

    graph = service_dependency_graph("api.example.test")
    payload = graph.as_dict()

    assert payload["root_domain"] == "api.example.test"
    assert {node["id"] for node in payload["nodes"]} >= {
        "domain:api.example.test",
        "domain:cdn.example.test",
        "service:example cloud",
    }
    member_edges = [edge for edge in payload["edges"] if edge["relation"] == "member_of"]
    assert {edge["source"] for edge in member_edges} >= {
        "domain:api.example.test",
        "domain:cdn.example.test",
    }
    assert all(edge["target"] == "service:example cloud" for edge in member_edges)


def test_graph_uses_explicit_structured_evidence_relationship(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import init_db, save_classification_run, save_research_findings

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    save_classification_run(_classification("api.example.test"))
    now = int(time.time())
    save_research_findings(
        [
            ResearchFinding(
                domain="api.example.test",
                provider="Service catalog",
                kind="service_dependency",
                title="Authentication dependency",
                summary="The API explicitly requires the login endpoint.",
                source_url="https://docs.example.test/dependencies",
                confidence=0.97,
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
        ]
    )

    graph = service_dependency_graph("api.example.test")
    edge = next(
        item for item in graph.edges if item.relation == "authentication_dependency"
    )

    assert edge.source == "domain:api.example.test"
    assert edge.target == "domain:login.example.test"
    assert edge.provenance == "evidence"
    assert edge.evidence_provider == "Service catalog"
    assert edge.evidence_url == "https://docs.example.test/dependencies"
    assert edge.confidence == 0.97


def test_graph_does_not_guess_dependencies_from_free_text(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import init_db, save_research_findings

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    now = int(time.time())
    save_research_findings(
        [
            ResearchFinding(
                domain="api.example.test",
                provider="Unstructured note",
                kind="service_dependency",
                title="Possible dependency",
                summary="This text says login.example.test is required, but has no contract.",
                confidence=0.9,
                retrieved_at=now,
                expires_at=now + 3600,
                raw_data={},
            )
        ]
    )

    graph = service_dependency_graph("api.example.test")

    assert "domain:login.example.test" not in {node.node_id for node in graph.nodes}
    assert all(edge.provenance != "evidence" for edge in graph.edges)


def test_compatibility_profile_creates_high_confidence_required_service_edge(
    monkeypatch, tmp_path
) -> None:
    from pihole_manager.database import init_db

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()

    graph = service_dependency_graph("accounts.google.com")
    edge = next(item for item in graph.edges if item.provenance == "compatibility_profile")

    assert edge.source == "domain:accounts.google.com"
    assert edge.target == "service:google oauth"
    assert edge.relation == "requires"
    assert edge.confidence == 1.0
    service_node = next(node for node in graph.nodes if node.node_id == "service:google oauth")
    assert service_node.service_role == "core"


def test_peer_domain_limit_is_bounded_and_reported(monkeypatch, tmp_path) -> None:
    from pihole_manager.database import init_db, save_classification_run

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    init_db()
    for domain in ("a.example.test", "b.example.test", "c.example.test"):
        save_classification_run(_classification(domain, service="Shared Example"))

    graph = service_dependency_graph("a.example.test", max_peer_domains=1)

    assert graph.peer_domains_truncated is True
    peer_nodes = [node for node in graph.nodes if node.node_type == "domain"]
    assert len(peer_nodes) <= 2
