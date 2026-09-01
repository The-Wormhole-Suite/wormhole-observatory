from __future__ import annotations

import sqlite3
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from pihole_manager.compatibility_profiles import compatibility_match_for_domain
from pihole_manager.database_core import _DB_LOCK, _connection, _normalize_domain
from pihole_manager.database_features import research_findings_get

_MAX_PEER_DOMAINS = 25
_MAX_RESEARCH_FINDINGS = 500


@dataclass(frozen=True, slots=True)
class ServiceGraphNode:
    node_id: str
    node_type: str
    label: str
    service_role: str = "unknown"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id,
            "type": self.node_type,
            "label": self.label,
            "service_role": self.service_role,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ServiceGraphEdge:
    source: str
    target: str
    relation: str
    confidence: float
    provenance: str
    evidence_provider: str = ""
    evidence_url: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relation": self.relation,
            "confidence": round(self.confidence, 3),
            "provenance": self.provenance,
            "evidence_provider": self.evidence_provider,
            "evidence_url": self.evidence_url,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class ServiceDependencyGraph:
    root_domain: str
    nodes: tuple[ServiceGraphNode, ...]
    edges: tuple[ServiceGraphEdge, ...]
    peer_domains_truncated: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "root_domain": self.root_domain,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "peer_domains_truncated": self.peer_domains_truncated,
            "nodes": [node.as_dict() for node in self.nodes],
            "edges": [edge.as_dict() for edge in self.edges],
        }

    def prompt_context(self, *, max_related_domains: int = 8) -> dict[str, Any]:
        node_by_id = {node.node_id: node for node in self.nodes}
        root_id = _domain_node_id(self.root_domain)
        services = [
            {
                "name": node.label,
                "role": node.service_role,
            }
            for node in self.nodes
            if node.node_type == "service"
        ]
        dependencies = []
        for edge in self.edges:
            if edge.source != root_id or edge.relation == "member_of":
                continue
            target = node_by_id.get(edge.target)
            dependencies.append(
                {
                    "target_type": target.node_type if target else "",
                    "target": target.label if target else edge.target,
                    "relation": edge.relation,
                    "confidence": round(edge.confidence, 3),
                    "provenance": edge.provenance,
                    "provider": edge.evidence_provider,
                    "source_url": edge.evidence_url,
                }
            )
        related_domain_nodes = [
            node
            for node in self.nodes
            if node.node_type == "domain" and node.node_id != root_id
        ]
        related_domains = [
            node.label for node in related_domain_nodes[: max(0, int(max_related_domains))]
        ]
        return {
            "services": services,
            "dependencies": dependencies,
            "related_domains": related_domains,
            "related_domains_truncated": self.peer_domains_truncated
            or len(related_domain_nodes) > len(related_domains),
        }


def service_dependency_graph(
    domain: str,
    *,
    findings: Sequence[Mapping[str, Any] | Any] | None = None,
    max_peer_domains: int = _MAX_PEER_DOMAINS,
) -> ServiceDependencyGraph:
    normalized = _normalize_domain(domain)
    if not normalized:
        raise ValueError("domain must not be empty")

    nodes: dict[str, ServiceGraphNode] = {}
    edges: dict[tuple[str, str, str, str], ServiceGraphEdge] = {}
    root_id = _domain_node_id(normalized)
    _put_node(
        nodes,
        ServiceGraphNode(
            root_id,
            "domain",
            normalized,
            metadata={"root": True},
        ),
    )

    current = _current_service_record(normalized)
    truncated = False
    if current and current["service"]:
        service = str(current["service"])
        role = str(current["service_role"] or "unknown")
        service_id = _service_node_id(service)
        _put_node(nodes, ServiceGraphNode(service_id, "service", service, role))
        _put_edge(
            edges,
            ServiceGraphEdge(
                root_id,
                service_id,
                "member_of",
                _confidence(current.get("confidence")),
                "classification",
            ),
        )
        peers, truncated = _service_peers(service, max_peer_domains=max_peer_domains)
        for peer in peers:
            peer_domain = str(peer["domain"])
            peer_id = _domain_node_id(peer_domain)
            _put_node(
                nodes,
                ServiceGraphNode(
                    peer_id,
                    "domain",
                    peer_domain,
                    str(peer.get("service_role") or "unknown"),
                ),
            )
            _put_edge(
                edges,
                ServiceGraphEdge(
                    peer_id,
                    service_id,
                    "member_of",
                    _confidence(peer.get("confidence")),
                    "classification",
                ),
            )

    compatibility = compatibility_match_for_domain(normalized)
    if compatibility is not None:
        profile = compatibility.profile
        service_id = _service_node_id(profile.name)
        _put_node(
            nodes,
            ServiceGraphNode(
                service_id,
                "service",
                profile.name,
                profile.service_role.value,
                metadata={"compatibility_profile_id": profile.profile_id},
            ),
        )
        _put_edge(
            edges,
            ServiceGraphEdge(
                root_id,
                service_id,
                "requires",
                1.0,
                "compatibility_profile",
                evidence_provider="Wormhole compatibility profiles",
                evidence_url=profile.source_url,
                metadata={
                    "profile_id": profile.profile_id,
                    "matched_pattern": compatibility.matched_pattern,
                    "match_type": compatibility.match_type,
                },
            ),
        )

    if findings is not None:
        selected_findings = list(findings)
    else:
        try:
            selected_findings = research_findings_get(
                normalized,
                fresh_only=False,
                limit=_MAX_RESEARCH_FINDINGS,
            )
        except sqlite3.OperationalError:
            selected_findings = []
    for finding in selected_findings:
        finding_data = _finding_mapping(finding)
        for relationship in _relationships_from_finding(finding_data):
            target_type = relationship["target_type"]
            target = relationship["target"]
            relation = relationship["relation"]
            if target_type == "domain":
                target_label = _normalize_domain(target)
                if not target_label:
                    continue
                target_id = _domain_node_id(target_label)
                _put_node(nodes, ServiceGraphNode(target_id, "domain", target_label))
            else:
                target_label = str(target).strip()
                if not target_label:
                    continue
                target_id = _service_node_id(target_label)
                _put_node(nodes, ServiceGraphNode(target_id, "service", target_label))
            _put_edge(
                edges,
                ServiceGraphEdge(
                    root_id,
                    target_id,
                    relation,
                    _confidence(finding_data.get("confidence")),
                    "evidence",
                    evidence_provider=str(finding_data.get("provider") or ""),
                    evidence_url=str(finding_data.get("source_url") or ""),
                    metadata={"finding_kind": str(finding_data.get("kind") or "")},
                ),
            )

    ordered_nodes = tuple(
        sorted(
            nodes.values(),
            key=lambda node: (
                0 if node.node_id == root_id else 1,
                0 if node.node_type == "service" else 1,
                node.label.casefold(),
            ),
        )
    )
    ordered_edges = tuple(
        sorted(
            edges.values(),
            key=lambda edge: (
                edge.source.casefold(),
                edge.relation,
                edge.target.casefold(),
                edge.provenance,
            ),
        )
    )
    return ServiceDependencyGraph(
        root_domain=normalized,
        nodes=ordered_nodes,
        edges=ordered_edges,
        peer_domains_truncated=truncated,
    )


def _current_service_record(domain: str) -> dict[str, Any] | None:
    try:
        with _DB_LOCK, _connection() as connection:
            row = connection.execute(
                """
                SELECT
                    d.domain,
                    d.current_service AS service,
                    d.current_service_role AS service_role,
                    COALESCE(
                        (
                            SELECT c.confidence
                            FROM classification_runs c
                            WHERE c.domain = d.domain AND c.is_primary = 1
                            ORDER BY c.created_at DESC, c.id DESC
                            LIMIT 1
                        ),
                        0
                    ) AS confidence
                FROM domains d
                WHERE d.domain = ?
                """,
                (domain,),
            ).fetchone()
    except sqlite3.OperationalError:
        return None
    return dict(row) if row else None


def _service_peers(
    service: str,
    *,
    max_peer_domains: int,
) -> tuple[list[dict[str, Any]], bool]:
    safe_limit = max(0, min(250, int(max_peer_domains)))
    if safe_limit == 0:
        return [], False
    try:
        with _DB_LOCK, _connection() as connection:
            rows = connection.execute(
                """
                SELECT
                    d.domain,
                    d.current_service_role AS service_role,
                    COALESCE(
                        (
                            SELECT c.confidence
                            FROM classification_runs c
                            WHERE c.domain = d.domain AND c.is_primary = 1
                            ORDER BY c.created_at DESC, c.id DESC
                            LIMIT 1
                        ),
                        0
                    ) AS confidence
                FROM domains d
                WHERE LOWER(d.current_service) = LOWER(?)
                ORDER BY d.domain
                LIMIT ?
                """,
                (service, safe_limit + 1),
            ).fetchall()
    except sqlite3.OperationalError:
        return [], False
    output = [dict(row) for row in rows[:safe_limit]]
    return output, len(rows) > safe_limit


def _relationships_from_finding(finding: Mapping[str, Any]) -> list[dict[str, str]]:
    raw_data = finding.get("raw_data")
    if not isinstance(raw_data, Mapping):
        return []
    raw_relationships = raw_data.get("service_relationships")
    if isinstance(raw_relationships, Mapping):
        candidates = [raw_relationships]
    elif isinstance(raw_relationships, list):
        candidates = raw_relationships
    else:
        single = raw_data.get("service_relationship")
        candidates = [single] if isinstance(single, Mapping) else []

    output: list[dict[str, str]] = []
    for candidate in candidates:
        if not isinstance(candidate, Mapping):
            continue
        target_type = str(candidate.get("target_type") or "").strip().lower()
        target = str(candidate.get("target") or "").strip()
        relation = _normalize_relation(candidate.get("relation"))
        if target_type not in {"domain", "service"} or not target or not relation:
            continue
        output.append(
            {
                "target_type": target_type,
                "target": target,
                "relation": relation,
            }
        )
    return output


def _finding_mapping(finding: Mapping[str, Any] | Any) -> Mapping[str, Any]:
    if isinstance(finding, Mapping):
        return finding
    raw_data = getattr(finding, "raw_data", {})
    return {
        "provider": getattr(finding, "provider", ""),
        "kind": getattr(finding, "kind", ""),
        "source_url": getattr(finding, "source_url", ""),
        "confidence": getattr(finding, "confidence", 0.0),
        "raw_data": raw_data if isinstance(raw_data, Mapping) else {},
    }


def _normalize_relation(value: object) -> str:
    relation = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    if not relation or len(relation) > 64:
        return ""
    if not relation.replace("_", "").isalnum():
        return ""
    return relation


def _put_node(nodes: dict[str, ServiceGraphNode], node: ServiceGraphNode) -> None:
    existing = nodes.get(node.node_id)
    if existing is None:
        nodes[node.node_id] = node
        return
    role_order = {"core": 3, "shared": 2, "optional": 1, "unknown": 0}
    if role_order.get(node.service_role, 0) > role_order.get(existing.service_role, 0):
        nodes[node.node_id] = node


def _put_edge(
    edges: dict[tuple[str, str, str, str], ServiceGraphEdge],
    edge: ServiceGraphEdge,
) -> None:
    key = (edge.source, edge.target, edge.relation, edge.provenance)
    existing = edges.get(key)
    if existing is None or edge.confidence > existing.confidence:
        edges[key] = edge


def _domain_node_id(domain: str) -> str:
    return f"domain:{_normalize_domain(domain)}"


def _service_node_id(service: str) -> str:
    return f"service:{' '.join(service.strip().casefold().split())}"


def _confidence(value: object) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0
