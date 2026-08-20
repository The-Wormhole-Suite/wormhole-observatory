# Service dependency graphs

Wormhole Observatory derives a service dependency graph from already persisted domain intelligence instead of maintaining a second copy of the same facts.

## Graph model

Nodes are either domains or named services. Edges are directional and keep their provenance:

- `member_of`: a classified domain belongs to a named service;
- `requires`: a protected compatibility profile explicitly identifies a service dependency;
- evidence-defined relationships such as `authentication_dependency` when a research adapter emits the normalized relationship contract.

Each edge includes confidence, provenance, and—when available—the evidence provider and source URL. This keeps dependency information auditable instead of turning inferred relationships into opaque facts.

## No speculative dependency inference

Free-text summaries are never parsed to invent graph edges. DNS co-occurrence, similar names, shared infrastructure, or simultaneous query activity also do not automatically become dependencies.

A research finding creates an evidence relationship only when its `raw_data` contains an explicit contract:

```json
{
  "service_relationship": {
    "target_type": "domain",
    "target": "login.example.test",
    "relation": "authentication_dependency"
  }
}
```

Multiple relationships may be supplied through `service_relationships`. `target_type` must be `domain` or `service`, and relation names are normalized identifiers.

## Derived service membership

The current primary classification already stores `service` and `service_role`. Domains with the same non-empty current service are connected to the same service node. Peer expansion is bounded so a very large shared service cannot create an unbounded graph or prompt.

Compatibility profiles add high-confidence `requires` edges. For example, a protected authentication endpoint can therefore expose both its service identity and its compatibility-critical role without pretending that the profile proves anything about privacy or security.

## LLM context

The complete graph is available in Domain Intelligence. The LLM evidence dossier receives a compact projection containing:

- named services and their roles;
- explicit dependencies with provenance and source URLs; and
- a bounded list of related domains belonging to the same service.

This avoids sending the full graph metadata for every domain in a batch while still giving the model useful dependency context.

## Freshness

The graph itself is not separately persisted. It is rebuilt from current classifications, compatibility profiles, and research findings whenever requested. Consequently, a reclassification or refreshed evidence set changes the graph automatically and cannot leave stale duplicate edges behind.
