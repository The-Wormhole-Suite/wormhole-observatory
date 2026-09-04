# Shared application-service pattern

Priority 9 uses one Python application core with multiple presentation and transport adapters. This document defines the incremental migration pattern established by the review-decision slice in issue #52.

## Dependency direction

```text
Tkinter UI ───────────────┐
                          ├─ composition / infrastructure wiring ─ application service ─ ports ─ DB / Pi-hole / workers
HTTP API ─ Web/PWA ───────┘
```

The dependency rule is one-way:

- application services contain canonical use-case behavior;
- application services do not import Tkinter, browser assets, HTTP handlers, or transport schemas;
- infrastructure operations are supplied through explicit ports;
- Tkinter gathers local user input, invokes the service in-process, and renders the result;
- HTTP authenticates and parses requests, invokes the same application capability, and maps typed results/errors to transport responses;
- browser JavaScript owns presentation and interaction state only.

The desktop application is not routed through localhost HTTP merely to create code sharing.

## Reference contract: review decisions

`pihole_manager.application.review_decisions` is the first reference implementation.

It defines:

- `ReviewDecisionCommand` — frontend-neutral input;
- `ReviewDecisionResult` — canonical typed output;
- `InvalidReviewDecision` — valid transport but invalid application input;
- `ReviewDecisionConflict` — valid command that cannot be applied to current state;
- `ReviewDecisionPorts` — required persistence/Pi-hole/infrastructure operations;
- `ReviewDecisionApplicationService` — the only owner of normalization, decision validation, rule mutation orchestration, review/staging resolution, and preference effects.

`pihole_manager.review_decisions` is the composition/compatibility layer. It wires current database and Pi-hole functions into the service and preserves the historical primitive/dict API while callers migrate.

## Adapter responsibilities

A frontend adapter may:

- collect fields and local interaction state;
- construct a command/query;
- invoke an application service;
- display or serialize the canonical result;
- map typed application errors to user-facing or HTTP-specific errors;
- perform authentication, authorization, pagination, request parsing, or presentation formatting where applicable.

A frontend adapter must not independently:

- decide allow/deny policy;
- normalize or validate domain-specific business rules differently from the service;
- write SQLite state directly for a migrated capability;
- call Pi-hole mutation APIs outside the service boundary;
- create a separate JavaScript version of application validation or policy behavior;
- bypass simulation, audit, transaction, rollback, or job-control rules owned by the core.

## Port rules

Ports describe infrastructure needed by an application use case. They should be as narrow as practical and express operations rather than frontend concepts.

Production wiring may retain legacy modules temporarily while migration is incremental. The important boundary is that orchestration and business decisions live in the application service, while the composition layer supplies infrastructure implementations.

Ports also make service behavior testable without Tkinter, a display server, HTTP sockets, or a live Pi-hole instance.

## Parity tests

For a capability exposed through more than one frontend, tests should verify the application result and state transition, not merely HTTP status codes or button callbacks.

The review-decision reference slice includes a parity test that executes the same decision:

1. directly through `ReviewDecisionApplicationService`;
2. through the authenticated HTTP review endpoint backed by that service;
3. with independent identical fake infrastructure state;
4. asserting equal canonical result and mutation events.

As Priority 9 progresses, equivalent parity contracts should cover Pi-hole rules/groups/lists, settings mutations, job controls, rollback, and backup/restore.

## Incremental migration checklist

For each capability migrated under Priority 9A:

1. identify all Tkinter, HTTP, worker, CLI, and other callers;
2. identify business rules currently embedded in presentation callbacks;
3. define frontend-neutral command/query and result types where the operation benefits from an explicit contract;
4. define stable application error categories;
5. move orchestration and validation into the application service;
6. wire database, Pi-hole, filesystem, provider, or worker operations through narrow ports or existing shared services;
7. retain compatibility adapters when removing them immediately would create unnecessary blast radius;
8. migrate frontends to thin adapters;
9. add service tests and cross-frontend parity tests;
10. verify headless operation without Tkinter initialization and retain GUI startup coverage.

Do not convert the entire application in one broad rewrite. Migrate bounded vertical slices while keeping every intermediate tree releasable.
