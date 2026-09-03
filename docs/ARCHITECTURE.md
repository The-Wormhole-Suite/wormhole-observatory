# Architecture

## Product model

Wormhole Observatory separates four layers:

1. **Observation** — when, how often, and from which clients a domain was queried.
2. **Evidence** — structured source findings, tags, service attribution, and history.
3. **Assessment and decision** — LLM assessment, deterministic policy checks, user decisions, and review tasks.
4. **Enforcement** — the actual exact allow or deny entry in Pi-hole.

Every queued domain reaches the LLM. The evidence layer improves the assessment; it does not
replace it. An LLM recommendation is never a direct DNS command.

## Components

### `pihole6api`

The low-level Pi-hole v6 HTTP client normalizes URLs, manages authentication, supports TLS and
timeouts, raises typed errors, and retries only appropriate transient failures.

### `pihole_manager`

The application layer contains typed configuration, SQLite persistence, durable queues, query
aggregation, evidence adapters, immutable classification history, LLM adapters, deterministic
policy evaluation, review tasks, and protected list entries.

### `pihole_manager.gui`

Tkinter remains a presentation layer. Network operations run outside the UI thread. Domain
Browser filters and pagination execute in SQLite. Column visibility and widths are persisted per
view.

## Shared core and frontend boundary

Wormhole Observatory is one Python application core with two first-class presentation paths:

```text
                         ┌─ Tkinter desktop frontend ── in-process adapter ─┐
User / operator ─────────┤                                                  ├─ application services
                         └─ Web frontend / PWA ── authenticated HTTP API ──┘
                                                                            │
                                                                            ├─ persistence
                                                                            ├─ Pi-hole adapters
                                                                            ├─ evidence / LLM adapters
                                                                            ├─ background jobs
                                                                            └─ audit / backup / restore
```

The boundary is architectural, not merely organizational:

- `pihole_manager` owns canonical application behavior, domain validation, transaction boundaries,
  policy resolution, mutation orchestration, persistence, auditing, jobs, backup/restore semantics,
  and integrations.
- `pihole_manager.gui` is a local Tkinter presentation layer. It may call shared application
  services directly in-process and must not become a second implementation of application rules.
- The HTTP server is an adapter over the same application services. It owns transport concerns such
  as authentication, authorization, request parsing, response schemas, pagination, HTTP error
  mapping, and concurrency/idempotency contracts; it does not own independent business rules.
- The Web/PWA client is a browser presentation layer over that HTTP API. JavaScript may implement
  view state, interaction state, client-side formatting, and optimistic UX, but canonical
  validation and mutations remain server-side.
- The headless runtime must not depend on Tkinter initialization or a display server. Docker is the
  preferred generic server distribution, and the Home Assistant App reuses that container runtime.
- The desktop frontend is not routed through localhost HTTP solely to manufacture code sharing.
  Shared Python services are the reuse boundary; HTTP exists because remote/browser clients need a
  transport boundary.

### Frontend parity policy

The existing Web/PWA is review-focused and therefore does not yet have administrative parity with
Tkinter. Expansion to full Web administration follows `docs/ROADMAP.md` Priority 9 and issue #50.
During that work a capability matrix must track support across shared core, Tkinter, HTTP API, and
Web UI.

A shared feature is complete only when:

1. its canonical behavior is implemented in the application/service layer;
2. every intended frontend reaches that same behavior through an adapter rather than duplicating it;
3. state-changing paths preserve the same validation, audit, simulation, policy, and transaction
   behavior regardless of frontend;
4. intentional platform-specific gaps are documented and tested; and
5. the headless/server path remains usable without importing or initializing Tkinter.

Remote Tkinter-to-server operation may be considered later, after the administration API reaches
sufficient parity. It is not a prerequisite for server mode and does not replace the browser UI.
VNC/noVNC-style streaming of the desktop GUI is not the primary Web architecture.

## Queue model

The query collector queues domains that are new or due for re-evaluation. Locked domains are
excluded from automatic collection and scheduled rechecks. Manual jobs use higher priority and
bypass the automatic queue threshold.

Separate realtime and background analysis workers start when their own eligible queue reaches the
configured size, the oldest automatic job exceeds its wait limit, or a manual job exists. For every
claimed domain the worker builds a dossier, freezes it for the analysis run, dispatches it through
the selected pool, validates every result, and stores immutable provider runs. Only primary results
can invoke the policy engine. Compare results are history-only.

Quota-delayed jobs have an `available_at` time and are not repeatedly reclaimed before that time.
Realtime and background queue claims are atomic and isolated by pool.

Simulation mode sits between policy resolution and enforcement. It records the resolved action,
marks it as `simulated`, and creates a reviewable pending action without calling the Pi-hole API.
Manual approval changes the action state to `applied`; dismissal preserves the historical decision
without enforcement.

## Evidence model

Each `ResearchFinding` contains provider, kind, signal type, verdict, title, summary, source URL,
confidence, decision relevance, retrieval time, expiration time, and raw structured data.

Sources use one of three modes:

- `local`: no dedicated external evidence service
- `catalog`: complete dataset downloaded periodically, domain matching performed locally
- `lookup`: domain or resolved public IP sent to a provider

The current adapters cover AdGuard service metadata, DNS records, Disconnect, RDAP, RIPEstat,
Netcraft Site Reports, VirusTotal, ThreatFox, PhishTank, archived urlscan.io results, and
Cloudflare Radar.

Netcraft is an optional experimental HTML adapter rather than a required core dependency. It uses
a unique user agent, checks robots.txt, rate-limits requests, selects only known table fields, and
fails closed when access or layout is unsuitable.

Prompt construction excludes negative cache markers, prioritizes decision-relevant findings,
limits the number of findings, and truncates summaries. Full raw data remains local.

## Decision relevance

Evidence context and policy evidence are distinct:

- DNS, RDAP, Netcraft, RIPEstat, service attribution, and popularity are context.
- confirmed tracker classifications and active security indicators can be decision relevant.

When `require_research_for_auto_action` is enabled, only decision-relevant findings satisfy the
automation guard. Infrastructure context can never independently authorize an allow or deny rule.

## LLM contract

The fixed JSON Schema requires exact domain identity, recommendation, tags, service and role,
privacy/security/breakage risks, confidence, manual-review state, recheck interval, and concise and
detailed descriptions. The validator rejects missing or extra fields, invalid types or ranges,
unknown or duplicate domains, and omitted domains.

A browsing-capable LLM is instructed to consult official documentation and targeted GitHub
repositories, issues, discussions, Pi-hole community reports, and credible user reports. Generic
GitHub search is not part of the deterministic evidence layer.

## Analysis dispatch and quota

`AnalysisPool`, `ProviderPoolMembership`, `ProviderCapability`, `ProviderLimitProfile`,
`RuntimeQuotaState`, `QuotaReservation`, `ProviderHealthState`, `ModelBenchmarkRun`, and
`ModelBenchmarkResult` are explicit configuration or persistence concepts.

Pool modes are distribute, fallback, compare, and verify. Distribution assigns one provider per
domain. Fallback is limited to operational unavailability. Compare never changes current domain
state. Verification compares an independent result with the primary classification and turns
material differences into a manual-review veto.

Before every provider HTTP attempt, the quota manager opens an immediate SQLite transaction,
expires abandoned reservations, checks all applicable request/token/unit windows and current live
header state, and inserts one reservation. Completed calls replace estimates with reported usage;
connection failures cancel reservations. Account and organization quotas use a non-secret API-key
fingerprint and optional quota group so multiple models share the same budget without persisting
credentials.

The registry trust order is user cap, live header, verified online registry, bundled registry, and
conservative unknown-provider defaults. Online registry bytes are accepted only over HTTPS after an
Ed25519 signature check and downgrade protection.

## Policy resolution

All tags participate. Identical `allow` or `deny` policies may permit automation;
`manual_review` vetoes it; mixed actionable policies create a conflict. Further guards prevent
automation for insufficient confidence, high breakage risk, core/shared infrastructure, missing
decision-relevant evidence, and protected-list conflicts. Simulation mode does not alter this
decision logic; it suppresses only the final enforcement call.

## Secrets and privacy

Runtime configuration, databases, evidence caches, and logs stay outside Git. Desktop secrets use
the operating-system credential store through `keyring`; when no usable credential backend exists,
configuration keeps the existing plaintext value as an explicit no-data-loss compatibility fallback.
Each evidence source exposes whether it downloads a catalog, runs locally, sends a domain, or sends
resolved public IP addresses.


## Update service boundary

Release discovery, platform-asset selection, digest verification, archive validation, install-plan
creation, and rollback-script generation live in `pihole_manager.updater` and do not import Tkinter.
The desktop settings page is only a presentation layer. Windows and Linux Onedir packages use the
same install manifest and update protocol. The replacement script runs outside the application
directory, waits for the old process to stop, preserves runtime data, starts the new version, and
restores the backup if startup confirmation is not received.

Stable and prerelease channels consume GitHub Release assets. Automated dev-branch builds are published as prereleases and
are generated from the `dev` branch by CI and identified by their commit build ID rather than only by
the package version. Source checkouts are deliberately download-only. Docker and Home Assistant
variants replace the installation adapter entirely: their container manager pulls and recreates an
image while persistent state remains in mounted storage.
