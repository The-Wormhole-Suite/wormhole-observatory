# Roadmap

## Completed

- transactional versioned SQLite migration runner with persistent migration history; legacy schema v12 is preserved as the compatibility baseline and the canonical schema is v13

## Priority 0: Framework audit recovery gate
- [x] establish a clean recovery baseline from the last verified release-candidate tree, excluding the transport-corrupted commits from the canonical path
- [x] reconcile the recovery baseline with current `main`, preserving completed roadmap work while incorporating the transactional migration runner
- [x] fix any Ruff/test failures exposed by the reconciled tree and require green Python CI before further feature work
- [x] verify every previously completed roadmap item still has implementation plus test/release evidence after reconciliation; do not trust checkbox state alone
- [x] rerun the full security and release-candidate gates on the reconciled canonical branch: Python CI, Pi-hole v6 integration, CodeQL, dependency review, reproducible desktop builds, container amd64/arm64 verification, signing/provenance checks
- [x] establish one canonical integration branch and retire or supersede stranded long-lived implementation branches so completed work cannot diverge silently from `main`
- [x] add a lightweight repository-integrity CI guard for sentinel placeholders and unexpectedly tiny critical workflow/source files
- [x] keep the first public v0.3.6 tag blocked until an explicit repository license is selected and the final release-candidate gate is green

### Recovery evidence (2026-09-01)
- canonical recovery PR: #41; superseded corrupted integration PR: #38
- Python compatibility: 3.11, 3.12, and 3.13 full test matrix
- Pi-hole compatibility: FTL 6.3, 6.5, and 6.6 integration matrix
- release trust: Windows/Linux byte-for-byte reproducibility, Sigstore verification, provenance/attestation, and amd64/arm64 container verification
- security: CodeQL Python/Actions and dependency review clean; third-party workflow actions pinned to immutable SHAs

## Priority 1: Stability and migration
- [x] operating-system credential stores
- [x] integration tests against multiple Pi-hole v6 minor versions
- [x] connection health state and clearer offline behavior
- [x] cancellable long-running evidence and LLM jobs
- [x] optional authenticated external trigger adapter for scheduled or MCP-driven review jobs

## Priority 2: Evidence quality
- [x] source-quality scoring and contradiction detection
- [x] locally indexed additional list repositories with provenance
- [x] URLhaus integration after its authenticated feed contract is implemented and tested
- [x] licensing review before enabling non-commercial datasets in distributed builds
- [x] certificate-transparency and additional reputation adapters
- [x] provider-native browsing support for LLMs that can cite primary sources
- [x] evidence citations in every generated description
- [x] golden datasets for source, prompt, and model comparison

## Priority 3: Domain intelligence
- [x] protected services and compatibility profiles
- [x] manual tags that override LLM tags
- [x] service dependency graphs
- [x] historical behavior-change detection
- [x] evidence freshness policies per tag and source

## Priority 4: Pi-hole management
- [x] group assignment for domains and lists
- [x] regex and subscribed-list views
- [x] conflict detection across exact rules, regex rules, groups, and locks
- [x] list audit jobs with configurable batches and rate limits
- [x] multiple Pi-hole instances
- [x] audit log and one-click rollback

## Priority 5: Review clients
- [x] authenticated local HTTP API
- [x] responsive web UI and PWA
- [x] ntfy and UnifiedPush notifications with deep links
- [x] allow, deny, postpone, ignore, and never-ask-again decisions
- [x] LAN and Tailscale access without a required public cloud

## Priority 6: Distribution
- [x] reproducible Windows and Linux Onedir releases
- [x] code-signing and release provenance (keyless Sigstore + signed in-toto/SLSA provenance)
- [x] multi-architecture Docker images with persistent volumes
- [x] Home Assistant app repository based on the container image
- [x] release retention and cleanup policy for development builds

## Priority 7: CI efficiency
- [x] avoid duplicate push and pull-request Python CI for feature branches
- [x] cancel superseded workflow runs
- [x] use a fast Python 3.12 pull-request gate and preserve the full supported-version gate on integration branches
- [x] scope Pi-hole compatibility testing to relevant paths and use the current target for ordinary pull requests
- [x] reserve reproducible Windows/Linux PR builds for packaging and release-build changes
- [x] keep native container smoke coverage while limiting QEMU multi-architecture PR builds to image-affecting changes
- [x] reduce scheduled development cleanup frequency while preserving post-publish cleanup
- [x] prevent public fork pull requests from receiving official release signatures or attestations

## Priority 8: Public release hardening
- [x] remediate known vulnerabilities in the current direct dependency baseline
- [x] license project source under AGPL-3.0-only, matching Sprachverstand
- [x] add a security policy with private vulnerability reporting guidance
- [x] enforce dependency review for pull requests that change dependencies
- [x] add CodeQL scanning for Python and GitHub Actions workflows
- [x] audit public README, contribution guidance, and release documentation
- [x] run the complete release-candidate gate before creating the first public v0.3.6 tag
- [x] preserve embedded `sbarbett/pihole6api` MIT attribution and add upstream/trademark notices
- [x] require project and third-party legal material in reproducible desktop release artifacts
- [x] replace legacy release branding/generated first-release notes with curated Wormhole Observatory v0.3.6 notes
- [ ] rerun the complete exact-tree release gate on the final licensing/release-preparation commit and record evidence in #46
- [ ] create and verify the first public `v0.3.6` tag only after Push Protection is confirmed enabled

## Priority 9: Shared-core dual frontend and full server administration

### Architectural invariant

Wormhole Observatory is **one application with one Python application core and two first-class
frontends**, not separate desktop and server products:

```text
                         ┌─ Tkinter desktop frontend ── in-process adapter ─┐
User / operator ─────────┤                                                  ├─ shared Python application services
                         └─ Web frontend / PWA ── authenticated HTTP API ──┘
                                                                            │
                                                                            ├─ SQLite / migrations
                                                                            ├─ Pi-hole v6 API
                                                                            ├─ evidence / LLM providers
                                                                            ├─ jobs / automation
                                                                            └─ audit / backup / restore
```

The application/service layer owns all business rules, validation, persistence, policy decisions,
Pi-hole mutations, evidence collection, job control, auditing and backup semantics. Tkinter remains
a local presentation layer that may call those services directly in-process. The Web frontend is a
separate browser presentation layer that reaches the same capabilities through a versioned HTTP
adapter. The desktop application must not be forced through HTTP merely for code reuse, and the Web
frontend must not reimplement application rules in JavaScript.

Docker is the preferred generic server distribution. Home Assistant reuses the same container
runtime. Bare-metal headless Python may remain supported where useful, but is not the primary server
installation path.

Tracking issue: #50.

### 9A. Shared application-service boundary

- [ ] inventory every user-visible desktop capability and classify it as shared-core, presentation-only, or platform-specific
- [ ] define explicit application-service/query interfaces for state-changing operations and read models instead of allowing frontends to reach directly into persistence or Pi-hole adapters
- [ ] move any remaining business decisions, validation, mutation orchestration, auditing, and rollback behavior out of Tkinter callbacks into shared application services
- [ ] keep configuration schemas and validation in the shared core so Tk and Web edit the same canonical settings model
- [ ] keep long-running jobs asynchronous/cancellable in the shared core; frontends only start, observe, cancel, retry, or prioritize them
- [ ] enforce import boundaries so core/service modules never depend on `pihole_manager.gui`, Tkinter, browser assets, or HTTP presentation code
- [ ] ensure the headless/container entry point can start and execute its full supported feature set without importing or initializing Tkinter

### 9B. Versioned administration API

- [ ] formalize a versioned HTTP API surface instead of extending review endpoints ad hoc
- [ ] expose Pi-hole instance management, connection health, groups, exact rules, regex rules, subscribed lists, conflicts, audits, and rollback through shared services
- [ ] expose Domain Database, evidence/history, protected services, dependency graphs, manual tags, rechecks, and review operations
- [ ] expose LLM providers, pools, quota state, evidence-source configuration, tests, and operational health without returning stored secrets
- [ ] expose job queues, scheduled work, cancellation/retry controls, simulation state, and background-worker status
- [ ] expose backup/export/restore and migration status through safe server-side operations rather than browser filesystem assumptions
- [ ] define consistent pagination, filtering, sorting, error envelopes, optimistic-concurrency/conflict behavior, and idempotency semantics for mutations
- [ ] generate or maintain machine-checkable API contracts and reject accidental backwards-incompatible changes without an explicit API-version decision

### 9C. Full responsive Web administration

- [ ] evolve the existing review PWA into a complete responsive administration shell while preserving its installable PWA behavior
- [ ] implement a Web dashboard for instance health, worker state, queue depth, recent actions, evidence-source status, provider quota/health, and update state
- [ ] implement Web administration for Pi-hole instances, domain rules/lists/groups, Domain Database, review queue, evidence/history, audit/rollback, and protected-service configuration
- [ ] implement Web administration for application settings, LLM providers/pools, evidence sources, notifications, automation, backups, and server operations
- [ ] preserve responsive phone/tablet/desktop layouts so the server UI is practical from mobile browsers as well as desktop browsers
- [ ] provide clear capability/error states when a function is unavailable because of deployment mode or host platform instead of silently hiding divergent behavior
- [ ] keep browser code presentation-oriented: no duplicated policy resolution, validation rules, Pi-hole mutation logic, or persistence behavior in JavaScript

### 9D. Desktop/Web parity contract

- [ ] maintain a capability matrix mapping each core feature to Tkinter, HTTP API, and Web UI support
- [ ] require every new shared feature to declare its frontend exposure before the roadmap item can be considered complete
- [ ] add service-level contract tests that both Tk-facing adapters and HTTP handlers exercise against the same fixtures and expected state transitions
- [ ] add mutation-parity tests for allow/deny, group/list/rule changes, settings writes, review decisions, job controls, rollback, and backup/restore flows
- [ ] add read-model parity tests for filtering, pagination, status, history, and conflict views
- [ ] permit deliberate desktop-only or Web-only capabilities only when the platform dependency is documented and the divergence is tested
- [ ] prevent frontend code from bypassing audit, policy, simulation, validation, or transaction boundaries

### 9E. Server authentication and network security

- [ ] evolve bearer-token bootstrap into a documented server-grade authentication/session model appropriate for browser administration
- [ ] add CSRF protection wherever cookie/session authentication or browser credentials make it applicable
- [ ] define secure token/session rotation, expiry, revocation, logout, and recovery behavior without storing recoverable secrets in browser storage unnecessarily
- [ ] keep safe defaults bound to local/private interfaces and require explicit configuration for broader network exposure
- [ ] document Tailscale-first remote access plus reverse-proxy/TLS deployments without requiring a public cloud
- [ ] define trusted-proxy/origin/host handling and rate limits for authentication-sensitive endpoints
- [ ] test that API responses, logs, diagnostics, exports, and browser-visible errors never expose stored credentials or secret configuration values

### 9F. Docker and server lifecycle

- [ ] keep one production container image for generic Docker and Home Assistant rather than maintaining separate server implementations
- [ ] provide a canonical Docker Compose example with explicit persistent volumes, health check, port binding, environment/config boundaries, and upgrade procedure
- [ ] add end-to-end persistent-volume tests for first boot, restart, upgrade, schema migration, backup, restore, and rollback
- [ ] define container update behavior independently from the desktop self-updater; image replacement must preserve application data and migration safety
- [ ] verify clean shutdown and restart semantics for workers, queues, SQLite transactions, and in-flight jobs
- [ ] verify `linux/amd64` and `linux/arm64` server behavior for every release that changes shared core or container/runtime code
- [ ] keep server runtime functional without desktop display libraries beyond unavoidable packaging dependencies

### 9G. Quality and release gates

- [ ] add API integration tests that boot the real headless runtime and execute representative administration workflows end to end
- [ ] add browser/PWA smoke tests for authentication, navigation, representative reads, representative mutations, and mobile-responsive rendering
- [ ] keep the existing Tkinter source and packaged-binary startup smoke gates alongside server tests; neither frontend may regress because the other advances
- [ ] require shared-core changes to pass desktop, API, and container test suites before release
- [ ] include the frontend capability matrix and known intentional parity gaps in release review until full parity is reached
- [ ] treat business logic duplicated in frontend code as an architectural regression to be removed before the corresponding feature is marked complete

### 9H. Optional later modes

- [ ] only after full administration API parity, evaluate an optional remote Tkinter client that connects to a remote Observatory core instead of opening the server database directly
- [ ] keep remote Tkinter optional; the supported server administration path remains the browser UI
- [ ] do not use VNC/noVNC or streamed Tkinter as the primary Web architecture
