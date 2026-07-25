# Architecture

## Product model

Pi-hole Manager treats four layers as separate concerns:

1. **Observation** – when, how often, and by which clients a domain was used
2. **Knowledge** – research findings, tags, service attribution, and classification history
3. **Decision** – user and policy decisions, including manual review tasks
4. **Enforcement** – the actual allow and deny entries in Pi-hole

An LLM recommendation is therefore not a DNS command. Only the deterministic policy engine may derive an enforcement action from it.

## Layers

### `pihole6api`

This layer knows only HTTP and Pi-hole resources. It contains no GUI, database, or application configuration logic.

- normalizes base URLs to `/api/`
- manages Pi-hole sessions
- supports configurable TLS verification and timeouts
- raises defined HTTP, authentication, and connection exceptions
- automatically retries only idempotent read requests

### `pihole_manager`

This layer contains application rules:

- typed and migratable configuration
- SQLite queues with claim, acknowledge, retry, and failure semantics
- persisted scanner checkpoints
- aggregated DNS-query observations
- versioned research and classification runs
- OpenAI-compatible LLM integration with validated batch output
- deterministic resolution of multiple tag policies
- long-running scanner, classifier, and lock-reconciliation workers

### `pihole_manager.gui`

Tkinter is limited to presentation and user interaction. Network operations run through an executor, and their results are returned to the UI thread.

## Data model

### `domains`

Stable state for each domain: first and last observation, query count, latest classification, next re-evaluation, and the current service and policy snapshot.

### `query_observations`

Hourly aggregates grouped by domain, client, query type, and status. This preserves relevant context without duplicating every DNS query indefinitely.

### `classification_runs`

Immutable history of LLM evaluations, including provider, model, prompt fingerprint, tags, risk scores, confidence, raw response, and expiration time.

### `research_findings`

Time-limited evidence from independent sources. The planned provider set includes:

- RDAP registration information through the IANA bootstrap registry
- GitHub code and list references
- Brave web-search results
- VirusTotal domain reports

Each provider has independent caching, timeout, and request-interval settings. Internet-facing research providers are disabled by default.

### `domain_locks`

An administrative protection rule for an exact allow or deny entry. The lock reconciler restores missing entries and creates a review task when contradictory entries are detected.

### `review_tasks`

Prioritized tasks for uncertain, risky, or conflicting results. This table is intended to become the shared foundation for desktop, web, and smartphone review clients.

## Tags, service attribution, and policy

The semantic layers remain separate:

- `tags`: multiple purposes or technical roles
- `service`: suspected or known service
- `service_role`: `core`, `optional`, `shared`, or `unknown`
- `policy`: model recommendation
- risk scores: privacy, security, and service-breakage risk

A classification may carry `telemetry`, `analytics`, and `api_backend` at the same time. Automatic action is allowed only when all applicable tag policies resolve to the same action.

## LLM contract

The LLM returns an object containing `schema_version` and a `results` array. The application validates:

- exactly one result for every requested domain
- no unknown or duplicate domains
- valid tags and enum values
- bounded confidence and risk values
- all required fields

Schema compliance protects only the technical interface. The policy engine also evaluates semantic risks and fails closed.

## Research data flow

Research providers collect structured evidence before LLM classification. Cached findings are combined with DNS observations and protection state into a domain dossier. The dossier is then supplied to the selected LLM, which performs interpretation, synthesis, and risk assessment.

Search-result snippets and API summaries are evidence hints, not verified facts. Future versions should fetch selected primary sources, retain relevant passages, weight source quality, and expose citations in the review interface.

## Persistence, privacy, and secrets

`options.json`, the SQLite database, and log files are runtime data stored in the application directory and must not be committed to Git. Configuration is replaced atomically through a temporary file.

An external provider is any internet-facing service outside the user's Pi-hole Manager host or trusted local environment. This includes public RDAP servers, GitHub, Brave Search, VirusTotal, and cloud-hosted LLM APIs. Such providers receive at least the domain being investigated; a cloud LLM may receive the complete configured domain dossier.

The current password storage remains baseline-only. A later version should support Windows Credential Manager, Secret Service, and macOS Keychain through a secret-store abstraction.
