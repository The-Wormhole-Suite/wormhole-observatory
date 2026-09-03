# Wormhole Observatory

Wormhole Observatory is a desktop and headless management application for **Pi-hole v6 or newer**. It combines exact allow/deny management with local domain intelligence, evidence collection, structured LLM classification, conservative automation, review clients, and optional container/Home Assistant deployment.

The project was developed under the working name **Pi-hole Manager**. Version 0.3.6 still retains some `pihole-manager` package names, entry points, and `Pi-Hole-Manager` build paths for compatibility; these identifiers do not indicate a separate project.

## Status

Pre-1.0 development. The repository is public and the current application version is 0.3.6. Enable **Simulation mode** for the first live test so the complete pipeline can run without automatic Pi-hole changes.

Stable public release artifacts are reproducible Windows/Linux Onedir builds with signed provenance. A headless multi-architecture container and a Home Assistant App configuration are also maintained in this repository. See [docs/RELEASE_TRUST.md](docs/RELEASE_TRUST.md), [docs/REPRODUCIBLE_RELEASES.md](docs/REPRODUCIBLE_RELEASES.md), and [docs/CONTAINER.md](docs/CONTAINER.md).

## Core data flow

1. The query collector retrieves live Pi-hole queries and stores aggregated observations.
2. New, stale, manually selected, or scheduled domains enter a durable analysis queue.
3. Fresh cached research findings are loaded separately for every source.
4. Enabled research sources run in parallel with each other, while requests remain serial within
   each source. A source is contacted only when its own evidence is missing or expired.
5. The realtime or background analysis pool freezes the dossier and dispatches it according to
   its configured provider strategy.
6. The LLM returns tags, service attribution, risks, confidence, description, and a recommendation.
7. The response is validated against a fixed schema.
8. A deterministic policy engine decides whether an automatic Pi-hole action is safe.
9. Unsafe, conflicting, or uncertain results create a manual review task.
10. In Simulation mode, otherwise eligible automatic actions are stored for later approval instead of being sent to Pi-hole.

The LLM interprets evidence. It is not allowed to bypass the safety and policy layer.

## Background workers

- **Query collector:** reads live queries, aggregates observations, and queues unseen or stale domains.
- **Realtime analysis worker:** processes interactive and manually queued work independently from
  slower background batches.
- **Background analysis worker:** processes collected domains and scheduled rechecks. Both workers
  refresh enabled evidence, use token-aware batches, store immutable provider runs, and evaluate
  policies only for primary results.

Automatic query jobs start when the configured queue threshold is reached or the oldest job has waited long enough. Manually queued jobs bypass that threshold. Pending, processing, and failed analysis jobs are visible immediately in Review Queue, including their source and current state.

LLM and evidence-provider requests honor `Retry-After` and common rate-limit reset headers.
Transient 408, 429, 500, 502, 503, and 504 responses use bounded adaptive backoff. Authentication
and other non-transient errors are not retried, and a rate-limited request never triggers additional
structured-output fallback calls.

LLM quota is reserved atomically in SQLite immediately before every HTTP attempt. Estimated token
usage is reconciled with response usage, and live quota headers take precedence over configured or
registry values. Background work cannot consume the configured realtime reserve. A quota-delayed
queue item is made available at the calculated reset time rather than being reclaimed in a tight
loop.

## Tags and policies

A domain may have multiple tags. Every tag has an administrative default policy:

- `allow`
- `deny`
- `manual_review`

Automatic action is permitted only when all tags resolve to the same actionable policy. A `manual_review` tag acts as a veto. Mixed `allow` and `deny` policies create a conflict and require review.

Each tag also has a recheck age. For domains with multiple tags, the shortest configured age is the upper limit; a shorter model suggestion is honored. Confidence is handled in three bands: results below the review threshold require review, results between the review and automatic thresholds are stored without automatic action, and results above the automatic threshold may be eligible for automation. Additional safety checks still block automation for high breakage risk, core or shared infrastructure, protected-list conflicts, and—by default—missing research evidence. Protected domains are excluded from automatic collection and scheduled rechecks; the manager does not continuously restore entries changed outside the application.

## Simulation mode

Simulation mode is enabled by default for new installations. Evidence collection, LLM calls,
structured validation, confidence thresholds, tag policies, and automatic decision resolution all
run normally. An eligible automatic whitelist or blacklist action is stored with the classification as a
`simulated` action and appears in Review Queue and Domain Database. **Apply planned** performs the saved
action later. Manual Whitelist/Blacklist buttons remain immediate and are never converted into simulations.

Disabling Simulation mode allows eligible automatic actions to be written to Pi-hole. Historical
simulation results remain visible and can still be applied or dismissed.

## Review workflow, Domain Browser, and table columns

The Review Queue uses three normal actions: **Analyze selected** queues the LLM and automatically reuses fresh evidence while collecting only missing or expired source data; **Collect evidence** refreshes enabled structured sources without invoking the LLM; and the single-domain context action **Run full review** refreshes evidence before queuing the LLM. The same context menu can show a compact evidence view without exposing raw provider payloads. Separate variants such as “analyze with collected evidence” are unnecessary because normal analysis always consumes the current evidence cache.

Pending entries show **Not analyzed** until an LLM result exists. Unknown risk values are displayed as a dash rather than a synthetic score. For classified domains, breakage risk is a 0–100 estimate of how likely blocking the domain is to disrupt a service; 50 represents medium risk and already prevents an automatic Pi-hole change.

The **Domain Database** tab provides a searchable view of every stored classification, including
entries that no longer require manual review. Its batch actions are **Re-analyze selected** and
**Re-collect evidence**. Filters are available for free text, policy, tag, service role, review
state, and overdue rechecks. Results are queried directly from SQLite and loaded in pages of 500
rows.

The main domain tables share sortable columns for domain, state, policy, risk, confidence, evidence age, service, tags, source, and timestamps. Column visibility is configurable per table and persisted locally.

## Analysis pools and provider limits

Realtime and background analysis use separate configurable provider pools. A pool may contain one or more providers, and a provider can be used by both pools. The dispatcher can select the first available provider, round-robin between providers, or fan out a comparison run where appropriate. Only the primary result can trigger policy actions; comparison results remain available for review.

Provider limit modes are **Auto**, **Auto with own caps**, and **Manual**. Resolution priority is:
provider-registry metadata, live provider headers, user caps, and finally conservative limits for an unknown remote provider. Shared account quotas can be linked through a common quota key.

## Evidence and research

Evidence collection is source-oriented rather than prompt-oriented. Each source has its own cache,
TTL, quality metadata, and error state. Current adapters include DNS, RDAP, certificate transparency,
list repositories, reputation sources, and optional authenticated feeds. The LLM receives a compact,
bounded dossier; raw provider payloads are not blindly forwarded.

Research may include, depending on configuration and availability:

- DNS records and local resolver observations
- RDAP registration data
- certificate-transparency observations
- RIPEstat/network metadata
- list repository matches with provenance
- Disconnect-style service/category data when licensing permits distribution
- optional Netcraft Site Report parsing when robots.txt and fair-use access permit it
- existing urlscan.io scan metadata without submitting active scans
- authenticated URLhaus feed data when configured

Prompt input is bounded: negative cache entries are omitted, decision-relevant findings are
prioritized, summaries are truncated, and only a limited number of findings are sent. Full raw
research remains local.

## Protected services and dependency graphs

Compatibility profiles identify protected services and domains where automatic blocking would be unusually risky. Service dependency graphs let classifications record relationships such as first-party service domains, shared infrastructure, authentication dependencies, telemetry, and optional components. Manual tags override LLM-generated tags without losing the model result.

Historical behavior-change detection compares evidence snapshots and classifications over time. Material changes can schedule a recheck rather than silently reusing an obsolete result. Evidence freshness is source- and tag-aware.

## Pi-hole management

The manager supports exact domain rules, regex rules, subscribed lists, group assignment, multiple Pi-hole instances, list audits, conflict detection, and an audit log with rollback. Mutating operations pass through the same service layer so UI, review API, and automation do not implement separate rule-writing logic.

## Review API and PWA

The optional local HTTP API exposes authenticated review operations and the responsive PWA. LAN and Tailscale access can be enabled without a public cloud. ntfy and UnifiedPush notifications can deep-link into a review item. Review decisions include allow, deny, postpone, ignore, and never-ask-again preferences.

See [docs/LOCAL_API.md](docs/LOCAL_API.md), [docs/REVIEW_PWA.md](docs/REVIEW_PWA.md), [docs/NETWORK_ACCESS.md](docs/NETWORK_ACCESS.md), and [docs/PUSH_NOTIFICATIONS.md](docs/PUSH_NOTIFICATIONS.md).

## Source installation

Requirements:

- Python 3.11 or newer
- Tkinter
- Pi-hole v6 or newer

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install -e .
python app.py
```

Install the dependencies once before starting the source checkout. On Windows, then start `app.pyw` with `pythonw.exe` or by double-clicking it to run without a terminal window. An editable installation also creates the GUI entry point `pihole-manager`. If `dnspython` is not available, the GUI still starts and the DNS evidence source falls back to standard-library A/AAAA resolution; installing the declared dependencies enables CNAME, NS, MX, HTTPS, and SVCB lookups.

On Linux:

```bash
source .venv/bin/activate
```

Optional desktop notifications:

```bash
python -m pip install -e ".[desktop-notifications]"
```

## Windows executable

A windowed PyInstaller build can be created without a console window:

```powershell
.\build_windows.ps1
```

The resulting Onedir application is written to `dist\Pi-Hole-Manager\`. Runtime errors continue to be written to the configured log file.

## Configuration

The first launch creates a local `options.json` for non-secret application settings. Supported credentials are stored through the operating-system credential store rather than being deliberately persisted in plaintext configuration. Existing legacy values are migrated when the relevant credential path is used. Keep configuration files, databases, logs, exports, and backups private because they can still contain operational metadata.

Pi-hole exposes version-specific API documentation at `http://pi.hole/api/docs`.

## Development

```bash
python -m pip install -e ".[dev]"
pytest
ruff check .
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), and [docs/ROADMAP.md](docs/ROADMAP.md).

## Update service

Packaged Windows and Linux Onedir builds can update themselves from GitHub Releases. The updater
selects the matching operating-system and CPU-architecture ZIP, verifies the published SHA-256
digest when available, validates the embedded install manifest, and prepares the new version beside
the running application. After the application closes, a small platform script replaces the program
directory, preserves `options.json`, SQLite files, evidence caches, update downloads, and log files,
then starts the new version. If the new version does not confirm a successful start, the previous
Onedir directory is restored automatically. Source checkouts can download updates but are never
overwritten automatically.

The Application settings provide two channels:

- **Stable releases** for normal version tags
- **Prerelease versions** for beta, release-candidate, and automated `dev`-branch Onedir builds

Update checks use the public GitHub Releases API and do not require a GitHub token to be stored by the application.

Container installations do not use the desktop self-updater. Docker or the chosen container manager pulls a new image and recreates the container while persistent data remains in mounted volumes. The Home Assistant App uses the same container image and Home Assistant's own update flow.

## License, source, and project identity

Wormhole Observatory source code is licensed under the **GNU Affero General Public License v3.0 only** (`AGPL-3.0-only`). See [LICENSE](LICENSE) and [NOTICE](NOTICE). The project name, logo, and other official branding are not licensed under the AGPL; see [TRADEMARKS.md](TRADEMARKS.md).

The embedded `pihole6api/` package is derived from the MIT-licensed `sbarbett/pihole6api` project. Its original copyright and MIT notice are preserved in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md); provenance is documented in [UPSTREAMS.md](UPSTREAMS.md). Packaged desktop releases also contain a generated `THIRD_PARTY_LICENSES.txt` for the pinned Python build/runtime environment.

Wormhole Observatory is not an official Pi-hole project and is not affiliated with or endorsed by the Pi-hole project. The Pi-hole name is used only to describe interoperability and compatibility.

Source code: https://github.com/The-Wormhole-Suite/wormhole-observatory

## Evidence source tests

The Evidence Sources settings page can test the selected source or all configured sources.
Tests use source-specific public test domains and exercise the actual parser without writing findings into the domain database. Each source can define its own test domain. Test all can independently skip every API-key source or only sources whose required key has not been configured. Skipped sources are counted in the completion line but omitted from the result table. The API-key field is shown only for source types that actually require one, and RDAP exposes its IANA bootstrap URL explicitly.
