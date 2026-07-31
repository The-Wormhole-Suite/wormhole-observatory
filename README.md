# Pi-hole Manager

Pi-hole Manager is a desktop application for **Pi-hole v6 or newer**. It combines management of exact whitelist and blacklist entries with local domain intelligence, evidence collection, structured LLM classification, and conservative automation.

## Status

Early alpha. Enable **Simulation mode** for the first live test so the complete pipeline can run without automatic Pi-hole changes.

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
entries.

The **Columns** menu in Live Queries, History Browser, Lists, Review Queue, and Domain Database
controls which fields are shown. Columns can be reordered by dragging their headings or through the
Reorder columns dialog. Review Queue headings can also be clicked to sort; the numbered column or
**Reset sort** restores the original queue order. Auto-update, auto-scroll, and the refresh interval
are configured directly in the Live Queries tab. Visibility, order, and widths are persisted
separately for every table. The Pi-hole comment column is hidden by default in the Lists tab and can
be enabled when needed. The Lists tab can queue selected entries or the complete current
whitelist/blacklist for review, optionally limited to domains that have never been classified.


## History Browser and idle backfill

The **History Browser** searches Pi-hole query history by time range, domain, and client. It can show only domains that do not yet have a stored classification, optionally deduplicate repeated rows by domain, and queue selected rows or the complete page for review. Results are read in bounded pages and are never sent to the LLM merely by opening the browser.

An optional idle history backfill can inspect older query pages after the live collector has received no new rows for a configured period. It queues only unclassified domains or domains whose recheck is due, processes one bounded page per cycle, and is disabled by default. Queue filtering is centralized; `.arpa` is excluded by default and additional suffixes can be configured under Automation without removing those rows from Live Queries or History Browser.

## Settings behavior

Settings pages scroll vertically when their content does not fit in the available window. Application, automation, provider, analysis-pool, prompt-profile, and evidence-source changes are saved automatically after validation. Pi-hole connection values remain explicit: **Save + Test** stores the base URL, password, timeout, and TLS setting before testing the saved connection. Optional help icons can be disabled globally from the Application page.

## Analysis pools and provider limits

Realtime and background analysis have independent provider memberships, prompt profiles, and
maximum parallelism. Each pool supports:

- **Distribute:** deterministically assigns every domain to exactly one weighted provider.
- **Fallback:** tries the next provider only for quota, cooldown, connection, timeout, or transient
  service failures. Invalid model output does not multiply requests.
- **Compare:** sends the same frozen dossier to every selected provider and stores results
  side-by-side without updating the current classification or Pi-hole.
- **Verify:** sends selected high-risk, sampled, or automation-eligible primary results to an
  independent provider. A material disagreement forces manual review and prevents automatic action.

The Analysis Pools settings page also runs a one-domain benchmark across selected providers using
one identical dossier. Results include model, status, latency, policy, and category.

Provider limit modes are **Auto**, **Auto with own caps**, and **Manual**. Resolution priority is:
user caps, live response headers, a verified online registry, the bundled registry, then
conservative limits for an unknown remote provider. Shared account quotas can be linked through a
quota group. Context size, calibrated output usage, safety reserve, and provider-specific maximums
determine the actual domains per request.

## Structured evidence and privacy

Every queued domain is still assessed by the LLM. The evidence layer does not replace the
model and is not a low-confidence fallback. It collects compact, machine-readable facts first,
then the LLM turns the complete dossier into tags, service attribution, risks, confidence, and a
human-readable explanation. A deterministic policy engine remains the final gate before any
Pi-hole change.

Evidence sources are divided into three modes:

- **Local sources** inspect DNS data without contacting a dedicated evidence provider.
- **Catalog sources** periodically download complete datasets and match domains locally.
- **Lookup sources** send the investigated domain or a locally resolved public IP to a service.

Built-in adapters include:

- AdGuard service metadata for service and domain-family attribution
- local A, AAAA, CNAME, NS, MX, HTTPS, and SVCB records
- optional Disconnect tracker metadata
- RDAP registration records
- RIPEstat prefix, ASN, and network-holder information
- optional Netcraft Site Report parsing when robots.txt and fair-use access permit it
- VirusTotal reputation and scanner verdicts
- ThreatFox exact IOC matches
- a locally indexed PhishTank verified-phishing database
- existing urlscan.io scan metadata without submitting active scans
- Cloudflare Radar popularity and category metadata

Generic search engines and generic GitHub code search are intentionally excluded from the
structured layer. There is no portable provider-independent model API flag that guarantees
Internet access, and Pi-hole Manager does not currently invoke provider-specific web-search tools.
A provider that performs browsing automatically may use official documentation, selected GitHub
repositories, issues, discussions, Pi-hole community reports, and user reports. Other models must
rely on the supplied dossier and must not claim independent web research.

Findings are normalized to a signal type and verdict. Infrastructure context such as RDAP,
Netcraft, DNS records, ASN ownership, or popularity can improve the LLM description but cannot by
itself authorize automatic whitelist or blacklist actions. Only explicitly decision-relevant evidence,
such as a confirmed tracker classification or active threat match, can satisfy the optional
evidence requirement for automation.

Prompt input is bounded: negative cache entries are omitted, decision-relevant findings are
prioritized, summaries are truncated, and only a limited number of findings are sent. Full raw
responses remain available in the local database for the details view.

External lookup providers receive the data described in their settings. Cloud-hosted LLMs receive
the resulting dossier. Local SQLite storage, a local Pi-hole instance, catalog lookups after the
catalog has been downloaded, and a locally hosted LLM remain inside the user's environment.

## Prompt profiles and output contract

Prompt profiles customize analysis behavior. The default profile tells browsing-capable models to verify domains against official documentation, GitHub issues and discussions, Pi-hole community reports, reputable blocklist repositories, and credible user reports. Models without browsing must not claim that they searched the web. The application appends an immutable technical contract containing:

- configured tags and policies
- exact required fields
- enumerated values and numeric ranges
- the JSON Schema
- one-result-per-domain rules

The user template must include `{domain_dossiers}`. The effective prompt can be previewed in the settings UI.

Malformed, incomplete, duplicated, or mismatched results are rejected before they reach the policy engine.

## LLM provider presets

LLM providers and provider presets are sorted alphabetically; the active provider remains marked.
Enabled evidence sources are shown before disabled sources and sorted alphabetically within each
group. The LLM Providers settings page includes verified presets for major direct APIs, routing
services, and local runtimes:

- OpenAI, Anthropic Claude, Google Gemini, xAI, DeepSeek, and Mistral
- GroqCloud, Cloudflare Workers AI, OpenRouter, Perplexity, Together AI, Fireworks AI, Cohere,
  Cerebras, SambaNova, and Hugging Face Inference Providers
- Ollama, LM Studio, llama.cpp, LocalAI, vLLM, and LiteLLM

Dedicated free-tier presets are included for Groq GPT OSS 120B, Gemini 3.6 Flash, OpenRouter's
free-model router, and Cloudflare Workers AI with Qwen3 30B, GPT OSS 20B, or GPT OSS 120B.
Cerebras is labeled as a time-limited trial rather than a permanent free tier. GitHub Models is not
offered because the service was retired. Adding a preset applies a conservative request profile;
runtime headers and the quota manager remain authoritative.

A practical free-tier starting point is Groq GPT OSS 120B as the realtime primary, Gemini as an
alternative, and OpenRouter Free as the last fallback. For background distribution, use Cloudflare
Workers AI with Qwen3 30B or GPT OSS 20B; select GPT OSS 120B when result quality matters more than
neuron consumption. Cerebras should only be added while its trial is active. Provider credentials
and Cloudflare account IDs must still be configured before adding these providers to a pool.

The bundled `provider-registry.json` records reviewed capabilities, free-tier status, quota scope,
and source URLs. A weekly workflow opens or updates a maintenance issue when entries need review.
Publishing a remote registry is a separate environment-protected workflow: it signs the exact JSON
with Ed25519 and uploads both `provider-registry.json` and `provider-registry.json.sig`. Runtime
updates remain disabled until a reviewed public key replaces the placeholder and the matching
private key is configured as the protected GitHub Actions secret
`PROVIDER_REGISTRY_ED25519_PRIVATE_KEY`. Generate a pair with:

```bash
python scripts/provider_registry.py generate-key registry-private.pem \
  pihole_manager/data/provider_registry_public_key.pem
```

Store `registry-private.pem` only in the protected secret, never in Git. After that one-time setup,
enable verified registry updates under Analysis Pools.

Most providers use the OpenAI-compatible Chat Completions transport. Anthropic uses its native Messages API. **Fetch models** queries the provider's live models endpoint when the provider exposes one, so model IDs do not need to remain hard-coded in the application. A custom OpenAI-compatible provider remains available for self-hosted and enterprise gateways.

**Discover local servers** probes only well-known loopback endpoints on `127.0.0.1`. It can detect Ollama, LM Studio, LocalAI, llama.cpp, vLLM, and LiteLLM, import visible model IDs, and avoid duplicate provider entries. It never scans the LAN automatically. A model server on another machine can be added through a preset or custom base URL and queried with **Fetch models**.

Provider settings also allow disabling the temperature parameter and selecting whether the API expects `max_tokens`, `max_completion_tokens`, or no output-token parameter. This is necessary because OpenAI-compatible implementations differ in these details.

Azure OpenAI, Amazon Bedrock, and Google Vertex AI are not represented as one-click presets because their endpoint and authentication values depend on deployments, regions, resources, or cloud IAM. They can be connected through an OpenAI-compatible gateway such as LiteLLM.

## Installation

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

The first launch creates a local `options.json`. It may contain Pi-hole, LLM, and research credentials in plain text. Operating-system credential-store integration is planned before a stable release.

Pi-hole exposes version-specific API documentation at `http://pi.hole/api/docs`.

## Development

```bash
python -m pip install -e ".[dev]"
pytest
ruff check .
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/ROADMAP.md](docs/ROADMAP.md).

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

Update checks use the public GitHub Releases API. They remain unavailable while the repository is private; no GitHub token is stored or requested by the application.

Container installations do not use the desktop self-updater. Docker or the chosen container manager
pulls a new image and recreates the container while persistent data remains in mounted volumes. A
future Home Assistant app uses the same container image and Home Assistant's own update flow.

## Evidence source tests

The Evidence Sources settings page can test the selected source or all configured sources.
Tests use source-specific public test domains and exercise the actual parser without writing findings into the domain database. Each source can define its own test domain. Test all can independently skip every API-key source or only sources whose required key has not been configured. Skipped sources are counted in the completion line but omitted from the result table. The API-key field is shown only for source types that actually require one, and RDAP exposes its IANA bootstrap URL explicitly.
