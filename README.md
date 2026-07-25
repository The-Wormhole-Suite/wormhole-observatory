# Pi-hole Manager

Pi-hole Manager is a desktop application for **Pi-hole v6 or newer**. It combines convenient management of exact allow and deny entries with a local domain-intelligence database, optional evidence collection, and OpenAI-compatible LLM analysis.

## Status

Early alpha. The project currently provides the technical foundation for explainable domain intelligence:

- live collection and aggregation of DNS queries
- versioned LLM classifications instead of overwriting previous results
- multiple tags per domain, service attribution, and separate risk scores
- automatic re-evaluation of expired classifications
- optional evidence collection through RDAP, GitHub, Brave Search, and VirusTotal
- protected allow and deny entries with reconciliation support
- durable worker queues with claim, acknowledge, retry, and failure states
- manual review tasks for uncertainty, high breakage risk, or policy conflicts

Automatic changes should initially be tested only in `manual` or `hybrid` mode.

## Research and LLM data flow

Research providers do not replace the LLM. They collect structured facts and source references before classification:

1. Pi-hole Manager checks its local research cache.
2. Enabled providers retrieve registration data, source-code references, search-result snippets, or threat-intelligence data.
3. Findings are stored locally with provider, source URL, confidence, retrieval time, and expiration time.
4. The application builds a domain dossier containing DNS observations, research findings, and protection state.
5. The dossier is sent to the selected LLM, which creates the human-readable description, tags, service attribution, risk scores, and recommendation.
6. The response is validated before it is stored or considered by the policy engine.

The current provider layer collects API responses and snippets. It does not yet crawl complete forum discussions or repository issues. Deeper source retrieval, source-quality weighting, and evidence citations are planned.

## Architecture

- `pihole6api/`: low-level, UI-independent Pi-hole v6 API layer
- `pihole_manager/`: configuration, SQLite persistence, research, LLM logic, and workers
- `pihole_manager/gui/`: Tkinter user interface and tabs
- `tests/`: offline tests without a running Pi-hole, research, or LLM server
- `docs/`: architecture decisions and roadmap

Further details are available in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

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

On Linux, activate the environment with:

```bash
source .venv/bin/activate
```

Optional desktop notifications:

```bash
python -m pip install -e ".[desktop-notifications]"
```

## Configuration and privacy

On first launch, Pi-hole Manager creates a local `options.json`. It may contain the Pi-hole application password and LLM or research API keys in plain text. The file is excluded through `.gitignore` and must never be committed.

External research is disabled by default. Enabling a provider sends the domain being investigated to that provider. RDAP does not require an API key; GitHub code search, Brave Search, and VirusTotal require separate credentials.

A cloud-hosted LLM is also an external service and receives the configured domain dossier. A locally hosted model, such as a local OpenAI-compatible endpoint, keeps that analysis inside the user's own environment.

`options.example.json` documents the complete configuration structure without credentials.

Pi-hole exposes version-specific API documentation at `http://pi.hole/api/docs`. This local documentation should be checked first when API behavior differs between Pi-hole releases.

## LLM output

The manager expects a strictly validated batch result. Each domain receives separate fields for:

- primary and additional tags
- service name and service role
- privacy, security, and breakage risk
- model confidence and manual-review reason
- recommendation, concise description, and detailed explanation
- next re-evaluation date

Providers may use JSON Schema, JSON Object mode, or prompt-only formatting. In `auto` structured-output mode, the client tries the supported variants in a controlled order. Responses containing missing, duplicate, or unexpected domains are rejected.

## Automation safety model

- `manual`: never change Pi-hole entries automatically
- `hybrid`: the model recommendation and every applicable tag policy must agree
- `auto`: a shared tag policy may be applied automatically

No automatic action is taken when:

- manual review is required
- confidence is below the configured threshold
- the domain is core or shared infrastructure
- breakage risk is too high
- tag policies conflict
- the action conflicts with a protected list entry

The concise LLM description is used as the Pi-hole comment for allow or deny actions.

## Development

```bash
python -m pip install -e ".[dev]"
pytest
ruff check .
```
