# Evidence freshness policies

Wormhole Observatory evaluates evidence freshness from both the evidence source and the domain's
current effective tags. The cache always uses the shortest applicable lifetime.

## Precedence

For each finding the effective expiry is the earliest of:

1. an expiry already supplied by the evidence adapter;
2. the source's configured `refresh_interval_hours`; and
3. the maximum age for any matching effective domain tag.

The global research max age is a fallback only for unknown/unconfigured source kinds. It does not
shorten an explicitly configured source or a local static compatibility profile.

A provider-supplied shorter expiry is never extended.

## Source policies

Existing `ResearchProviderOptions.refresh_interval_hours` is the source-specific policy control.
This avoids a second duplicate set of source refresh settings. Built-in fallback values mirror the
normal source defaults and also cover adapters that are registered without a persisted provider
entry.

Examples include Local DNS at 6 hours, ThreatFox at 6 hours, PhishTank at 1 hour, RDAP at 168
hours, repository lists at 12 hours, and URLhaus at 6 hours.

`compatibility_profile` is local, versioned application data. It uses a one-year source lifetime and
is deliberately tag-insensitive; a domain later receiving a `malware` tag must not make the local
service-protection fact disappear after six hours.

## Tag policies

Tag maximum evidence ages are intentionally separate from classification recheck intervals:

| Tag group | Evidence maximum age |
| --- | ---: |
| malware, phishing, command-and-control | 6 h |
| security / antifraud | 12 h |
| unknown, software updates | 24 h |
| payments | 48 h |
| advertising, tracking, analytics, telemetry, authentication, API, messaging, IoT | 72 h |
| crash reporting, content/media, shared CDN infrastructure | 168 h |

When multiple tags are active, the shortest tag lifetime wins. Manual tags have precedence over LLM
and current-classification tags, matching the rest of Domain Intelligence.

For a newly observed domain with no classification yet, source freshness applies immediately and
tag freshness begins automatically once tags exist.

## Upgrade and cache behavior

Freshness is enforced twice:

- when a finding is saved, its effective expiry and policy provenance are stored in
  `raw_data.freshness_policy`; and
- whenever code requests `research_findings_get(..., fresh_only=True)`, existing rows are
  re-evaluated against the current source and tag policy.

The second check makes the policy retroactive. Evidence written by an older Observatory version can
therefore become stale immediately after an upgrade or after a manual tag change even if its stored
legacy `expires_at` value lies further in the future.

No database migration is required. Stale rows remain available for history and inspection when
`fresh_only=False`; they are simply excluded from active evidence collection, LLM context, and new
evidence citations until refreshed.
