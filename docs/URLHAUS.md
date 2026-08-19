# URLhaus evidence-source contract

Wormhole Observatory uses the URLhaus Community API only as an optional, user-configured evidence source. It is disabled by default.

## Authentication and endpoint

- An abuse.ch Auth-Key is required.
- The application sends `POST https://urlhaus-api.abuse.ch/v1/host/`.
- The normalized domain is sent as the form field `host`.
- The Auth-Key is sent only in the `Auth-Key` HTTP header and is managed through the existing research-provider credential-store path.
- A missing key is treated as a configuration error; the source test can skip unconfigured API-key sources.

## Evidence semantics

URLhaus tracks URLs used for malware distribution. A host result therefore needs current-status handling instead of treating every historical record as an active threat.

- At least one URL with `url_status=online`: verdict `malware`, decision-relevant.
- No online URL but at least one `url_status=unknown`: verdict `suspicious`, not eligible for automatic action by this source alone.
- Offline-only records: verdict `historical_malware`, not decision-relevant.
- `query_status=no_results`: neutral `no_match`; absence is never treated as evidence that a domain is safe.

Only a bounded subset of returned URL details is retained in evidence metadata. The Auth-Key is never added to evidence payloads.

## Operational defaults

- Source disabled by default.
- Six-hour evidence freshness window.
- One-second minimum request interval before adaptive backoff.
- Standard retry/backoff handling applies to transient HTTP failures and rate limiting.

The Community API remains subject to the abuse.ch fair-use terms. Distribution or commercial-use implications are handled by the separate evidence-source licensing review.
