# Local Review HTTP API

Wormhole Observatory exposes a small versioned HTTP API through the existing authenticated review-trigger server. The API is intended for local review clients, the bundled web/PWA client, schedulers, and trusted LAN/Tailscale integrations.

## Security model

The server is disabled by default. Configure it under **Settings → Application → External review trigger**. That label is retained for configuration compatibility even though the server now also provides the review API and PWA.

- Every API endpoint, including `/health`, requires `Authorization: Bearer <token>`.
- The default bind address is `127.0.0.1`.
- Binding to a non-loopback address is rejected unless remote access is explicitly enabled.
- API responses use `Cache-Control: no-store`.
- Request bodies are capped at 64 KiB.
- Review list sizes and queued-domain batches are capped by `max_domains_per_request`.
- The static `/app/*` PWA shell is public but contains no data or token; all of its data requests still use the authenticated API.

Do not put the bearer token in a URL or query string.

## API version 1

### `GET /health`

Minimal authenticated health probe.

### `GET /v1/status`

Returns the API version, service name, and advertised capabilities.

### `GET /v1/reviews?limit=200`

Returns pending review/analysis-queue items. Postponed and never-ask-again domains are omitted. Only documented review fields are serialized; internal database fields are not exposed.

### `GET /v1/reviews/{domain}`

Returns the current review/classification record for an exact normalized domain, or `404` when no record exists.

### `POST /v1/reviews/{domain}/decision`

Applies one review decision. Body examples:

```json
{"decision": "allow"}
```

```json
{"decision": "postpone", "postpone_until": 2000000000}
```

Supported decisions are `allow`, `deny`, `postpone`, `ignore`, and `never_ask`.

- **allow/deny** apply an exact Pi-hole rule and close the review. An opposite exact rule is removed after the selected rule is successfully present.
- **ignore** closes only the current review; a later classification may request review again.
- **postpone** hides the review until the supplied future Unix timestamp without destroying the analyzer's review state.
- **never_ask** durably suppresses future review prompts while preserving analysis/history.

Validation errors return `400`. Conflicts such as protected Pi-hole rules return `409`.

### `POST /v1/review`

Queues domains for analysis/review. Body:

```json
{"domains": ["example.com", "api.example.org"]}
```

### `POST /v1/recheck-due?limit=100`

Queues domains whose scheduled recheck is due.

### `POST /v1/cancel`

Cancels currently cancellable classifier jobs.

## Bundled web client

Opening `/` redirects to `/app/`. The web client is responsive and installable as a PWA when the browser considers the origin a secure context. The detail dialog exposes the same five review decisions as the desktop client.

## Example

```bash
curl -H "Authorization: Bearer $WORMHOLE_TOKEN" \
  http://127.0.0.1:8765/v1/reviews?limit=25
```
