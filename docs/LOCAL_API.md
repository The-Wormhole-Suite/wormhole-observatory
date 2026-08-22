# Local Review HTTP API

Wormhole Observatory exposes a small versioned HTTP API through the existing authenticated review-trigger server. The API is intended for local review clients, later web/PWA clients, schedulers, and trusted LAN/Tailscale integrations.

## Security model

The server is disabled by default. Configure it under **Settings → Application → External review trigger**. That label is retained for configuration compatibility even though the server now also provides read-only review endpoints.

- Every endpoint, including `/health`, requires `Authorization: Bearer <token>`.
- The default bind address is `127.0.0.1`.
- Binding to a non-loopback address is rejected unless remote access is explicitly enabled.
- Responses use `Cache-Control: no-store`.
- Request bodies are capped at 64 KiB.
- Review list sizes and queued-domain batches are capped by `max_domains_per_request`.

Do not put the bearer token in a URL or query string.

## API version 1

### `GET /health`

Minimal authenticated health probe.

### `GET /v1/status`

Returns the API version, service name, and advertised capabilities.

### `GET /v1/reviews?limit=200`

Returns pending review/analysis-queue items. Only the documented review fields are serialized; internal database fields are not exposed. The requested limit is clamped to the configured API maximum.

### `GET /v1/reviews/{domain}`

Returns the current review/classification record for an exact normalized domain, or `404` when no record exists.

### `POST /v1/review`

Queues domains for analysis/review. Body:

```json
{"domains": ["example.com", "api.example.org"]}
```

### `POST /v1/recheck-due?limit=100`

Queues domains whose scheduled recheck is due.

### `POST /v1/cancel`

Cancels currently cancellable classifier jobs.

## Example

```bash
curl -H "Authorization: Bearer $WORMHOLE_TOKEN" \
  http://127.0.0.1:8765/v1/reviews?limit=25
```

Review decisions such as allow, deny, postpone, ignore, and never-ask-again are intentionally not part of this first API contract. They are a separate roadmap item so their persistence and rollback semantics can be finalized before exposing write endpoints to web/PWA clients.
