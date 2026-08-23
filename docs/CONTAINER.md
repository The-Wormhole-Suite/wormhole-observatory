# Container deployment

Wormhole Observatory ships a headless container for the authenticated review API, PWA and
background scanner/classifier services. The Tk desktop UI is intentionally not started in the
container.

## Architectures and registry

The CI workflow verifies and publishes a single OCI image index for:

- `linux/amd64`
- `linux/arm64`

Release and development images are published to
`ghcr.io/the-wormhole-suite/wormhole-observatory`. Because the repository is private, pulling the
package can require GitHub Container Registry authentication depending on package visibility and
repository access.

Published images include BuildKit provenance (`mode=max`) and an SBOM attached to the image index.
The runtime image uses the multi-platform Python 3.11.16 slim-bookworm image pinned by index digest.

## Persistent data

`PIHOLE_MANAGER_HOME` is fixed to `/data` in the image and `/data` is declared as the persistent
volume. This keeps the existing application storage model intact. The volume contains, among other
files:

- `options.json`
- `pihole_manager.sqlite3`
- Pi-hole audit data
- review-network access settings
- logs and other application state that already use `app_directory()`

Back up the volume before destructive configuration or database changes. Updating or replacing the
container does not require copying state into the image.

## Required authentication

The headless service refuses to start without an API token. Supply it with
`WORMHOLE_API_TOKEN`. The environment value is used at runtime and is not written back into
`options.json` by the headless launcher.

Example:

```sh
export WORMHOLE_API_TOKEN='replace-with-a-long-random-token'
docker compose up -d
```

The PWA is available at `http://HOST:8765/app/`. API endpoints, including `/health`, require the
Bearer token. The PWA keeps the token in browser session storage as documented in the review-client
documentation.

## Runtime environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `WORMHOLE_API_TOKEN` | none | Required Bearer token; existing stored trigger token is a fallback |
| `WORMHOLE_BIND_HOST` | `0.0.0.0` | Container bind address |
| `WORMHOLE_PORT` | `8765` | HTTP/API port |
| `WORMHOLE_ACCESS_MODE` | `lan_tailscale` | `local`, `lan`, `tailscale`, `lan_tailscale`, or `any` |
| `WORMHOLE_MAX_DOMAINS` | existing setting | Maximum domains accepted by one review request |

The default `lan_tailscale` mode keeps the existing network-scope guard in front of the authenticated
API. Set `any` only when the surrounding Docker host, firewall or reverse proxy intentionally
provides the network boundary.

## Existing configuration

On first start the application creates a default `/data/options.json`. Pi-hole, provider, scanning,
LLM and other existing settings remain in this normal configuration file. A deployment can seed the
volume with an existing compatible configuration before starting the container.

The container starts the same scanner, list-audit worker and realtime/background classifiers used by
the desktop application. Disabled features remain idle because those workers reload their normal
settings from `/data/options.json`.

## Updates

Container deployments are updated by pulling/replacing the image. The desktop self-updater is not
part of the headless runtime lifecycle. Persistent state remains in `/data`.
