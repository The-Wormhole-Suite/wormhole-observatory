# Home Assistant App: Wormhole Observatory

## Purpose

This App runs the headless Wormhole Observatory service under Home Assistant Supervisor. It uses the
same pre-built multi-architecture container published for normal Docker deployments; Home Assistant
does not build a second copy of Wormhole.

## Before installation

The App version and OCI image tag must match. Version `0.3.6` therefore expects:

`ghcr.io/the-wormhole-suite/wormhole-observatory:0.3.6`

The repository currently has no historical Git tags. The image will be produced by the existing
container release workflow when `v0.3.6` is published. If the GHCR package is private, the Home
Assistant host must have registry credentials that can pull it. Public package visibility removes
that requirement.

## Configuration

### `api_token`

Required Bearer token for the Wormhole review API and PWA. Use a long random value. Home Assistant
stores App options in `/data/options.json`; the container bootstrap reads this root-owned file before
dropping privileges and never copies the token into Wormhole's own `options.json`.

### `access_mode`

Controls the existing Wormhole network-source guard:

- `local`: loopback only
- `lan`: private LAN addresses
- `tailscale`: Tailscale addresses
- `lan_tailscale`: LAN and Tailscale; default
- `any`: rely entirely on the Home Assistant host/firewall network boundary

Authentication is required regardless of the selected network mode.

### `max_domains`

Maximum number of domains accepted in one review request. Valid range: 1 to 10000. Default: 500.

## Web interface

After starting the App, use **Open Web UI**. Home Assistant maps container port 8765 and substitutes
the effective host port in the configured URL. The PWA itself still requires the configured Bearer
token.

Ingress is intentionally disabled in the first App version. Wormhole's PWA currently uses its own
authentication and root-relative routes, while Home Assistant Ingress uses a path prefix and its own
authenticated proxy. Keeping these modes separate avoids weakening either security model.

## Persistence and backups

Home Assistant owns `/data/options.json`. Wormhole stores its database, normal configuration, audit
history and logs below `/data/wormhole`, preventing schema collisions with Supervisor options.

Backups use `cold` mode so Supervisor stops Wormhole before copying its SQLite-backed persistent
state. The App starts again after the backup completes.

## Runtime privilege model

Supervisor App options are mode 0600 and root-owned. The image therefore starts a minimal bootstrap
as root, reads only the Supervisor options, prepares `/data/wormhole`, clears supplementary groups,
and permanently drops to UID/GID 10001 before executing the Wormhole service. The long-running
Wormhole process is not root.

The App does not request host networking, Docker access, privileged capabilities or elevated
Supervisor API roles.
