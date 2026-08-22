# Review Web UI and PWA

The local review server includes a responsive, installable web client at `/app/`. It uses the versioned local API and does not require a separate Node.js process, frontend build, or cloud service.

## Security boundaries

The static app shell (`/app/*`, `/manifest.webmanifest`, and `/sw.js`) is intentionally readable without authentication because browsers cannot attach a Bearer header while initially loading an HTML document, manifest, or service worker. The shell contains no review data, configuration secrets, or API token.

All data endpoints under `/v1/*` remain Bearer-authenticated. The web client asks for that token after loading and stores it in `sessionStorage`, so it is discarded when the browser session ends. API responses continue to use `Cache-Control: no-store`.

The service worker caches only the static shell. It explicitly excludes `/v1/*` and `/health`, so review information and health responses are never placed in the PWA cache.

## Usage

1. Enable the local review server under **Settings → Application → External review trigger** and configure a strong token.
2. Open `http://127.0.0.1:<port>/app/` on the same machine.
3. Enter the configured token.
4. The queue is displayed as responsive cards with local filtering and a domain-details dialog.

The client follows the operating-system light/dark preference and adapts to desktop and phone widths.

## Installation and offline shell

Service workers and PWA installation require a secure browser context. `localhost` and loopback addresses are treated as secure for development/local use. A plain `http://` LAN address generally is not. The later LAN/Tailscale roadmap item will provide the supported remote-access path; HTTPS/Tailscale access should be used for installable remote PWAs.

When offline, the installed app shell can still open, but it deliberately does not retain prior review data. Once Wormhole Observatory is reachable again, Refresh reloads the authenticated queue.

## Current scope

This PWA is the review/read client foundation. Allow, deny, postpone, ignore, and never-ask-again actions are intentionally added in their separate roadmap item so the same decision semantics can be shared by desktop, HTTP API, notifications, and PWA.
