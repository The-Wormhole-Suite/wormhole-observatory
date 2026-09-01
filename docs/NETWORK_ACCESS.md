# LAN and Tailscale review access

Wormhole Observatory can expose its authenticated review API and bundled PWA without any required public cloud. Network access is opt-in and constrained independently from the bearer-token authentication layer.

## Access modes

Configure the server under **Settings → Application → External review trigger → Client access**.

| Mode | Accepted clients |
| --- | --- |
| Local only | Loopback clients on the Observatory host |
| LAN only | Loopback plus private RFC1918 IPv4, IPv6 ULA, and link-local clients |
| Tailscale only | Loopback plus Tailscale IPv4/IPv6 addresses |
| LAN + Tailscale | Both LAN and Tailscale clients |
| Any network (advanced) | Any source address that can reach the bind address |

Source-network filtering happens before API authentication. API endpoints still require the configured bearer token in every mode.

The access policy is stored separately in `review_access.json`. Older installations that explicitly enabled the legacy `allow_remote` setting are treated as **Any network** until the access mode is saved explicitly, preserving connectivity while making the scope visible in the UI.

## Direct LAN access

For LAN clients to connect directly:

1. Enable the authenticated HTTP server and generate a strong bearer token.
2. Choose **LAN only** or **LAN + Tailscale**.
3. Bind to `0.0.0.0`, `::`, or the specific LAN interface address rather than `127.0.0.1`.
4. Restrict the operating-system firewall to the intended local network when possible.
5. Open `http://<observatory-lan-address>:8765/app/` and enter the bearer token in the PWA.

Plain HTTP on another device may not qualify as a browser secure context, so installation and service-worker features can be limited even though the review UI itself works. Use a local HTTPS reverse proxy when an installable LAN PWA is required.

## Recommended Tailscale setup

The preferred Tailscale deployment keeps Observatory itself loopback-only and lets Tailscale provide the private HTTPS endpoint:

1. Keep **Bind address** at `127.0.0.1`.
2. Keep **Client access** at **Local only**.
3. Enable the authenticated server on port `8765`.
4. On the same machine, run:

```text
tailscale serve 8765
```

5. Open the HTTPS URL shown by Tailscale and append `/app/` when necessary.

In this setup, Tailscale Serve proxies to the local Observatory listener, provides a tailnet-only HTTPS origin, and leaves bearer-token authentication enabled inside Observatory. Tailnet access policies can therefore be used in addition to the Observatory token.

Use **Tailscale Serve**, not **Tailscale Funnel**, for this private workflow. Funnel is intended to expose a service publicly on the internet.

## Direct Tailscale-address binding

A second option is to bind Observatory to `0.0.0.0`, `::`, or the host's Tailscale address and select **Tailscale only**. Observatory then rejects non-loopback clients whose source address is outside Tailscale's address ranges before bearer authentication is evaluated.

This is useful for API clients, but the Tailscale Serve approach is preferable for the PWA because it supplies HTTPS without requiring Observatory to manage TLS certificates.

## Security notes

- Network scope is an additional restriction, not a replacement for the bearer token.
- Do not put the bearer token in URLs, bookmarks, notification links, or query strings.
- Prefer the narrowest access mode that satisfies the deployment.
- `Any network (advanced)` should normally be paired with an external firewall or trusted reverse proxy.
- The PWA shell contains no embedded token or review data; `/v1/*` data remains authenticated and is served with `Cache-Control: no-store`.
