# Upstream and incorporated projects

Wormhole Observatory is primarily developed as its own application, but it
contains a substantially modified, embedded Pi-hole v6 API client derived from
the upstream `sbarbett/pihole6api` project.

## sbarbett/pihole6api

- Upstream: https://github.com/sbarbett/pihole6api
- Upstream license: MIT
- Upstream copyright: Copyright 2025 Shane Barbetta
- Local package: `pihole6api/`

The local `pihole6api/` package retains the upstream public client structure,
Pi-hole endpoint mappings, and portions of the implementation lineage while
adding substantial Wormhole Observatory-specific changes, including connection
handling, compatibility work, error handling, health checks, TLS behavior, and
tests.

The upstream MIT notice and license text are preserved in
`THIRD_PARTY_NOTICES.md` and are included with distributed binaries.

## Pi-hole

Wormhole Observatory interoperates with the Pi-hole v6 API but does not include
Pi-hole source code. Pi-hole is an external project and is not an upstream code
component of this repository.
