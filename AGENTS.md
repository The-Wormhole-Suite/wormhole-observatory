# Wormhole Observatory — Repository Instructions

Repository: `The-Wormhole-Suite/wormhole-observatory`

Follow the global Codex instructions first.

## Project constraints

- Windows/Python desktop application and part of the Wormhole Suite.
- Preserve suite-wide branding and shared visual language.
- GUI work should emphasize clarity, sharpness, responsive layout, high-DPI support, and polished glass/frosted-glass presentation without sacrificing performance.
- Long-running downloads, scans, model operations, or system tasks must not block the UI thread.
- Keep application state and operations safe if the user navigates away while background work is active.

## Repository workflow

- Inspect GUI framework choice, threading/async model, packaging/release tooling, Windows integration, ROADMAP, CI, and suite assets before substantial changes.

## Pi-hole / DNS-specific constraints

- Wormhole Observatory is the successor to the former Pi-hole Manager; treat Pi-hole/DNS functionality as part of this repository, not as a separate project.
- Treat DNS configuration, blocking rules, authentication, network settings, service restart/reload behavior, upgrades, and remote-host operations as high-impact.
- Prefer validation and reversible changes before applying live configuration.
- Never assume one Pi-hole version/API shape; inspect the currently supported version and current upstream documentation.
- UI/status reporting must distinguish unreachable service, authentication failure, invalid configuration, provider/API errors, and actual Pi-hole errors.
- Inspect the API/client layer, evidence/provider pipeline, configuration persistence, migration behavior, tests, CI, and packaging before substantial Pi-hole-related changes.
