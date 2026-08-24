# Release candidate process

Wormhole Observatory 0.3.6 is the first release prepared from the completed roadmap on the public repository. The application package and Home Assistant App metadata already use version `0.3.6`, but no public Git tag or GitHub Release existed at the start of this release-readiness phase.

## Promotion policy

Development work is integrated on `codex/roadmap-audit-20260819`. Promotion to `main` happens only through a protected pull request. Pull requests targeting `main` deliberately restore the expensive compatibility gates that ordinary feature pull requests avoid:

- Python 3.11, 3.12, and 3.13;
- Pi-hole FTL 6.3, 6.5, and 6.6 integration contracts;
- reproducible Windows and Linux Onedir builds when the release workflow is selected;
- native container smoke, persistence, and Home Assistant bootstrap checks;
- multi-architecture container verification when image-affecting inputs changed.

A failed gate blocks promotion. Superseded runs remain cancellable.

## Candidate before stable

The repository and Home Assistant App are still explicitly marked alpha/experimental. The first public release from the promoted commit therefore uses the prerelease tag `v0.3.6-rc.1`. Stable `v0.3.6` is created only after the candidate has passed the runtime checks below. This prevents the desktop stable update channel from receiving an unvalidated first public build.

The Home Assistant App metadata intentionally remains at `0.3.6`; it expects the stable GHCR tag `0.3.6`. The App is therefore not considered release-complete until that stable image exists.

## Release-candidate verification

After `v0.3.6-rc.1` is published, verify all of the following before creating `v0.3.6`:

1. Windows and Linux ZIP assets are present and their reproducibility jobs passed.
2. SHA-256 metadata, portable in-toto/SLSA provenance, Sigstore signatures, and GitHub artifact attestations are present and verify.
3. A clean Windows Onedir launch reaches the application UI without migration errors.
4. A clean Linux Onedir launch reaches the application UI without migration errors.
5. The desktop updater can discover the prerelease on the prerelease channel without exposing it to the stable channel.
6. The GHCR release-candidate image contains both `linux/amd64` and `linux/arm64`.
7. The container starts with a fresh volume, survives recreation, and preserves `/data/wormhole`.
8. The Home Assistant bootstrap correctly consumes Supervisor-style `/data/options.json` while the long-running process drops to UID/GID 10001.
9. No release-facing documentation still describes completed features as future or unavailable.

## Stable release verification

After the candidate passes, create `v0.3.6` from the same accepted source state. Verify the stable GitHub Release, `ghcr.io/the-wormhole-suite/wormhole-observatory:0.3.6`, Home Assistant App image resolution, and the desktop stable updater. Record any follow-up work as a new roadmap priority rather than changing the accepted release silently.
