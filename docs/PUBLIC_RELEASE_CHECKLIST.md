# Public release checklist

This checklist defines the minimum gate before creating the first public
`v0.3.6` tag. Exact-tree CI/security evidence is recorded on release issue #46
rather than by making a checkbox-only commit after the tested release commit.

## Repository and legal readiness

- [x] Project license selected: GNU AGPL v3.0 only (`AGPL-3.0-only`).
- [x] Canonical `LICENSE`, `NOTICE`, `TRADEMARKS.md`, and `UPSTREAMS.md` are present.
- [x] Embedded `sbarbett/pihole6api` MIT attribution is preserved in `THIRD_PARTY_NOTICES.md`.
- [x] Desktop packaging requires the project legal files and a generated Python `THIRD_PARTY_LICENSES.txt` inside the Onedir artifact.
- [x] `SECURITY.md` documents private vulnerability reporting guidance.
- [x] Pull requests that change dependencies run GitHub Dependency Review.
- [x] CodeQL scans Python and GitHub Actions workflows.
- [x] Public README and contribution guidance describe the current project and deployment modes.
- [x] First-release notes are curated in `docs/releases/v0.3.6.md`; the release workflow does not use generic generated notes.

## Security baseline

- [x] The current direct dependency baseline has no known vulnerability identified by the release-hardening audit.
- [x] Secret Scanning is enabled and has no unresolved alert as of the pre-finalization audit.
- [ ] Push Protection is visually confirmed enabled in GitHub repository settings.
- [ ] CodeQL has no unresolved release-blocking alert on the final release commit.
- [ ] Dependabot, Dependency Review, and normal CI are green for the final release commit.
- [ ] No credential, token, private database, user configuration, or sensitive log is included in release inputs or artifacts.

## Compatibility and reproducibility

- [ ] Python 3.11, 3.12, and 3.13 supported-version tests are green on the final release commit.
- [ ] Pi-hole FTL 6.3, 6.5, and 6.6 compatibility tests are green on the final release commit.
- [ ] Windows Onedir is built twice and verified byte-for-byte reproducible.
- [ ] Linux Onedir is built twice and verified byte-for-byte reproducible.
- [ ] Both desktop ZIPs pass the mandatory legal-file/third-party-notice gate.
- [ ] Headless container smoke, persistent-volume behavior, and Home Assistant bootstrap are green.
- [ ] `linux/amd64` and `linux/arm64` container builds succeed before tagging.

## Release trust

- [ ] Release ZIPs have SHA-256 digests and portable in-toto/SLSA provenance.
- [ ] Release ZIPs and provenance are keylessly signed and self-verified with Sigstore.
- [ ] GitHub Artifact Attestations succeed for the public repository.
- [ ] Curated release notes accurately describe security-relevant changes, compatibility, licensing, and known limitations.

## Publication

- [ ] The final release commit is exactly the commit validated by the release-candidate gate recorded in #46.
- [ ] The `v0.3.6` tag is created only after all blocking items above are complete.
- [ ] Tag-triggered GHCR publication succeeds for the matching stable semver/latest tags with SBOM and provenance.
- [ ] GitHub Release assets, GHCR image tags, and Home Assistant metadata refer to application version `0.3.6`.
- [ ] Post-publication install/update smoke checks confirm the published assets rather than local build outputs.

The stable tag must not be created while any blocking item remains unresolved. Do
not modify the fully gated release commit merely to mark external-evidence
checkboxes; record those run IDs and results on #46 instead.
