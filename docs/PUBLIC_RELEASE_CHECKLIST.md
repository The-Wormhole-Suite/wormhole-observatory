# Public release checklist

This checklist defines the minimum gate before creating the first public `v0.3.6` tag and should remain applicable to later stable releases unless superseded by a documented release process.

## Repository readiness

- [ ] An explicit repository license has been selected and committed as `LICENSE`.
- [x] `SECURITY.md` documents private vulnerability reporting guidance.
- [x] Pull requests that change dependencies run GitHub Dependency Review.
- [x] CodeQL scans Python and GitHub Actions workflows.
- [x] Public README and contribution guidance describe the current project and deployment modes.

## Security baseline

- [x] The current direct dependency baseline has no known vulnerability identified by the release-hardening audit.
- [ ] CodeQL has no unresolved release-blocking alert on the release candidate.
- [ ] Dependency Review and normal CI are green for the release candidate.
- [ ] No credential, token, private database, user configuration, or sensitive log is included in release inputs or artifacts.

## Compatibility and reproducibility

- [ ] Python 3.11, 3.12, and 3.13 supported-version tests are green.
- [ ] Pi-hole FTL 6.3, 6.5, and 6.6 compatibility tests are green.
- [ ] Windows Onedir is built twice and verified byte-for-byte reproducible.
- [ ] Linux Onedir is built twice and verified byte-for-byte reproducible.
- [ ] Headless container smoke, persistent-volume behavior, and Home Assistant bootstrap are green.
- [ ] `linux/amd64` and `linux/arm64` container publication succeeds.

## Release trust

- [ ] Release ZIPs have SHA-256 digests and portable in-toto/SLSA provenance.
- [ ] Release ZIPs and provenance are keylessly signed and self-verified with Sigstore.
- [ ] GitHub Artifact Attestations succeed for the public repository.
- [ ] Release notes accurately describe security-relevant changes, compatibility, and known limitations.

## Publication

- [ ] The final release commit is the commit tested by the release-candidate gate.
- [ ] The `v0.3.6` tag is created only after all blocking items above are complete.
- [ ] GitHub Release assets, GHCR image tags, and Home Assistant metadata refer to the same application version.
- [ ] Post-publication install/update smoke checks confirm the published assets rather than local build outputs.

The stable tag must not be created while any blocking item remains unresolved. Development and prerelease artifacts may continue to be used for testing.
