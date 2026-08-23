# Development build retention

Development builds are intentionally short-lived. Stable releases, stable tags, and stable container versions are never selected by this policy.

## Policy

- GitHub Actions artifacts from `dev-release.yml` are retained for 14 days.
- Development prereleases named `dev-*` are eligible for deletion only when they are older than 30 days and are not among the 10 newest development prereleases.
- GHCR container versions are eligible only when all of their remaining tags are `sha-*`, they are older than 30 days, and they are not among the 10 newest such versions.
- Untagged GHCR versions are deliberately not deleted automatically because their origin is ambiguous.
- Versions carrying `dev`, semantic-version, or `latest` tags are never selected.

Cleanup runs after the corresponding development publication and once per day from `.github/workflows/dev-cleanup.yml`. The selector lives in `pihole_manager.dev_retention` and is covered by unit tests.

The cleanup script also supports `--dry-run`, `--releases-only`, and `--packages-only` for maintenance and diagnostics.
