# Roadmap

## Priority 1: Stability and migration

- introduce explicit, versioned SQLite migrations instead of relying only on idempotent schema extensions
- store credentials through Windows Credential Manager, Secret Service, and macOS Keychain
- test API behavior against multiple Pi-hole v6 minor releases
- provide a controlled dry-run report before automatic actions can be enabled
- add cancellation, timeout, and progress reporting for long research and LLM jobs
- synchronize the validated v0.2 backend and GUI implementation completely with the GitHub repository

## Priority 2: Domain intelligence

- Protected Services and Compatibility Profiles
- manually editable tags that override LLM-generated tags
- targeted prioritization of known blocklist and allowlist repositories
- evidence and link views instead of a raw JSON-only details dialog
- dedicated GitHub Issues, Discussions, and repository-documentation research providers
- controlled retrieval of selected forum and documentation pages
- optional DNS, CNAME, and certificate-transparency providers
- source-quality weighting and contradictory-evidence detection
- citations connecting every synthesized claim to stored evidence
- a golden dataset for prompt, provider, and model comparisons

## Priority 3: Pi-hole management

- editable group assignment for domains and lists
- separate views for regex rules and subscribed lists
- conflict detection across allow, deny, regex, groups, and locks
- support for multiple Pi-hole instances
- audit log and one-click rollback

## Priority 4: Review clients

- authenticated local HTTP API with roles
- responsive web interface or PWA as the first smartphone client
- ntfy and UnifiedPush notifications with deep links
- review actions: allow, deny, remind later, ignore, and never ask again
- access through LAN or Tailscale without requiring a public cloud service

## Priority 5: Distribution

- Windows builds with PyInstaller
- signed releases and reproducible builds
- automated release artifacts through GitHub Actions
