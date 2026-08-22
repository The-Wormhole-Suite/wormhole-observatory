# Roadmap

## Priority 1: Stability and migration

- [x] versioned SQLite migrations with rollback tests
- [x] operating-system credential stores
- [x] integration tests against multiple Pi-hole v6 minor versions
- [x] connection health state and clearer offline behavior
- [x] cancellable long-running evidence and LLM jobs
- [x] optional authenticated external trigger adapter for scheduled or MCP-driven review jobs

## Priority 2: Evidence quality

- [x] source-quality scoring and contradiction detection
- [x] locally indexed additional list repositories with provenance
- [x] URLhaus integration after its authenticated feed contract is implemented and tested
- [x] licensing review before enabling non-commercial datasets in distributed builds
- [x] certificate-transparency and additional reputation adapters
- [x] provider-native browsing support for LLMs that can cite primary sources
- [x] evidence citations in every generated description
- [x] golden datasets for source, prompt, and model comparison

## Priority 3: Domain intelligence

- [x] protected services and compatibility profiles
- [x] manual tags that override LLM tags
- [x] service dependency graphs
- [x] historical behavior-change detection
- [x] evidence freshness policies per tag and source

## Priority 4: Pi-hole management

- [x] group assignment for domains and lists
- [x] regex and subscribed-list views
- [x] conflict detection across exact rules, regex rules, groups, and locks
- [x] list audit jobs with configurable batches and rate limits
- [x] multiple Pi-hole instances
- [x] audit log and one-click rollback

## Priority 5: Review clients

- [x] authenticated local HTTP API
- [x] responsive web UI and PWA
- [x] ntfy and UnifiedPush notifications with deep links
- [x] allow, deny, postpone, ignore, and never-ask-again decisions
- [x] LAN and Tailscale access without a required public cloud

## Priority 6: Distribution

- signed and reproducible Windows and Linux Onedir releases
- code-signing and release provenance
- multi-architecture Docker images with persistent volumes
- Home Assistant app repository based on the container image
- release retention and cleanup policy for development builds
