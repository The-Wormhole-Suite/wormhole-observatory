# Roadmap

## Priority 1: Stability and migration

- [x] versioned SQLite migrations with rollback tests
- [x] operating-system credential stores
- [x] integration tests against multiple Pi-hole v6 minor versions
- [x] connection health state and clearer offline behavior
- cancellable long-running evidence and LLM jobs
- optional authenticated external trigger adapter for scheduled or MCP-driven review jobs

## Priority 2: Evidence quality

- source-quality scoring and contradiction detection
- locally indexed additional list repositories with provenance
- URLhaus integration after its authenticated feed contract is implemented and tested
- licensing review before enabling non-commercial datasets in distributed builds
- certificate-transparency and additional reputation adapters
- provider-native browsing support for LLMs that can cite primary sources
- evidence citations in every generated description
- golden datasets for source, prompt, and model comparison

## Priority 3: Domain intelligence

- protected services and compatibility profiles
- manual tags that override LLM tags
- service dependency graphs
- historical behavior-change detection
- evidence freshness policies per tag and source

## Priority 4: Pi-hole management

- group assignment for domains and lists
- regex and subscribed-list views
- conflict detection across exact rules, regex rules, groups, and locks
- list audit jobs with configurable batches and rate limits
- multiple Pi-hole instances
- audit log and one-click rollback

## Priority 5: Review clients

- authenticated local HTTP API
- responsive web UI and PWA
- ntfy and UnifiedPush notifications with deep links
- allow, deny, postpone, ignore, and never-ask-again decisions
- LAN and Tailscale access without a required public cloud

## Priority 6: Distribution

- signed and reproducible Windows and Linux Onedir releases
- code-signing and release provenance
- multi-architecture Docker images with persistent volumes
- Home Assistant app repository based on the container image
- release retention and cleanup policy for development builds
