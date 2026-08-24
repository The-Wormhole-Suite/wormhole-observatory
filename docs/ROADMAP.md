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
- [x] reproducible Windows and Linux Onedir releases
- [x] code-signing and release provenance (keyless Sigstore + signed in-toto/SLSA provenance)
- [x] multi-architecture Docker images with persistent volumes
- [x] Home Assistant app repository based on the container image
- [x] release retention and cleanup policy for development builds

## Priority 7: CI efficiency
- [x] avoid duplicate push and pull-request Python CI for feature branches
- [x] cancel superseded workflow runs
- [x] use a fast Python 3.12 pull-request gate and preserve the full supported-version gate on integration branches
- [x] scope Pi-hole compatibility testing to relevant paths and use the current target for ordinary pull requests
- [x] reserve reproducible Windows/Linux PR builds for packaging and release-build changes
- [x] keep native container smoke coverage while limiting QEMU multi-architecture PR builds to image-affecting changes
- [x] reduce scheduled development cleanup frequency while preserving post-publish cleanup
- [x] prevent public fork pull requests from receiving official release signatures or attestations

## Priority 8: Release candidate 0.3.6
- [x] reconcile release-facing naming, credential-store, public-repository, and Home Assistant documentation
- [x] require the full supported Python and Pi-hole compatibility matrices on pull requests targeting `main`
- [x] retire obsolete pre-roadmap integration pull requests
- [ ] promote the completed integration branch to `main` through the protected pull-request flow
- [ ] pass the complete promotion gate, including reproducible Windows/Linux artifacts and container verification
- [ ] publish and verify a public `v0.3.6-rc.1` prerelease from the promoted `main` commit
- [ ] validate desktop updater/download, signed provenance, GitHub attestations, and multi-architecture container behavior against the release candidate
- [ ] publish stable `v0.3.6` only after release-candidate validation
- [ ] verify the `0.3.6` GHCR image resolves for the experimental Home Assistant App and record the post-release baseline
