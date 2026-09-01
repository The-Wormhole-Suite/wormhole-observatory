# Roadmap

## Priority 0: Framework audit recovery gate
- [ ] restore all `PLACEHOLDER_RESTORE_FROM_REPO_REQUIRED` casualties on the integration branch, including release/container workflows and affected Pi-hole UI/service/test files, from their last verified implementations
- [ ] fix remaining Ruff violations in the restored connection and multi-instance code, then require green Python CI before any further feature work
- [ ] reconcile `codex/roadmap-audit-20260819` with current `main`, preserving the completed roadmap implementation while incorporating schema v12 transactional migrations
- [ ] verify every previously completed roadmap item still has implementation + test/release evidence after reconciliation; do not trust checkbox state alone
- [ ] rerun the full security and release-candidate gates on the reconciled canonical branch: Python CI, Pi-hole v6 integration, CodeQL, dependency review, reproducible desktop builds, container amd64/arm64 verification, signing/provenance checks
- [ ] establish one canonical integration branch and retire/merge stranded long-lived implementation branches so completed work cannot diverge silently from `main`
- [ ] add a lightweight repository-integrity CI guard for sentinel placeholders and unexpectedly tiny critical workflow/source files
- [ ] keep the explicit repository license and first public v0.3.6 release-candidate gate as release blockers

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

## Priority 8: Public release hardening
- [x] remediate known vulnerabilities in the current direct dependency baseline
- [ ] add an explicit repository license after the project license is selected
- [x] add a security policy with private vulnerability reporting guidance
- [x] enforce dependency review for pull requests that change dependencies
- [x] add CodeQL scanning for Python and GitHub Actions workflows
- [x] audit public README, contribution guidance, and release documentation
- [ ] run the complete release-candidate gate before creating the first public v0.3.6 tag
