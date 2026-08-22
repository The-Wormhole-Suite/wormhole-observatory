# Wormhole Observatory Roadmap

This roadmap is the source of truth for the active development branch.

## Priority 1: Stability and correctness

- [x] Pi-hole v6 API compatibility
- [x] resilient connection handling and retries
- [x] cancellation for long-running jobs
- [x] query pagination and safe background loading
- [x] updater hardening and signed provider-registry support
- [x] Windows/Linux packaging and CI coverage

## Priority 2: LLM analysis and evidence pipeline

- [x] quota-aware LLM analysis profiles and provider pools
- [x] provider presets and provider registry
- [x] locally indexed repository evidence sources
- [x] authenticated URLhaus evidence
- [x] evidence licensing enforcement
- [x] certificate-transparency and reputation adapters
- [x] provider-native browsing support
- [x] evidence citations in generated descriptions
- [x] reproducible golden datasets
- [x] protected service compatibility profiles
- [x] manual tag overrides
- [x] service dependency graphs

## Priority 3: Domain intelligence

- [x] historical behavior-change detection
- [x] evidence freshness policies per tag and source

## Priority 4: Pi-hole management

- [x] group assignment for domains and lists
- [x] regex and subscribed-list views
- [x] conflict detection across exact rules, regex rules, groups, and locks
- list audit jobs with configurable batches and rate limits
- multiple Pi-hole instances
- audit log with one-click rollback

## Priority 5: Operator experience

- richer dashboards and operational metrics
- import/export workflows
- more contextual tooltips and guided explanations
- batch review ergonomics
- saved filters and table layouts

## Priority 6: Distribution and integrations

- Home Assistant add-on
- Docker image and documented compose setup
- release channels and update policy
- external trigger / MCP-oriented workflows

## Later / research

- cross-instance policy comparison
- automatic compatibility learning from breakage reports
- optional Wormhole Connector integration
