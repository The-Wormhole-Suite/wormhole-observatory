# AI session state

Updated: 2026-09-25

## Canonical repository

- Repository: `The-Wormhole-Suite/wormhole-observatory`
- Canonical branch: `main`
- Priority focus: Priority 9 — shared-core dual frontend and full server administration
- Tracking issue: #50

## Completed in this session

### Scheduled development cleanup repair

- Reproduced the recurring scheduled failure: `scripts/cleanup_dev_builds.py` could not import `pihole_manager` when executed as a script.
- PR #57 changes the workflow invocation to `python -m scripts.cleanup_dev_builds`.
- Manual workflow dispatch succeeded on the branch.
- Python CI and CodeQL checks succeeded.
- PR #57 merged to `main` as `8ef16bc7755fcce7d3ceafab12f5ce052c5bd823`.

### Priority 9A capability inventory

- PR #58 adds `docs/DESKTOP_CAPABILITY_INVENTORY.md`.
- Inventory covers every top-level Tk surface and Settings page.
- Capabilities are classified as `shared-core`, `presentation-only`, or `platform-specific`.
- The inventory records current Tk coupling to database, Pi-hole, worker, config, updater, notification and research modules.
- Existing application-service coverage is explicitly recorded for review decisions and managed regex/subscription rules.

## Next implementation order

1. Exact-domain mutation + review queue command service.
2. Pi-hole/history/domain read models.
3. Canonical settings service for Pi-hole instances, automation, providers, pools, prompts, evidence and notifications.
4. Job-control service for analysis, evidence, audits and workers.
5. Audit/rollback and group-management service boundaries.

## Priority 9A invariants

- One application core, two first-class frontends.
- Tk calls shared services in-process; Web reaches the same capabilities through HTTP adapters.
- Do not force local Tk through HTTP.
- No business policy, validation, persistence, Pi-hole mutation, audit or job orchestration may be duplicated in frontend code.
- Desktop-only rendering, native file choosers, local notifications and desktop self-update may remain platform-specific when documented and tested.

## Open release hardening outside Priority 9

- #43: confirm Push Protection.
- #46: rerun exact-tree release gate and create/verify first public `v0.3.6` only after Push Protection is confirmed.
- #56: provider registry review required.
