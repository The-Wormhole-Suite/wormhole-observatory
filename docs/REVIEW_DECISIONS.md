# Review decisions

Wormhole Observatory uses one decision service for the desktop Review Queue, authenticated HTTP API, and bundled PWA.

## Semantics

- **Allow**: ensure an exact allow rule exists in the active Pi-hole, remove an opposite exact deny rule when present, then mark the review applied.
- **Deny**: ensure an exact deny rule exists in the active Pi-hole, remove an opposite exact allow rule when present, then mark the review applied.
- **Ignore**: resolve only the current review request. New analysis may request review again.
- **Postpone**: keep the analyzer's `needs_review` state intact but hide the domain until a chosen future timestamp. It automatically becomes visible again after that time.
- **Never ask again**: persistently suppress review prompts and new review tasks for the domain. Analysis/history is retained rather than rewritten.

User review preferences are stored separately in a versioned `review_preferences.sqlite3` database. This separates human workflow choices from model/classification state and permits later preference management without losing evidence or analysis history.

Pi-hole mutations still use the normal audited Pi-hole service, so Allow/Deny changes are visible in the Pi-hole Audit Log and remain eligible for its rollback protections.
