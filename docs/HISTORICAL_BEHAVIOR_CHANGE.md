# Historical behavior-change detection

Wormhole Observatory compares each new primary classification with the latest previous primary
classification for the same domain. The goal is to catch meaningful changes before an automated
Pi-hole action is applied without treating ordinary model noise as a proven real-world change.

## Safety model

The detector is derived from existing classification history; it does not add another database
state table. Secondary benchmark/model-comparison runs (`is_primary = 0`) are ignored.

Signals include:

- a change between allow and deny recommendations;
- a named service identity change;
- crossing the `core/shared` versus `optional/unknown` service-role boundary;
- material privacy, security, or breakage-risk changes; and
- substantial changes to the primary tag or complete tag set.

Each signal contributes to a bounded 0–100 change score. Small score drift is recorded but does not
force review. Decisive policy flips, protected-service-role boundary changes, large security-risk
increases, or a combined score of at least 35 require manual review.

A change signal means **the classifications disagree materially**. It does not by itself prove that
the remote service changed; a provider/model/prompt change can also be the cause. The report keeps
the previous provider/model/profile and a baseline-consistency value so that this distinction stays
visible.

## Automation integration

The existing deterministic pre-policy guard enriches the proposed classification and then applies
the historical-change guard. If the report requires review, the classification is copied with
`needs_review=True` and an explanatory review reason. The automatic policy layer therefore cannot
apply a Pi-hole change until the discrepancy has been reviewed.

Manual tag overrides remain independent. Historical change detection compares stored model
classifications, while manual tags continue to control the effective tag-policy view.

## Domain Intelligence

`database.domain_details()` adds the full report to Domain Intelligence, including the field-level
signals and previous-run provenance. Small changes remain visible there even when they do not block
automation.

No free-text evidence is converted into historical-change facts, and the detector does not claim
causality from DNS/query timing alone.
