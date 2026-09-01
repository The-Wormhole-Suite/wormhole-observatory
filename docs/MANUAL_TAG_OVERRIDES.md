# Manual tag overrides

Manual tags are the operator-controlled tag layer for a domain. They override LLM-generated tags
for the active Domain Database view, tag filtering, Review Queue display, and automatic tag-policy
decisions.

## Precedence

When at least one manual tag exists for a domain, the effective tag set is the manual tag set. LLM
tags remain stored unchanged in classification history and model/benchmark output, but they no
longer drive active tag policy until the manual override is removed.

This separation is intentional:

- re-analysis can update model output without silently replacing an operator decision;
- model comparisons still see the original model tags;
- current filtering and automation use one unambiguous effective tag set; and
- removing the manual override immediately exposes the latest classification tags again.

An empty manual tag set means "no override" rather than "override with zero tags".

## Editing

Open **Domain Database**, open a domain's **Details**, and choose **Edit manual tags**. Tags may be
entered comma- or semicolon-separated. Saving a non-empty list activates the override. Saving an
empty value removes it.

The Domain Intelligence payload shows whether a manual override is active and retains the complete
tag provenance list (`manual`, `llm`, and current-classification sources) for auditing.

## Automation

Only the transient classification used for automatic tag-policy resolution receives the manual tag
set. The persisted classification keeps the LLM tags. Existing safety controls still take
precedence: protected compatibility profiles, core/shared service rules, breakage-risk limits,
confidence thresholds, locks, and manual-review requirements can still prevent an automatic action.
