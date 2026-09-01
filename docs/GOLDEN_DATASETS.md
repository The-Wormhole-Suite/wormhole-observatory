# Golden datasets

Wormhole Observatory uses versioned, frozen evidence cases to compare evidence sources, prompt revisions, and LLM/model variants without allowing live network changes to move the reference point between runs.

## Why the dataset is synthetic

The bundled `golden_dataset_v1.json` uses reserved `.test` domains and synthetic evidence. This avoids redistributing third-party provider data and keeps the reference cases stable. Real-world cases can be added later only when their provenance, redistribution terms, and long-term stability are suitable for a committed test dataset.

A golden score is a regression signal, not an assertion that every acceptable model must produce identical prose. The evaluator intentionally checks semantic constraints instead of exact text.

## What is scored

Each case contains a frozen evidence dossier plus two groups of expectations:

- classification expectations: allowed policies, required and forbidden tags, acceptable service roles, review requirements, and risk ranges;
- source expectations: required providers, evidence kinds and verdicts, forbidden verdicts, and a minimum number of decision-relevant findings.

The evaluator returns the number of passed checks, total checks, a normalized score, and actionable failure messages.

## Source comparison

Run `evaluate_sources(case, dossier)` against the same golden case after changing a source adapter, source-quality policy, or dossier construction. A regression such as a missing threat verdict or missing decision-relevant finding is reported independently of any LLM output.

## Prompt and model comparison

Use the exact same frozen `case.dossier` for every variant. `compare_variants()` accepts arbitrary variant labels, so labels should carry the dimensions under test, for example:

```python
results = compare_variants(
    case,
    {
        "prompt-v3 / gpt-model-a": result_a,
        "prompt-v4 / gpt-model-a": result_b,
        "prompt-v4 / local-model-b": result_c,
    },
)
```

This makes prompt-only, model-only, and combined changes directly comparable without changing the evidence input.

## Existing benchmark integration

The existing model benchmark output returned by `benchmark_run_get()` can be scored directly:

```python
from pihole_manager.database import benchmark_run_get
from pihole_manager.golden_dataset import evaluate_benchmark_run, load_golden_dataset

run = benchmark_run_get(run_id)
dataset = load_golden_dataset()
results = evaluate_benchmark_run(dataset, run)
```

`evaluate_benchmark_run()` ignores failed provider results and ranks completed provider/model variants by the combined classification and source score. The benchmark must use the golden case's frozen dossier if the goal is a reproducible model comparison.

## Versioning rules

The top-level `schema_version` defines the parser contract. Incompatible structural changes require a new schema version. Changes to the meaning or expected outcome of a reference case should create a new dataset ID or a reviewed dataset revision rather than silently changing historical expectations.

For stable comparisons:

1. never refresh the committed dossier from live sources during a benchmark;
2. change one dimension at a time when isolating source, prompt, or model effects;
3. retain the provider, model, prompt/profile identifier, and dataset ID with exported benchmark results;
4. review golden-case changes like production policy changes, because weakening an expectation can hide a regression.
