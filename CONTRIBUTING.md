# Contributing to Wormhole Observatory

Wormhole Observatory is in pre-1.0 development. Contributions should preserve the project's conservative Pi-hole automation model: evidence and LLM output may inform a decision, but policy and safety checks remain deterministic and explicit.

## Before opening a change

- Search existing issues and pull requests for related work.
- Keep security vulnerabilities out of public issues and pull requests; follow [SECURITY.md](SECURITY.md).
- Keep changes focused. Large unrelated refactors make review and rollback harder.
- Do not commit credentials, API tokens, private domain lists, local databases, logs, or generated user configuration.

## Development environment

Use Python 3.11 or newer.

```bash
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
python -m pip install -e ".[dev]"
ruff check .
pytest
```

On Windows, activate the environment with `.venv\Scripts\activate`.

The normal pull-request gate uses Python 3.12 for fast feedback. Supported-version checks, Pi-hole compatibility tests, release reproducibility, container tests, dependency review, and CodeQL run according to the changed paths and release context.

## Pull requests

For ordinary external contributions, open the pull request against `main` unless a maintainer or an existing issue specifies another target branch. Maintainers may retarget active development work to the current integration branch.

A pull request should:

- explain the user-visible or architectural reason for the change;
- include tests for behavior that can regress;
- update documentation when configuration, API, security, packaging, or operational behavior changes;
- avoid weakening Simulation mode, protected-service checks, credential handling, authentication, provenance verification, or rollback safeguards without an explicit design rationale;
- keep new dependencies to the minimum necessary and allow the dependency-review gate to evaluate them.

## Code style

Python code is formatted and linted according to `pyproject.toml`. Ruff uses a 100-character line limit and Python 3.11 as its target language level.

Prefer small modules with explicit inputs and deterministic policy logic. Network adapters should use bounded timeouts, existing retry/rate-limit helpers where applicable, and structured errors rather than silently converting failures into positive evidence.

## Tests

Run at least:

```bash
ruff check .
pytest
```

Changes to Pi-hole integration should preserve `tests/integration/test_pihole_v6.py`. Changes to packaging, the build lock, release scripts, container files, or Home Assistant metadata should be expected to trigger the corresponding reproducibility or container gates in GitHub Actions.

Do not bypass a failing security or release gate merely to make a pull request green. Fix the cause or document why a maintainer must deliberately change the policy.

## Dependencies

Runtime dependencies are declared in `pyproject.toml`. Reproducible Onedir builds additionally pin their complete build/runtime environment in `requirements-build.lock`.

Dependency changes must keep these two views consistent where applicable. Known vulnerable versions must not be introduced. Pull requests changing dependency manifests are checked by GitHub Dependency Review.

## Release-related changes

Release artifacts are reproducible and use keyless Sigstore plus in-toto/SLSA provenance. Do not replace this with long-lived repository signing keys. See [docs/RELEASE_TRUST.md](docs/RELEASE_TRUST.md), [docs/REPRODUCIBLE_RELEASES.md](docs/REPRODUCIBLE_RELEASES.md), and [docs/PUBLIC_RELEASE_CHECKLIST.md](docs/PUBLIC_RELEASE_CHECKLIST.md).
