# CI efficiency

Wormhole Observatory uses layered CI so ordinary pull requests get fast feedback without weakening release gates.

## Fast pull-request gate

Normal pull requests run Ruff and the full unit-test suite on Python 3.12 once. Push CI is limited to long-lived integration branches, which avoids running the same Python matrix for both `push` and `pull_request` on feature branches.

Superseded workflow runs are cancelled through workflow-level concurrency groups.

## Compatibility gate

Python 3.11, 3.12 and 3.13 run after changes land on the long-lived integration branches and can also be started manually. This preserves supported-version coverage without repeating the complete matrix for every feature-branch commit.

Pi-hole pull requests use the current pinned Pi-hole/FTL compatibility target. The complete historical compatibility matrix remains available on integration-branch pushes, manual runs and the periodic compatibility run.

## Distribution gates

Reproducible Windows and Linux Onedir builds are mandatory for version tags and for pull requests that change packaging, dependency or release-build inputs. Ordinary application-code pull requests rely on the unit-test gate and are validated by the full distribution gate before an actual release.

Container pull requests always exercise the native headless smoke and persistence test when container/runtime-relevant paths change. QEMU multi-architecture verification is reserved for changes that can affect the container image itself. Development and version-tag publishing perform the multi-architecture build directly instead of building the same platforms once for verification and a second time for publishing.

Public fork pull requests never receive Wormhole Sigstore signatures or GitHub artifact attestations. Those trust artifacts are restricted to trusted repository events and same-repository pull requests.

## Scheduled maintenance

Development cleanup runs weekly in addition to cleanup after development publishing. The 30-day retention policy does not require a daily runner. The historical Pi-hole compatibility matrix runs monthly rather than weekly and remains available on demand.

## Public repository runners

The project uses only standard GitHub-hosted runners. GitHub currently documents standard GitHub-hosted runners as free and unlimited for public repositories. The efficiency rules above are retained to reduce queue time, duplicated work and noisy CI history even when runner minutes are not billed.
