from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _required_env(name: str) -> str:
    value = str(os.environ.get(name) or "").strip()
    if not value:
        raise RuntimeError(f"Required environment variable is missing: {name}")
    return value


def build_statement(artifact: Path) -> dict[str, Any]:
    repository = _required_env("GITHUB_REPOSITORY")
    commit_sha = _required_env("GITHUB_SHA")
    git_ref = _required_env("GITHUB_REF")
    workflow_ref = _required_env("RELEASE_WORKFLOW_REF")
    run_id = _required_env("GITHUB_RUN_ID")
    run_attempt = _required_env("GITHUB_RUN_ATTEMPT")
    runner_os = _required_env("RUNNER_OS")
    runner_arch = _required_env("RUNNER_ARCH")

    repository_url = f"https://github.com/{repository}"
    workflow_identity = f"https://github.com/{workflow_ref}"
    invocation_id = f"{repository_url}/actions/runs/{run_id}/attempts/{run_attempt}"

    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": artifact.name,
                "digest": {"sha256": _sha256(artifact)},
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": f"{repository_url}/.github/workflows/release-trust@v1",
                "externalParameters": {
                    "repository": repository_url,
                    "ref": git_ref,
                },
                "internalParameters": {
                    "runnerOS": runner_os,
                    "runnerArch": runner_arch,
                },
                "resolvedDependencies": [
                    {
                        "uri": f"git+{repository_url}@{commit_sha}",
                        "digest": {"gitCommit": commit_sha},
                    }
                ],
            },
            "runDetails": {
                "builder": {"id": workflow_identity},
                "metadata": {"invocationId": invocation_id},
            },
        },
    }


def write_provenance(artifact: Path) -> Path:
    statement = build_statement(artifact)
    output = artifact.with_suffix(artifact.suffix + ".intoto.json")
    output.write_text(
        json.dumps(statement, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return output


def generate(directory: Path) -> list[Path]:
    artifacts = sorted(path for path in directory.glob("*.zip") if path.is_file())
    if not artifacts:
        raise RuntimeError(f"No release ZIP files found in {directory}")
    return [write_provenance(artifact) for artifact in artifacts]
