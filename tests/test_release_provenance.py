from __future__ import annotations

import hashlib
import json
from pathlib import Path

from scripts.generate_release_provenance import generate

import pytest


_ENV = {
    "GITHUB_REPOSITORY": "The-Wormhole-Suite/wormhole-observatory",
    "GITHUB_SHA": "a" * 40,
    "GITHUB_REF": "refs/tags/v1.2.3",
    "RELEASE_WORKFLOW_REF": (
        "The-Wormhole-Suite/wormhole-observatory/.github/workflows/release.yml@refs/tags/v1.2.3"
    ),
    "GITHUB_RUN_ID": "12345",
    "GITHUB_RUN_ATTEMPT": "2",
    "RUNNER_OS": "Linux",
    "RUNNER_ARCH": "X64",
}


def _set_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in _ENV.items():
        monkeypatch.setenv(name, value)


def test_generate_release_provenance_binds_artifact_and_workflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_env(monkeypatch)
    artifact = tmp_path / "Pi-Hole-Manager-linux-x64.zip"
    artifact.write_bytes(b"release-bytes")

    outputs = generate(tmp_path)

    assert len(outputs) == 1
    statement = json.loads(outputs[0].read_text(encoding="utf-8"))
    expected_digest = hashlib.sha256(b"release-bytes").hexdigest()
    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert statement["predicateType"] == "https://slsa.dev/provenance/v1"
    assert statement["subject"] == [
        {
            "name": artifact.name,
            "digest": {"sha256": expected_digest},
        }
    ]
    predicate = statement["predicate"]
    assert predicate["buildDefinition"]["externalParameters"]["ref"] == "refs/tags/v1.2.3"
    assert predicate["runDetails"]["builder"]["id"].endswith(
        "/.github/workflows/release.yml@refs/tags/v1.2.3"
    )
    assert predicate["runDetails"]["metadata"]["invocationId"].endswith(
        "/actions/runs/12345/attempts/2"
    )


def test_generate_release_provenance_requires_zip(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="No release ZIP"):
        generate(tmp_path)
