from __future__ import annotations

from pathlib import Path

import pytest

from scripts import generate_binary_license_bundle as licenses


class _FakeMetadata(dict):
    def get_all(self, key: str):
        if key == "Project-URL":
            return ["Source, https://example.invalid/package"]
        return []


class _FakeDistribution:
    version = "1.2.3"
    files = ()
    metadata = _FakeMetadata(
        {
            "Name": "Example",
            "License-Expression": "MIT",
        }
    )


def test_active_lock_entries_are_deduplicated_and_marker_aware(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = tmp_path / "requirements.lock"
    lock.write_text(
        "Example==1.2.3\n"
        "Example==1.2.3\n"
        "Skipped==9.9.9; python_version < '2'\n",
        encoding="utf-8",
    )
    calls: list[str] = []

    def fake_distribution(name: str):
        calls.append(name)
        return _FakeDistribution()

    monkeypatch.setattr(licenses.metadata, "distribution", fake_distribution)
    output = tmp_path / "THIRD_PARTY_LICENSES.txt"
    licenses.generate_bundle(lock, output)

    text = output.read_text(encoding="utf-8")
    assert calls == ["Example"]
    assert "Example 1.2.3" in text
    assert "License-Expression: MIT" in text
    assert "Skipped" not in text


def test_missing_license_metadata_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = tmp_path / "requirements.lock"
    lock.write_text("Example==1.2.3\n", encoding="utf-8")
    distribution = _FakeDistribution()
    distribution.metadata = _FakeMetadata({"Name": "Example"})
    monkeypatch.setattr(licenses.metadata, "distribution", lambda name: distribution)

    with pytest.raises(RuntimeError, match="No license metadata"):
        licenses.generate_bundle(lock, tmp_path / "bundle.txt")
