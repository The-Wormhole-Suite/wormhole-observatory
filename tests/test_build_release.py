from __future__ import annotations

import hashlib
import os
import zipfile
from pathlib import Path

import pytest

import build_release
from scripts.verify_reproducible_release import verify


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_deterministic_zip_ignores_source_mtimes(tmp_path: Path) -> None:
    source = tmp_path / "Pi-Hole-Manager"
    nested = source / "data"
    nested.mkdir(parents=True)
    executable = source / "Pi-Hole-Manager"
    executable.write_bytes(b"binary")
    executable.chmod(0o755)
    payload = nested / "payload.txt"
    payload.write_text("payload\n", encoding="utf-8")

    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    epoch = 1_700_000_000
    build_release._write_deterministic_zip(source, first, epoch=epoch)

    os.utime(executable, (epoch + 5000, epoch + 5000))
    os.utime(payload, (epoch + 9000, epoch + 9000))
    build_release._write_deterministic_zip(source, second, epoch=epoch)

    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        names = archive.namelist()
        assert names == sorted(names)
        assert "Pi-Hole-Manager/data/payload.txt" in names
        mode = archive.getinfo("Pi-Hole-Manager/Pi-Hole-Manager").external_attr >> 16
        assert mode & 0o111


def test_source_date_epoch_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    with pytest.raises(RuntimeError, match="SOURCE_DATE_EPOCH"):
        build_release._source_date_epoch()


def test_reproducibility_verifier_detects_mismatch(tmp_path: Path) -> None:
    first = tmp_path / "a"
    second = tmp_path / "b"
    first.mkdir()
    second.mkdir()
    (first / "app.zip").write_bytes(b"same")
    (second / "app.zip").write_bytes(b"same")

    verify(first, second)
    assert _digest(first / "app.zip") == _digest(second / "app.zip")

    (second / "app.zip").write_bytes(b"different")
    with pytest.raises(RuntimeError, match="not reproducible"):
        verify(first, second)


def test_binary_legal_bundle_is_required(tmp_path: Path) -> None:
    source = tmp_path / "Pi-Hole-Manager"
    source.mkdir()
    for name in build_release._REQUIRED_LEGAL_FILES:
        (source / name).write_text("placeholder\n", encoding="utf-8")
    (source / "THIRD_PARTY_NOTICES.md").write_text(
        "sbarbett/pihole6api\nCopyright 2025 Shane Barbetta\n",
        encoding="utf-8",
    )
    (source / "THIRD_PARTY_LICENSES.txt").write_text(
        "Wormhole Observatory third-party license bundle\n",
        encoding="utf-8",
    )

    build_release._validate_binary_legal_bundle(source)
    (source / "NOTICE").unlink()
    with pytest.raises(RuntimeError, match="NOTICE"):
        build_release._validate_binary_legal_bundle(source)


def test_binary_legal_bundle_is_staged_at_onedir_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "dist" / "Pi-Hole-Manager"
    source.mkdir(parents=True)
    for name in build_release._PROJECT_LEGAL_FILES:
        (tmp_path / name).write_text(f"{name}\n", encoding="utf-8")
    (tmp_path / "requirements-build.lock").write_text("Example==1.0\n", encoding="utf-8")

    def fake_generate(lock_path: Path, output_path: Path) -> Path:
        assert lock_path == tmp_path / "requirements-build.lock"
        output_path.write_text(
            "Wormhole Observatory third-party license bundle\n", encoding="utf-8"
        )
        return output_path

    monkeypatch.setattr(build_release, "generate_bundle", fake_generate)
    build_release._stage_binary_legal_bundle(tmp_path, source)

    for name in build_release._PROJECT_LEGAL_FILES:
        assert (source / name).read_text(encoding="utf-8") == f"{name}\n"
    assert (source / "THIRD_PARTY_LICENSES.txt").is_file()
