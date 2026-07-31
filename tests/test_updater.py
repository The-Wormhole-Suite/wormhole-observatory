from __future__ import annotations

import hashlib
import json
import time
import zipfile
from pathlib import Path
from typing import Any

import pytest

from pihole_manager.config import UpdateOptions
from pihole_manager.updater import (
    DownloadResult,
    InstallManifest,
    ReleaseAsset,
    UpdateInfo,
    check_for_update,
    compare_versions,
    download_update,
    launch_update_installer,
    prepare_update_install,
    should_check,
)


class _ReleaseResponse:
    def __init__(self, payload: Any) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> Any:
        return self._payload


class _DownloadResponse:
    def __init__(self, content: bytes) -> None:
        self._content = content

    def __enter__(self) -> _DownloadResponse:
        return self

    def __exit__(self, *_args: Any) -> None:
        return None

    def raise_for_status(self) -> None:
        return None

    def iter_content(self, chunk_size: int) -> list[bytes]:
        del chunk_size
        return [self._content]


def _manifest(
    *,
    version: str,
    build_id: str,
    platform_id: str = "linux",
    architecture: str = "x64",
    entrypoint: str = "Pi-Hole-Manager",
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "application": "pi-hole-manager",
        "version": version,
        "channel": "prerelease",
        "platform": platform_id,
        "architecture": architecture,
        "entrypoint": entrypoint,
        "build_id": build_id,
    }


def test_version_comparison_handles_tags_and_prereleases() -> None:
    assert compare_versions("v0.3.1", "0.3.0") > 0
    assert compare_versions("0.3.1", "0.3.1-beta") > 0
    assert compare_versions("0.3.1", "0.3.1") == 0


def test_update_check_selects_platform_onedir_zip(monkeypatch) -> None:
    payload = {
        "tag_name": "v0.4.0",
        "name": "Pi-hole Manager 0.4.0",
        "html_url": "https://github.example/release",
        "body": "Release notes",
        "published_at": "2026-07-27T00:00:00Z",
        "target_commitish": "abcdef",
        "assets": [
            {
                "name": "Pi-Hole-Manager-linux-x64.zip",
                "browser_download_url": "https://github.example/update.zip",
                "size": 123,
                "digest": "sha256:abc",
            },
            {
                "name": "Pi-Hole-Manager-windows-x64.zip",
                "browser_download_url": "https://github.example/windows.zip",
                "size": 123,
                "digest": "sha256:def",
            },
        ],
    }
    monkeypatch.setattr(
        "pihole_manager.updater.requests.get",
        lambda *_args, **_kwargs: _ReleaseResponse(payload),
    )
    monkeypatch.setattr("pihole_manager.updater._platform_id", lambda: "linux")
    monkeypatch.setattr("pihole_manager.updater._architecture_id", lambda: "x64")

    update = check_for_update(current_version="0.3.0")

    assert update.available is True
    assert update.latest_version == "0.4.0"
    assert update.asset is not None
    assert update.asset.name == "Pi-Hole-Manager-linux-x64.zip"


def test_prerelease_channel_accepts_dev_branch_builds(monkeypatch) -> None:
    payload = [
        {
            "tag_name": "dev-42-abcdef12",
            "name": "Development build abcdef12",
            "html_url": "https://github.example/dev",
            "body": "",
            "published_at": "2026-07-27T00:00:00Z",
            "target_commitish": "abcdef123456",
            "draft": False,
            "prerelease": True,
            "assets": [
                {
                    "name": "Pi-Hole-Manager-linux-x64.zip",
                    "browser_download_url": "https://github.example/dev.zip",
                    "size": 123,
                    "digest": "sha256:abc",
                }
            ],
        }
    ]
    monkeypatch.setattr(
        "pihole_manager.updater.requests.get",
        lambda *_args, **_kwargs: _ReleaseResponse(payload),
    )
    monkeypatch.setattr("pihole_manager.updater._platform_id", lambda: "linux")
    monkeypatch.setattr("pihole_manager.updater._architecture_id", lambda: "x64")
    monkeypatch.setattr(
        "pihole_manager.updater.read_install_manifest",
        lambda *_args, **_kwargs: InstallManifest(
            application="pi-hole-manager",
            version="0.3.2",
            channel="prerelease",
            platform="linux",
            architecture="x64",
            entrypoint="Pi-Hole-Manager",
            build_id="older",
        ),
    )

    update = check_for_update(channel="prerelease")

    assert update.available is True
    assert update.build_id == "abcdef123456"
    assert update.latest_version == "0.3.6"


def test_download_verifies_published_sha256(monkeypatch, tmp_path: Path) -> None:
    content = b"verified update archive"
    digest = hashlib.sha256(content).hexdigest()
    update = UpdateInfo(
        current_version="0.3.0",
        latest_version="0.4.0",
        release_name="0.4.0",
        release_url="https://github.example/release",
        release_notes="",
        published_at="",
        asset=ReleaseAsset(
            name="Pi-Hole-Manager-linux-x64.zip",
            download_url="https://github.example/update.zip",
            size=len(content),
            digest=f"sha256:{digest}",
        ),
    )
    monkeypatch.setattr(
        "pihole_manager.updater.requests.get",
        lambda *_args, **_kwargs: _DownloadResponse(content),
    )

    result = download_update(update, destination=tmp_path)

    assert isinstance(result, DownloadResult)
    assert result.verified is True
    assert result.path.read_bytes() == content


def test_prepare_update_rejects_zip_path_traversal(monkeypatch, tmp_path: Path) -> None:
    install_dir = tmp_path / "Pi-Hole-Manager"
    install_dir.mkdir()
    (install_dir / "Pi-Hole-Manager").write_text("old", encoding="utf-8")
    (install_dir / "install_manifest.json").write_text(
        json.dumps(_manifest(version="0.3.1", build_id="old")),
        encoding="utf-8",
    )
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("../escape.txt", "unsafe")
    monkeypatch.setattr("pihole_manager.updater._platform_id", lambda: "linux")
    monkeypatch.setattr("pihole_manager.updater._architecture_id", lambda: "x64")
    update = UpdateInfo(
        current_version="0.3.1",
        latest_version="0.3.2",
        release_name="0.3.2",
        release_url="",
        release_notes="",
        published_at="",
        asset=None,
    )

    with pytest.raises(ValueError, match="Unsafe archive member"):
        prepare_update_install(
            update,
            archive,
            install_directory_override=install_dir,
        )


def test_linux_installer_replaces_onedir_and_preserves_data(
    monkeypatch,
    tmp_path: Path,
) -> None:
    if __import__("os").name == "nt":
        pytest.skip("Linux installer test")
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path / "data"))
    monkeypatch.setattr("pihole_manager.updater._platform_id", lambda: "linux")
    monkeypatch.setattr("pihole_manager.updater._architecture_id", lambda: "x64")

    install_dir = tmp_path / "Pi-Hole-Manager"
    install_dir.mkdir()
    old_entrypoint = install_dir / "Pi-Hole-Manager"
    old_entrypoint.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    old_entrypoint.chmod(0o755)
    (install_dir / "install_manifest.json").write_text(
        json.dumps(_manifest(version="0.3.1", build_id="old")),
        encoding="utf-8",
    )
    (install_dir / "options.json").write_text("preserve-me", encoding="utf-8")

    archive = tmp_path / "Pi-Hole-Manager-linux-x64.zip"
    new_script = """#!/bin/sh
if [ "$1" = "--post-update-marker" ]; then
    printf 'ok' > "$2"
fi
sleep 2
"""
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(
            "Pi-Hole-Manager/install_manifest.json",
            json.dumps(_manifest(version="0.3.2", build_id="new")),
        )
        info = zipfile.ZipInfo("Pi-Hole-Manager/Pi-Hole-Manager")
        info.external_attr = 0o755 << 16
        handle.writestr(info, new_script)
        handle.writestr("Pi-Hole-Manager/new.txt", "installed")

    update = UpdateInfo(
        current_version="0.3.1",
        latest_version="0.3.2",
        release_name="0.3.2",
        release_url="",
        release_notes="",
        published_at="",
        asset=None,
    )
    plan = prepare_update_install(
        update,
        archive,
        install_directory_override=install_dir,
    )
    launch_update_installer(plan, parent_pid=999_999_999)

    deadline = time.time() + 10
    while time.time() < deadline and not plan.status_path.exists():
        time.sleep(0.1)

    assert json.loads(plan.status_path.read_text(encoding="utf-8"))["state"] == "success"
    assert (install_dir / "new.txt").read_text(encoding="utf-8") == "installed"
    assert (install_dir / "options.json").read_text(encoding="utf-8") == "preserve-me"
    assert not plan.backup_directory.exists()


def test_automatic_check_respects_interval() -> None:
    options = UpdateOptions(
        check_automatically=True,
        check_interval_hours=24,
        last_check_at=100,
    )
    assert should_check(options, now=100 + 24 * 3600 - 1) is False
    assert should_check(options, now=100 + 24 * 3600) is True
    options.check_automatically = False
    assert should_check(options, now=100 + 48 * 3600) is False


def test_linux_installer_rolls_back_when_new_build_does_not_start(
    monkeypatch,
    tmp_path: Path,
) -> None:
    if __import__("os").name == "nt":
        pytest.skip("Linux installer test")
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path / "data"))
    monkeypatch.setattr("pihole_manager.updater._platform_id", lambda: "linux")
    monkeypatch.setattr("pihole_manager.updater._architecture_id", lambda: "x64")

    install_dir = tmp_path / "Pi-Hole-Manager"
    install_dir.mkdir()
    old_entrypoint = install_dir / "Pi-Hole-Manager"
    old_entrypoint.write_text(
        '#!/bin/sh\nprintf \'restarted\' > "$(dirname "$0")/old-restarted.txt"\n',
        encoding="utf-8",
    )
    old_entrypoint.chmod(0o755)
    (install_dir / "install_manifest.json").write_text(
        json.dumps(_manifest(version="0.3.1", build_id="old")),
        encoding="utf-8",
    )
    (install_dir / "old.txt").write_text("previous version", encoding="utf-8")

    archive = tmp_path / "Pi-Hole-Manager-linux-x64.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr(
            "Pi-Hole-Manager/install_manifest.json",
            json.dumps(_manifest(version="0.3.2", build_id="new")),
        )
        info = zipfile.ZipInfo("Pi-Hole-Manager/Pi-Hole-Manager")
        info.external_attr = 0o755 << 16
        handle.writestr(info, "#!/bin/sh\nexit 1\n")
        handle.writestr("Pi-Hole-Manager/new.txt", "broken")

    update = UpdateInfo(
        current_version="0.3.1",
        latest_version="0.3.2",
        release_name="0.3.2",
        release_url="",
        release_notes="",
        published_at="",
        asset=None,
    )
    plan = prepare_update_install(
        update,
        archive,
        install_directory_override=install_dir,
    )
    launch_update_installer(plan, parent_pid=999_999_999)

    deadline = time.time() + 10
    while time.time() < deadline and not plan.status_path.exists():
        time.sleep(0.1)

    assert json.loads(plan.status_path.read_text(encoding="utf-8"))["state"] == "rolled_back"
    assert (install_dir / "old.txt").read_text(encoding="utf-8") == "previous version"
    assert not (install_dir / "new.txt").exists()


def test_prerelease_channel_also_accepts_newer_stable_release(monkeypatch) -> None:
    payload = [
        {
            "tag_name": "v0.4.0-beta.1",
            "name": "Beta",
            "draft": False,
            "prerelease": True,
            "assets": [],
        },
        {
            "tag_name": "v0.4.0",
            "name": "Stable",
            "draft": False,
            "prerelease": False,
            "assets": [],
        },
    ]
    monkeypatch.setattr(
        "pihole_manager.updater.requests.get",
        lambda *_args, **_kwargs: _ReleaseResponse(payload),
    )

    update = check_for_update(channel="prerelease", current_version="0.3.2")

    assert update.latest_version == "0.4.0"
    assert update.release_name == "Stable"


def test_private_repository_404_has_clear_error(monkeypatch) -> None:
    import requests

    class _NotFoundResponse:
        status_code = 404

        def raise_for_status(self) -> None:
            response = requests.Response()
            response.status_code = 404
            raise requests.HTTPError("404", response=response)

    monkeypatch.setattr(
        "pihole_manager.updater.requests.get",
        lambda *_args, **_kwargs: _NotFoundResponse(),
    )

    with pytest.raises(RuntimeError, match="repository is currently private"):
        check_for_update(channel="stable")
