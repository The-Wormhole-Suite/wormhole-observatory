from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import requests

from pihole_manager import __version__
from pihole_manager.config import UpdateOptions, app_directory

log = logging.getLogger(__name__)
_REPOSITORY = "HyperCriSiS/Pi-Hole-Manager"
_API_BASE = f"https://api.github.com/repos/{_REPOSITORY}"
_RELEASES_API = f"{_API_BASE}/releases"
_VERSION_RE = re.compile(r"^(?:v)?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+](.*))?$")
_SUPPORTED_CHANNELS = {"stable", "prerelease"}
_MANIFEST_NAME = "install_manifest.json"
_PRESERVED_NAMES = (
    "options.json",
    "pihole_manager.sqlite3",
    "pihole_manager.sqlite3-wal",
    "pihole_manager.sqlite3-shm",
    "evidence_cache",
    "updates",
)


@dataclass(frozen=True, slots=True)
class ReleaseAsset:
    name: str
    download_url: str
    size: int
    digest: str = ""


@dataclass(frozen=True, slots=True)
class UpdateInfo:
    current_version: str
    latest_version: str
    release_name: str
    release_url: str
    release_notes: str
    published_at: str
    asset: ReleaseAsset | None
    channel: str = "stable"
    build_id: str = ""
    current_build_id: str = ""
    build_based: bool = False

    @property
    def available(self) -> bool:
        if self.build_based:
            return bool(self.build_id) and not _same_build_id(self.build_id, self.current_build_id)
        return compare_versions(self.latest_version, self.current_version) > 0


@dataclass(frozen=True, slots=True)
class DownloadResult:
    path: Path
    verified: bool


@dataclass(frozen=True, slots=True)
class InstallManifest:
    application: str
    version: str
    channel: str
    platform: str
    architecture: str
    entrypoint: str
    build_id: str = ""
    schema_version: int = 1


@dataclass(frozen=True, slots=True)
class InstallPlan:
    install_directory: Path
    staged_directory: Path
    stage_container: Path
    backup_directory: Path
    entrypoint: str
    marker_path: Path
    status_path: Path
    token: str
    version: str
    preserved_names: tuple[str, ...]


def compare_versions(left: str, right: str) -> int:
    left_key = _version_key(left)
    right_key = _version_key(right)
    return (left_key > right_key) - (left_key < right_key)


def should_check(options: UpdateOptions, *, now: int | None = None) -> bool:
    if not options.check_automatically:
        return False
    current = int(time.time()) if now is None else int(now)
    interval = max(1, int(options.check_interval_hours)) * 3600
    return current - max(0, int(options.last_check_at)) >= interval


def check_for_update(
    *,
    channel: str = "stable",
    current_version: str = __version__,
    timeout: float = 15.0,
) -> UpdateInfo:
    normalized_channel = _normalize_channel(channel)
    payload = _fetch_release_payload(normalized_channel, timeout)
    latest_version = str(payload.get("tag_name") or payload.get("name") or "").strip()
    if not latest_version:
        raise ValueError("The GitHub release contains no version tag")
    build_based = _is_development_release(payload)
    build_id = _release_build_id(payload)
    current_manifest = read_install_manifest()
    asset = _select_asset(payload.get("assets"))
    return UpdateInfo(
        current_version=current_version,
        latest_version=_display_version(latest_version, normalized_channel),
        release_name=str(payload.get("name") or latest_version),
        release_url=str(payload.get("html_url") or ""),
        release_notes=str(payload.get("body") or ""),
        published_at=str(payload.get("published_at") or ""),
        asset=asset,
        channel=normalized_channel,
        build_id=build_id,
        current_build_id=current_manifest.build_id if current_manifest else "",
        build_based=build_based,
    )


def download_update(
    update: UpdateInfo,
    *,
    destination: Path | None = None,
    timeout: float = 120.0,
) -> DownloadResult:
    if update.asset is None:
        raise ValueError("The release has no suitable downloadable Onedir ZIP asset")
    target_dir = destination or (app_directory() / "updates")
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / update.asset.name

    headers = _request_headers()
    with requests.get(
        update.asset.download_url,
        headers=headers,
        timeout=timeout,
        stream=True,
        allow_redirects=True,
    ) as response:
        response.raise_for_status()
        digest = hashlib.sha256()
        with tempfile.NamedTemporaryFile(
            "wb",
            dir=target_dir,
            prefix=f".{update.asset.name}.",
            suffix=".part",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            try:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if not chunk:
                        continue
                    handle.write(chunk)
                    digest.update(chunk)
                handle.flush()
            except Exception:
                temp_path.unlink(missing_ok=True)
                raise

    verified = _verify_digest(update.asset.digest, digest.hexdigest())
    if update.asset.digest and not verified:
        temp_path.unlink(missing_ok=True)
        raise ValueError("Downloaded update failed SHA-256 verification")
    temp_path.replace(target)
    return DownloadResult(path=target, verified=verified)


def installation_directory() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


def read_install_manifest(directory: Path | None = None) -> InstallManifest | None:
    path = (directory or installation_directory()) / _MANIFEST_NAME
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return InstallManifest(
            application=str(raw.get("application") or ""),
            version=str(raw.get("version") or ""),
            channel=str(raw.get("channel") or "stable"),
            platform=str(raw.get("platform") or ""),
            architecture=str(raw.get("architecture") or ""),
            entrypoint=str(raw.get("entrypoint") or ""),
            build_id=str(raw.get("build_id") or ""),
            schema_version=int(raw.get("schema_version") or 1),
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None


def can_install_update(directory: Path | None = None) -> bool:
    root = directory or installation_directory()
    manifest = read_install_manifest(root)
    if manifest is None or manifest.application != "pi-hole-manager":
        return False
    entrypoint = root / manifest.entrypoint
    return entrypoint.is_file() and os.access(root.parent, os.W_OK)


def prepare_update_install(
    update: UpdateInfo,
    archive_path: Path,
    *,
    install_directory_override: Path | None = None,
) -> InstallPlan:
    install_dir = (install_directory_override or installation_directory()).resolve()
    if not can_install_update(install_dir):
        raise RuntimeError(
            "Automatic installation is available only in a packaged Onedir build "
            "located in a writable directory."
        )
    if not archive_path.is_file():
        raise FileNotFoundError(archive_path)

    token = uuid.uuid4().hex
    stage_container = install_dir.parent / f".{install_dir.name}.update-{token}"
    backup_dir = install_dir.parent / f".{install_dir.name}.backup"
    if stage_container.exists():
        shutil.rmtree(stage_container)
    stage_container.mkdir(parents=True)
    try:
        _safe_extract_zip(archive_path, stage_container)
        staged_root = _find_staged_root(stage_container)
        manifest = read_install_manifest(staged_root)
        if manifest is None:
            raise ValueError("The update archive contains no valid install manifest")
        _validate_manifest(manifest, update)
        entrypoint = staged_root / manifest.entrypoint
        if not entrypoint.is_file():
            raise ValueError(f"The update entrypoint is missing: {manifest.entrypoint}")
        if os.name != "nt":
            entrypoint.chmod(entrypoint.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
    except Exception:
        shutil.rmtree(stage_container, ignore_errors=True)
        raise

    temp_root = Path(tempfile.gettempdir()) / "pihole-manager-updater"
    temp_root.mkdir(parents=True, exist_ok=True)
    marker = temp_root / f"started-{token}.marker"
    status = app_directory() / "updates" / f"install-{token}.json"
    marker.unlink(missing_ok=True)
    status.parent.mkdir(parents=True, exist_ok=True)
    return InstallPlan(
        install_directory=install_dir,
        staged_directory=staged_root,
        stage_container=stage_container,
        backup_directory=backup_dir,
        entrypoint=manifest.entrypoint,
        marker_path=marker,
        status_path=status,
        token=token,
        version=manifest.version,
        preserved_names=_preserved_names(install_dir),
    )


def launch_update_installer(plan: InstallPlan, *, parent_pid: int | None = None) -> Path:
    pid = int(parent_pid or os.getpid())
    temp_root = Path(tempfile.gettempdir()) / "pihole-manager-updater"
    temp_root.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        script_path = temp_root / f"apply-{plan.token}.ps1"
        script_path.write_text(_powershell_script(plan, pid), encoding="utf-8-sig")
        process = subprocess.Popen(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script_path),
            ],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            close_fds=True,
        )
    else:
        script_path = temp_root / f"apply-{plan.token}.sh"
        script_path.write_text(_shell_script(plan, pid), encoding="utf-8")
        script_path.chmod(0o700)
        process = subprocess.Popen(
            ["/bin/sh", str(script_path)],
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    threading.Thread(
        target=process.wait,
        name=f"UpdateInstaller-{plan.token[:8]}",
        daemon=True,
    ).start()
    return script_path


def mark_update_started(marker_path: str) -> None:
    if not marker_path:
        return
    path = Path(marker_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(int(time.time())), encoding="utf-8")


def _fetch_release_payload(channel: str, timeout: float) -> dict[str, Any]:
    try:
        if channel == "stable":
            response = requests.get(
                f"{_RELEASES_API}/latest",
                headers=_request_headers(),
                timeout=timeout,
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("GitHub returned an invalid release response")
            return payload

        response = requests.get(
            _RELEASES_API,
            params={"per_page": 50},
            headers=_request_headers(),
            timeout=timeout,
        )
        response.raise_for_status()
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else 0
        if status == 404:
            raise RuntimeError(
                "GitHub releases are unavailable. The repository is currently private, "
                "missing, or has not been published yet."
            ) from exc
        raise

    releases = response.json()
    if not isinstance(releases, list):
        raise ValueError("GitHub returned an invalid releases response")
    candidates = [item for item in releases if isinstance(item, dict) and not item.get("draft")]
    if not candidates:
        raise ValueError("No published GitHub release or prerelease was found")
    if _is_development_release(candidates[0]):
        return candidates[0]
    versioned = [item for item in candidates if not _is_development_release(item)]
    return max(
        versioned,
        key=lambda item: _version_key(str(item.get("tag_name") or item.get("name") or "")),
    )


def _is_development_release(payload: dict[str, Any]) -> bool:
    if not payload.get("prerelease"):
        return False
    tag = str(payload.get("tag_name") or "").lower()
    name = str(payload.get("name") or "").lower()
    target = str(payload.get("target_commitish") or "").lower()
    return target == "dev" or tag.startswith("dev-") or "development build" in name


def _release_build_id(payload: dict[str, Any]) -> str:
    tag = str(payload.get("tag_name") or "").strip()
    target = str(payload.get("target_commitish") or "").strip()
    if target and target.lower() != "dev":
        return target
    if tag.lower().startswith("dev-"):
        return tag.rsplit("-", 1)[-1]
    return target or tag


def _same_build_id(left: str, right: str) -> bool:
    left_value = str(left).strip().lower()
    right_value = str(right).strip().lower()
    if not left_value or not right_value:
        return False
    return left_value.startswith(right_value) or right_value.startswith(left_value)


def _select_asset(raw_assets: Any) -> ReleaseAsset | None:
    if not isinstance(raw_assets, list):
        return None
    current_platform = _platform_id()
    current_arch = _architecture_id()
    candidates: list[tuple[tuple[int, str], dict[str, Any]]] = []
    for item in raw_assets:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not name.lower().endswith(".zip"):
            continue
        priority = _asset_priority(name, current_platform, current_arch)
        if priority[0] < 9:
            candidates.append((priority, item))
    candidates.sort(key=lambda item: item[0])
    if not candidates:
        return None
    item = candidates[0][1]
    return ReleaseAsset(
        name=str(item.get("name") or "").strip(),
        download_url=str(item.get("browser_download_url") or "").strip(),
        size=max(0, int(item.get("size") or 0)),
        digest=str(item.get("digest") or "").strip(),
    )


def _asset_priority(name: str, current_platform: str, current_arch: str) -> tuple[int, str]:
    lower = name.lower()
    if "pi-hole-manager" not in lower or "source" in lower:
        return 9, lower
    platform_match = current_platform in lower
    arch_aliases = {
        "x64": ("x64", "amd64", "x86_64"),
        "arm64": ("arm64", "aarch64"),
    }
    arch_match = any(alias in lower for alias in arch_aliases[current_arch])
    if platform_match and arch_match:
        return 0, lower
    if platform_match and not any(
        alias in lower for aliases in arch_aliases.values() for alias in aliases
    ):
        return 1, lower
    return 9, lower


def _find_staged_root(container: Path) -> Path:
    direct_manifest = container / _MANIFEST_NAME
    if direct_manifest.is_file():
        return container
    manifests = list(container.glob(f"*/{_MANIFEST_NAME}"))
    if len(manifests) != 1:
        raise ValueError("The update archive must contain exactly one Onedir application")
    return manifests[0].parent


def _validate_manifest(manifest: InstallManifest, update: UpdateInfo) -> None:
    if manifest.application != "pi-hole-manager":
        raise ValueError("The update archive is not a Pi-hole Manager build")
    if manifest.schema_version != 1:
        raise ValueError("Unsupported update manifest version")
    if manifest.platform != _platform_id():
        raise ValueError(f"This update targets {manifest.platform}, not {_platform_id()}")
    if manifest.architecture != _architecture_id():
        raise ValueError(f"This update targets {manifest.architecture}, not {_architecture_id()}")
    if update.build_based:
        if (
            update.build_id
            and manifest.build_id
            and not _same_build_id(update.build_id, manifest.build_id)
        ):
            raise ValueError("The development build ID does not match the release")
    elif compare_versions(manifest.version, update.latest_version) != 0:
        raise ValueError("The update version does not match the selected release")


def _safe_extract_zip(archive_path: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive_path) as archive:
        for info in archive.infolist():
            name = info.filename.replace("\\", "/")
            parts = PurePosixPath(name).parts
            if not name or name.startswith("/") or ".." in parts:
                raise ValueError(f"Unsafe archive member: {info.filename}")
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ValueError(f"Symbolic links are not allowed in updates: {info.filename}")
            target = (destination / Path(*parts)).resolve()
            if destination.resolve() not in target.parents and target != destination.resolve():
                raise ValueError(f"Unsafe archive member: {info.filename}")
        archive.extractall(destination)


def _preserved_names(install_dir: Path) -> tuple[str, ...]:
    names = list(_PRESERVED_NAMES)
    for path in sorted(install_dir.glob("*.log")):
        if path.is_file() and path.name not in names:
            names.append(path.name)
    return tuple(names)


def _powershell_script(plan: InstallPlan, parent_pid: int) -> str:
    q = _powershell_quote
    preserved = ", ".join(q(name) for name in plan.preserved_names)
    return f"""$ErrorActionPreference = 'Stop'
$parentPid = {parent_pid}
$installDir = {q(str(plan.install_directory))}
$stageDir = {q(str(plan.staged_directory))}
$stageContainer = {q(str(plan.stage_container))}
$backupDir = {q(str(plan.backup_directory))}
$entrypoint = {q(plan.entrypoint)}
$marker = {q(str(plan.marker_path))}
$statusPath = {q(str(plan.status_path))}
$token = {q(plan.token)}
$preserved = @({preserved})

while (Get-Process -Id $parentPid -ErrorAction SilentlyContinue) {{
    Start-Sleep -Milliseconds 250
}}

function Write-Status([string]$state, [string]$message) {{
    $payload = @{{state=$state; message=$message; version={q(plan.version)}}} | ConvertTo-Json
    New-Item -ItemType Directory -Force -Path (Split-Path $statusPath) | Out-Null
    Set-Content -Path $statusPath -Value $payload -Encoding UTF8
}}

try {{
    Remove-Item -Recurse -Force $backupDir -ErrorAction SilentlyContinue
    Move-Item -Path $installDir -Destination $backupDir
    Move-Item -Path $stageDir -Destination $installDir
    foreach ($name in $preserved) {{
        $source = Join-Path $backupDir $name
        $target = Join-Path $installDir $name
        if (Test-Path $source) {{
            Remove-Item -Recurse -Force $target -ErrorAction SilentlyContinue
            Copy-Item -Recurse -Force $source $target
        }}
    }}
    $exe = Join-Path $installDir $entrypoint
    $process = Start-Process `
        -FilePath $exe `
        -ArgumentList @('--post-update-marker', $marker) `
        -PassThru
    $started = $false
    for ($i = 0; $i -lt 120; $i++) {{
        if (Test-Path $marker) {{ $started = $true; break }}
        if ($process.HasExited) {{ break }}
        Start-Sleep -Milliseconds 250
    }}
    if (-not $started) {{ throw 'The updated application did not start successfully.' }}
    Remove-Item -Recurse -Force $backupDir -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $stageContainer -ErrorAction SilentlyContinue
    Remove-Item -Force $marker -ErrorAction SilentlyContinue
    Write-Status 'success' 'Update installed successfully.'
}} catch {{
    $message = $_.Exception.Message
    Remove-Item -Recurse -Force $installDir -ErrorAction SilentlyContinue
    if (Test-Path $backupDir) {{ Move-Item -Path $backupDir -Destination $installDir }}
    $oldExe = Join-Path $installDir $entrypoint
    if (Test-Path $oldExe) {{ Start-Process -FilePath $oldExe }}
    Write-Status 'rolled_back' $message
}}
"""


def _shell_script(plan: InstallPlan, parent_pid: int) -> str:
    q = _shell_quote
    preserve_commands = "\n".join(f"preserve_item {q(name)}" for name in plan.preserved_names)
    return f"""#!/bin/sh
set -u
parent_pid={parent_pid}
install_dir={q(str(plan.install_directory))}
stage_dir={q(str(plan.staged_directory))}
stage_container={q(str(plan.stage_container))}
backup_dir={q(str(plan.backup_directory))}
entrypoint={q(plan.entrypoint)}
marker={q(str(plan.marker_path))}
status_path={q(str(plan.status_path))}

while kill -0 "$parent_pid" 2>/dev/null; do sleep 0.25; done
write_status() {{
    mkdir -p "$(dirname "$status_path")"
    printf '{{"state":"%s","message":"%s","version":"%s"}}\n' \
        "$1" "$2" {q(plan.version)} > "$status_path"
}}
rollback() {{
    message="$1"
    rm -rf "$install_dir"
    if [ -d "$backup_dir" ]; then mv "$backup_dir" "$install_dir"; fi
    if [ -x "$install_dir/$entrypoint" ]; then "$install_dir/$entrypoint" >/dev/null 2>&1 & fi
    write_status rolled_back "$message"
    exit 1
}}
preserve_item() {{
    name="$1"
    if [ -e "$backup_dir/$name" ]; then
        rm -rf "$install_dir/$name"
        cp -a "$backup_dir/$name" "$install_dir/$name" || \
            rollback 'Could not preserve application data.'
    fi
}}

rm -rf "$backup_dir"
mv "$install_dir" "$backup_dir" || exit 1
mv "$stage_dir" "$install_dir" || rollback 'Could not move the staged update into place.'
{preserve_commands}
"$install_dir/$entrypoint" --post-update-marker "$marker" >/dev/null 2>&1 &
new_pid=$!
started=0
i=0
while [ "$i" -lt 120 ]; do
    if [ -f "$marker" ]; then started=1; break; fi
    if ! kill -0 "$new_pid" 2>/dev/null; then break; fi
    i=$((i + 1))
    sleep 0.25
done
if [ "$started" -ne 1 ]; then
    kill "$new_pid" 2>/dev/null || true
    rollback 'The updated application did not start successfully.'
fi
rm -rf "$backup_dir"
rm -rf "$stage_container"
rm -f "$marker"
write_status success 'Update installed successfully.'
"""


def _normalize_channel(channel: str) -> str:
    value = str(channel).strip().lower()
    if value not in _SUPPORTED_CHANNELS:
        raise ValueError(f"Unsupported update channel: {channel}")
    return value


def _display_version(tag: str, channel: str) -> str:
    stripped = tag.lstrip("vV")
    if channel == "prerelease" and stripped.lower().startswith("dev-"):
        return __version__
    return stripped


def _platform_id() -> str:
    return "windows" if os.name == "nt" else "linux"


def _architecture_id() -> str:
    machine = platform.machine().lower()
    if machine in {"amd64", "x86_64", "x64"}:
        return "x64"
    if machine in {"arm64", "aarch64"}:
        return "arm64"
    raise RuntimeError(f"Unsupported CPU architecture: {machine}")


def _version_key(value: str) -> tuple[int, int, int, int, str]:
    normalized = value.strip()
    match = _VERSION_RE.match(normalized)
    if match is None:
        return 0, 0, 0, -1, normalized.casefold()
    major, minor, patch, suffix = match.groups()
    stable = 1 if not suffix else 0
    return int(major), int(minor or 0), int(patch or 0), stable, (suffix or "")


def _verify_digest(expected: str, actual_sha256: str) -> bool:
    if not expected:
        return False
    algorithm, separator, value = expected.partition(":")
    if not separator or algorithm.lower() != "sha256":
        return False
    return value.strip().lower() == actual_sha256.strip().lower()


def _request_headers() -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "User-Agent": f"Pi-Hole-Manager/{__version__}",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _powershell_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"
