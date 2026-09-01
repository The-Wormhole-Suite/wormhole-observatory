from __future__ import annotations

import argparse
import hashlib
import os
import platform
import stat
import time
import zipfile
from pathlib import Path

from pihole_manager.config import Options
from pihole_manager.evidence_licensing import distribution_license_issues

_ZIP_MIN_EPOCH = 315532800  # 1980-01-01 UTC


def _architecture() -> str:
    machine = platform.machine().lower()
    if machine in {"amd64", "x86_64", "x64"}:
        return "x64"
    if machine in {"arm64", "aarch64"}:
        return "arm64"
    raise RuntimeError(f"Unsupported CPU architecture: {machine}")


def _validate_evidence_license_defaults() -> None:
    enabled_kinds = [
        provider.kind
        for provider in Options().research_providers
        if provider.enabled
    ]
    issues = distribution_license_issues(enabled_kinds)
    if issues:
        formatted = "\n- ".join(issues)
        raise RuntimeError(
            "Evidence-source release defaults failed the licensing gate:\n- "
            + formatted
        )


def _source_date_epoch() -> int:
    raw = str(os.environ.get("SOURCE_DATE_EPOCH") or "").strip()
    if not raw:
        raise RuntimeError(
            "SOURCE_DATE_EPOCH must be set to the source commit timestamp for release builds"
        )
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError("SOURCE_DATE_EPOCH must be an integer Unix timestamp") from exc
    return max(value, _ZIP_MIN_EPOCH)


def _zip_datetime(epoch: int) -> tuple[int, int, int, int, int, int]:
    value = time.gmtime(max(epoch, _ZIP_MIN_EPOCH))
    second = value.tm_sec - (value.tm_sec % 2)
    return (
        value.tm_year,
        value.tm_mon,
        value.tm_mday,
        value.tm_hour,
        value.tm_min,
        second,
    )


def _archive_mode(path: Path) -> int:
    mode = stat.S_IMODE(path.stat().st_mode)
    if path.is_dir():
        return mode or 0o755
    return mode or 0o644


def _write_deterministic_zip(source: Path, archive: Path, *, epoch: int) -> None:
    archive.parent.mkdir(parents=True, exist_ok=True)
    timestamp = _zip_datetime(epoch)
    entries = sorted(source.rglob("*"), key=lambda item: item.relative_to(source).as_posix())
    root = source.name
    with zipfile.ZipFile(
        archive,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as output:
        root_info = zipfile.ZipInfo(f"{root}/", timestamp)
        root_info.create_system = 3
        root_info.external_attr = (0o755 | stat.S_IFDIR) << 16
        root_info.compress_type = zipfile.ZIP_STORED
        output.writestr(root_info, b"")
        for path in entries:
            relative = path.relative_to(source).as_posix()
            arcname = f"{root}/{relative}"
            if path.is_dir():
                info = zipfile.ZipInfo(f"{arcname}/", timestamp)
                info.create_system = 3
                info.external_attr = (_archive_mode(path) | stat.S_IFDIR) << 16
                info.compress_type = zipfile.ZIP_STORED
                output.writestr(info, b"")
                continue
            info = zipfile.ZipInfo(arcname, timestamp)
            info.create_system = 3
            info.external_attr = (_archive_mode(path) | stat.S_IFREG) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            output.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Package a Pi-hole Manager Onedir build")
    parser.add_argument("--platform", choices=("windows", "linux"), required=True)
    parser.add_argument("--output-dir", default="release")
    args = parser.parse_args()

    _validate_evidence_license_defaults()
    project_root = Path(__file__).resolve().parent
    source = project_root / "dist" / "Pi-Hole-Manager"
    if not source.is_dir():
        raise FileNotFoundError(f"Onedir build not found: {source}")
    output_dir = project_root / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / f"Pi-Hole-Manager-{args.platform}-{_architecture()}.zip"
    _write_deterministic_zip(source, archive, epoch=_source_date_epoch())
    digest = _sha256(archive)
    archive.with_suffix(archive.suffix + ".sha256").write_text(
        f"{digest}  {archive.name}\n",
        encoding="utf-8",
        newline="\n",
    )
    print(archive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
