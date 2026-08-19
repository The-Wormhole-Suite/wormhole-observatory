from __future__ import annotations

import argparse
import hashlib
import platform
import shutil
from pathlib import Path

from pihole_manager.config import Options
from pihole_manager.evidence_licensing import distribution_license_issues


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
    archive_base = output_dir / f"Pi-Hole-Manager-{args.platform}-{_architecture()}"
    archive = Path(
        shutil.make_archive(
            str(archive_base),
            "zip",
            root_dir=source.parent,
            base_dir=source.name,
        )
    )
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(archive.suffix + ".sha256").write_text(
        f"{digest}  {archive.name}\n",
        encoding="utf-8",
    )
    print(archive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
