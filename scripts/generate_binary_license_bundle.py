from __future__ import annotations

import argparse
import re
from importlib import metadata
from pathlib import Path

from packaging.requirements import Requirement

_LICENSE_BASENAME = re.compile(
    r"^(license|licence|copying|notice|copyright|authors?)([._-].*)?$",
    re.IGNORECASE,
)


def _locked_requirements(lock_path: Path) -> list[Requirement]:
    requirements: list[Requirement] = []
    for raw_line in lock_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        requirement = Requirement(line)
        if requirement.marker is not None and not requirement.marker.evaluate():
            continue
        requirements.append(requirement)
    return requirements


def _license_files(distribution: metadata.Distribution) -> list[tuple[str, str]]:
    collected: list[tuple[str, str]] = []
    for package_path in distribution.files or ():
        relative = package_path.as_posix()
        name = Path(relative).name
        parts = [part.lower() for part in Path(relative).parts]
        in_license_directory = "licenses" in parts or "license" in parts
        if not in_license_directory and not _LICENSE_BASENAME.match(name):
            continue
        path = Path(distribution.locate_file(package_path))
        if not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = path.read_text(encoding="utf-8", errors="replace")
        collected.append((relative, text.replace("\r\n", "\n").replace("\r", "\n")))
    collected.sort(key=lambda item: item[0].lower())
    return collected


def _project_urls(dist_metadata: metadata.PackageMetadata) -> list[str]:
    values = sorted(set(dist_metadata.get_all("Project-URL") or []), key=str.lower)
    homepage = str(dist_metadata.get("Home-page") or "").strip()
    if homepage:
        values.append(f"Homepage, {homepage}")
    return values


def generate_bundle(lock_path: Path, output_path: Path) -> Path:
    sections = [
        "Wormhole Observatory third-party license bundle",
        "",
        "Generated deterministically from the active entries in requirements-build.lock.",
        "Inclusion here is conservative and covers the pinned Python build/runtime environment;",
        "it does not imply that every listed package is imported at runtime on every platform.",
        "",
    ]
    seen: set[str] = set()
    for requirement in sorted(_locked_requirements(lock_path), key=lambda item: item.name.lower()):
        normalized = requirement.name.lower().replace("_", "-")
        if normalized in seen:
            continue
        seen.add(normalized)
        try:
            distribution = metadata.distribution(requirement.name)
        except metadata.PackageNotFoundError as exc:
            raise RuntimeError(
                f"Pinned distribution is not installed: {requirement.name}"
            ) from exc

        dist_metadata = distribution.metadata
        name = str(dist_metadata.get("Name") or requirement.name)
        version = distribution.version
        license_expression = str(dist_metadata.get("License-Expression") or "").strip()
        license_field = str(dist_metadata.get("License") or "").strip()
        files = _license_files(distribution)
        if not files and not license_expression and not license_field:
            raise RuntimeError(
                "No license metadata or license file found for pinned distribution: "
                f"{name}=={version}"
            )

        sections.extend(["=" * 80, f"{name} {version}"])
        if license_expression:
            sections.append(f"License-Expression: {license_expression}")
        if license_field:
            sections.append(f"License: {license_field}")
        for project_url in _project_urls(dist_metadata):
            sections.append(f"Project-URL: {project_url}")
        if not files:
            sections.append("License files: none included in installed distribution metadata")
            sections.append("")
            continue

        for relative, text in files:
            sections.extend(["", f"--- {relative} ---", text.rstrip(), ""])

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(sections).rstrip() + "\n", encoding="utf-8", newline="\n")
    return output_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate deterministic third-party license bundle"
    )
    parser.add_argument("--lock", default="requirements-build.lock")
    parser.add_argument("--output", default="build/THIRD_PARTY_LICENSES.txt")
    args = parser.parse_args()
    generate_bundle(Path(args.lock), Path(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
