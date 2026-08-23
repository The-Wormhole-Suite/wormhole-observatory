from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _archives(directory: Path) -> dict[str, Path]:
    return {path.name: path for path in sorted(directory.glob("*.zip")) if path.is_file()}


def verify(first: Path, second: Path) -> None:
    first_archives = _archives(first)
    second_archives = _archives(second)
    if not first_archives:
        raise RuntimeError(f"No release ZIP files found in {first}")
    if first_archives.keys() != second_archives.keys():
        raise RuntimeError(
            "Release archive sets differ: "
            f"{sorted(first_archives)} != {sorted(second_archives)}"
        )
    mismatches: list[str] = []
    for name in first_archives:
        first_digest = _sha256(first_archives[name])
        second_digest = _sha256(second_archives[name])
        if first_digest != second_digest:
            mismatches.append(f"{name}: {first_digest} != {second_digest}")
    if mismatches:
        raise RuntimeError("Build is not reproducible:\n" + "\n".join(mismatches))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify two Onedir release passes are byte-for-byte identical"
    )
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path)
    args = parser.parse_args()
    verify(args.first, args.second)
    print("Reproducibility verification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
