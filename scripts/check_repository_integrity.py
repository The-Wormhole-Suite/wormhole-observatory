from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SCAN_ROOTS = (
    ROOT / ".github" / "workflows",
    ROOT / "pihole6api",
    ROOT / "pihole_manager",
    ROOT / "scripts",
    ROOT / "tests",
)

CRITICAL_MIN_LINES = {
    ".github/workflows/ci.yml": 20,
    ".github/workflows/release.yml": 100,
    ".github/workflows/dev-release.yml": 100,
    ".github/workflows/container.yml": 100,
    "pihole6api/connection.py": 250,
    "pihole_manager/pihole_service.py": 300,
    "pihole_manager/gui/tabs/settings_pihole.py": 250,
    "tests/test_connection.py": 100,
}

TEXT_SUFFIXES = {".py", ".yml", ".yaml", ".toml", ".sh", ".ps1"}
RESTORE_SENTINEL = "PLACEHOLDER" + "_RESTORE_FROM_REPO_REQUIRED"
ACTION_USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s+([^@\s]+)@([^\s#]+)")
IMMUTABLE_ACTION_REF_RE = re.compile(r"^[0-9a-fA-F]{40}$")
TRUSTED_MUTABLE_ACTION_OWNERS = {"actions", "github"}


def _text_files() -> list[Path]:
    files: list[Path] = []
    for scan_root in SCAN_ROOTS:
        if not scan_root.exists():
            continue
        files.extend(
            path
            for path in scan_root.rglob("*")
            if path.is_file() and path.suffix.lower() in TEXT_SUFFIXES
        )
    return sorted(set(files))


def check_repository_integrity() -> list[str]:
    errors: list[str] = []

    for relative, minimum_lines in CRITICAL_MIN_LINES.items():
        path = ROOT / relative
        if not path.is_file():
            errors.append(f"critical file is missing: {relative}")
            continue
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        if line_count < minimum_lines:
            errors.append(
                f"critical file is unexpectedly small: {relative} "
                f"({line_count} lines; expected at least {minimum_lines})"
            )

    for path in _text_files():
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT).as_posix()
        if RESTORE_SENTINEL in text:
            errors.append(f"restore sentinel found in {relative}")
        for line_number, line in enumerate(text.splitlines(), start=1):
            if line.strip() == "PLACEHOLDER":
                errors.append(f"standalone placeholder found in {relative}:{line_number}")
            if relative.startswith(".github/workflows/"):
                match = ACTION_USES_RE.match(line)
                if match:
                    action, ref = match.groups()
                    owner = action.split("/", 1)[0].lower()
                    if (
                        not action.startswith("./")
                        and owner not in TRUSTED_MUTABLE_ACTION_OWNERS
                        and not IMMUTABLE_ACTION_REF_RE.fullmatch(ref)
                    ):
                        errors.append(
                            "third-party action is not pinned to a full commit SHA: "
                            f"{relative}:{line_number} ({action}@{ref})"
                        )

    return errors


def main() -> int:
    errors = check_repository_integrity()
    if errors:
        print("Repository integrity check failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("Repository integrity check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
