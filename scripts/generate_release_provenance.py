from __future__ import annotations

import argparse
from pathlib import Path

from pihole_manager.release_provenance import generate


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate in-toto/SLSA provenance for release ZIP artifacts"
    )
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    for output in generate(args.directory):
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
