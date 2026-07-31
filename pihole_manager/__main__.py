from __future__ import annotations

import argparse
from collections.abc import Sequence

from pihole_manager import __version__


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Pi-hole Manager for Pi-hole v6+")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--post-update-marker", default="", help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    from pihole_manager.gui.app import run_app

    run_app(post_update_marker=args.post_update_marker)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
