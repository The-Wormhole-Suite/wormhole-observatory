from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from pihole_manager.config import app_directory, load_options

_CONFIGURED = False


def _resolve_log_path(filename: str) -> Path:
    path = Path(filename).expanduser()
    if not path.is_absolute():
        path = app_directory() / path
    return path.resolve()


def setup_logging(force: bool = False) -> None:
    global _CONFIGURED
    if _CONFIGURED and not force:
        return

    options = load_options().logging
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()

    level = getattr(logging, options.level.upper(), logging.INFO)
    root.setLevel(level)

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(level)
    console.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    root.addHandler(console)

    if options.enabled:
        path = _resolve_log_path(options.filename)
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            path,
            maxBytes=options.rotate_bytes,
            backupCount=options.backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(threadName)s %(name)s "
                "[%(filename)s:%(lineno)d]: %(message)s"
            )
        )
        root.addHandler(file_handler)
        root.info("File logging enabled at %s", path)

    logging.getLogger("urllib3").setLevel(logging.WARNING)
    _CONFIGURED = True
