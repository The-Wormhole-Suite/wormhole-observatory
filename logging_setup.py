# Robust logging setup: create directories automatically and fall back safely
import os
import logging
import logging.handlers
from config import load_options

_configured = False


def _safe_log_path(raw_path: str) -> str:
    """Ensure directory exists; if creation fails, fall back to user home."""
    try:
        if not raw_path:
            raise ValueError("empty path")
        # If relative, place it next to this file
        if not os.path.isabs(raw_path):
            base_dir = os.path.dirname(__file__)
            raw_path = os.path.join(base_dir, raw_path)
        log_dir = os.path.dirname(raw_path) or "."
        os.makedirs(log_dir, exist_ok=True)
        return raw_path
    except Exception:
        # Ultimate fallback: home dir
        home = os.path.expanduser("~")
        fallback = os.path.join(home, "pihole_manager.log")
        try:
            os.makedirs(os.path.dirname(fallback), exist_ok=True)
        except Exception:
            pass
        return fallback


def setup_logging(force: bool = False) -> None:
    global _configured
    if _configured and not force:
        return

    opts = load_options().logging

    logger = logging.getLogger()
    logger.handlers.clear()

    # Always have at least INFO if invalid
    level = getattr(logging, opts.level.upper(), logging.INFO)
    logger.setLevel(level)

    if opts.enabled:
        file_path = _safe_log_path(opts.file_path)
        fh = logging.handlers.RotatingFileHandler(
            file_path,
            maxBytes=int(opts.rotate_bytes),
            backupCount=int(opts.backup_count),
            encoding="utf-8",
        )
        fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(threadName)s %(name)s: %(message)s"
        )
        fh.setFormatter(fmt)
        logger.addHandler(fh)

        ch = logging.StreamHandler()
        ch.setFormatter(fmt)
        logger.addHandler(ch)
    else:
        # Even if file logging is disabled, keep a simple console handler so we see errors.
        ch = logging.StreamHandler()
        ch.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        )
        logger.addHandler(ch)

    logger.debug("Logging initialized.")
    _configured = True
