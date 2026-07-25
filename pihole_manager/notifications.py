from __future__ import annotations

import logging
import time

from pihole_manager.config import load_options

log = logging.getLogger(__name__)

try:
    from plyer import notification as desktop_notification
except ImportError:
    desktop_notification = None

try:
    import winsound
except ImportError:
    winsound = None


class Notifier:
    def __init__(self) -> None:
        self._last_notification = 0.0

    def notify(self, title: str, message: str | None = None) -> None:
        if message is None:
            message = title
            title = load_options().notify.toast_title
        if not message:
            return

        options = load_options().notify
        now = time.monotonic()
        if now - self._last_notification < max(0, options.rate_limit_sec):
            return
        self._last_notification = now

        if options.enable_desktop and desktop_notification is not None:
            try:
                desktop_notification.notify(
                    title=title,
                    message=message,
                    app_name="Pi-hole Manager",
                    timeout=5,
                )
            except Exception:
                log.exception("Desktop notification failed")
        else:
            log.info("%s: %s", title, message)

        if options.enable_sound and winsound is not None:
            try:
                winsound.MessageBeep(winsound.MB_ICONASTERISK)
            except RuntimeError:
                log.debug("Notification sound failed", exc_info=True)
