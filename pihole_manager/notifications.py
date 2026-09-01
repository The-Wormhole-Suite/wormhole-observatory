from __future__ import annotations

import logging
import re
import threading
import time

from pihole_manager.config import load_options
from pihole_manager.push_notifications import load_push_options, send_push_notifications

log = logging.getLogger(__name__)

try:
    from plyer import notification as desktop_notification
except ImportError:
    desktop_notification = None

try:
    import winsound
except ImportError:
    winsound = None

_DOMAIN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![A-Za-z0-9_-])"
)


def _domain_from_message(message: str) -> str | None:
    match = _DOMAIN_PATTERN.search(message)
    return match.group(0).lower().rstrip(".") if match else None


class Notifier:
    def __init__(self) -> None:
        self._last_notification = 0.0

    def notify(
        self,
        title: str,
        message: str | None = None,
        *,
        domain: str | None = None,
    ) -> None:
        if message is None:
            message = title
            title = load_options().notify.toast_title
        if not message:
            return

        options = load_options()
        notify_options = options.notify
        now = time.monotonic()
        if now - self._last_notification < max(0, notify_options.rate_limit_sec):
            return
        self._last_notification = now

        if notify_options.enable_desktop and desktop_notification is not None:
            try:
                desktop_notification.notify(
                    title=title,
                    message=message,
                    app_name="Wormhole Observatory",
                    timeout=5,
                )
            except Exception:
                log.exception("Desktop notification failed")
        else:
            log.info("%s: %s", title, message)

        if notify_options.enable_sound and winsound is not None:
            try:
                winsound.MessageBeep(winsound.MB_ICONASTERISK)
            except RuntimeError:
                log.debug("Notification sound failed", exc_info=True)

        push_options = load_push_options()
        if not (push_options.ntfy_enabled or push_options.unifiedpush_enabled):
            return
        linked_domain = (domain or _domain_from_message(message) or "").strip() or None
        threading.Thread(
            target=send_push_notifications,
            args=(title, message),
            kwargs={"domain": linked_domain, "options": push_options},
            name="PushNotification",
            daemon=True,
        ).start()
