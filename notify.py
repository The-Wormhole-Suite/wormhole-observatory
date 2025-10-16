
import logging
from typing import Dict, Any
from config import load_options
log = logging.getLogger(__name__)

class Notifier:
    def __init__(self):
        self.opts = load_options().notify

    def refresh(self):
        self.opts = load_options().notify

    def send_info(self, text: str) -> None:
        log.info("NOTIFY: %s", text)
        # TODO: implement Telegram/Signal/HA based on self.opts.enabled_channels

    def request_confirmation(self, payload: Dict[str, Any]) -> bool:
        log.info("CONFIRM REQUEST: %s", payload)
        # TODO: interactive confirmation; return False by default
        return False
