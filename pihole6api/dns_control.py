from __future__ import annotations

from typing import Any

from pihole6api.connection import PiHole6Connection


class PiHole6DnsControl:
    def __init__(self, connection: PiHole6Connection) -> None:
        self.connection = connection

    def get_blocking_status(self) -> Any:
        return self.connection.get("dns/blocking")

    def set_blocking_status(self, blocking: bool, timer: int | None = None) -> Any:
        payload: dict[str, bool | int] = {"blocking": blocking}
        if timer is not None:
            payload["timer"] = max(0, int(timer))
        return self.connection.post("dns/blocking", data=payload)
