from __future__ import annotations

from typing import Any

from pihole6api.connection import PiHole6Connection


class PiHole6Actions:
    def __init__(self, connection: PiHole6Connection) -> None:
        self.connection = connection

    def flush_arp(self) -> Any:
        return self.connection.post("action/flush/arp")

    def flush_logs(self) -> Any:
        return self.connection.post("action/flush/logs")

    def run_gravity(self) -> Any:
        return self.connection.post("action/gravity")

    def restart_dns(self) -> Any:
        return self.connection.post("action/restartdns")
