from __future__ import annotations

from typing import Any

from pihole6api.connection import PiHole6Connection, encode_path


class PiHole6Dhcp:
    def __init__(self, connection: PiHole6Connection) -> None:
        self.connection = connection

    def get_leases(self) -> Any:
        return self.connection.get("dhcp/leases")

    def remove_lease(self, ip: str) -> Any:
        return self.connection.delete(f"dhcp/leases/{encode_path(ip)}")
