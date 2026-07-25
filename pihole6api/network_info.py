from __future__ import annotations

from typing import Any

from pihole6api.connection import PiHole6Connection, encode_path


class PiHole6NetworkInfo:
    def __init__(self, connection: PiHole6Connection) -> None:
        self.connection = connection

    def get_devices(
        self, max_devices: int | None = None, max_addresses: int | None = None
    ) -> Any:
        params = {
            key: value
            for key, value in {
                "max_devices": max_devices,
                "max_addresses": max_addresses,
            }.items()
            if value is not None
        }
        return self.connection.get("network/devices", params=params or None)

    def delete_device(self, device_id: str | int) -> Any:
        return self.connection.delete(f"network/devices/{encode_path(str(device_id))}")

    def get_gateway(self, detailed: bool = False) -> Any:
        return self.connection.get(
            "network/gateway", params={"detailed": str(detailed).lower()}
        )

    def get_interfaces(self, detailed: bool = False) -> Any:
        return self.connection.get(
            "network/interfaces", params={"detailed": str(detailed).lower()}
        )

    def get_routes(self, detailed: bool = False) -> Any:
        return self.connection.get(
            "network/routes", params={"detailed": str(detailed).lower()}
        )
