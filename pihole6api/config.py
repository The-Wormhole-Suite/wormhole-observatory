from __future__ import annotations

import json
from typing import Any

from pihole6api.connection import PiHole6Connection, encode_path


class PiHole6Configuration:
    def __init__(self, connection: PiHole6Connection) -> None:
        self.connection = connection

    def export_settings(self) -> bytes:
        return self.connection.get("teleporter", binary=True)

    def import_settings(self, file_path: str, import_options: dict[str, Any] | None = None) -> Any:
        data = {"import": json.dumps(import_options)} if import_options else {}
        return self.connection.upload("teleporter", file_path, data)

    def get_config(self, detailed: bool = False) -> Any:
        return self.connection.get("config", params={"detailed": str(detailed).lower()})

    def update_config(self, config_changes: dict[str, Any]) -> Any:
        return self.connection.patch("config", data={"config": config_changes})

    def get_config_section(self, element: str, detailed: bool = False) -> Any:
        return self.connection.get(
            f"config/{element.strip('/')}",
            params={"detailed": str(detailed).lower()},
        )

    def add_config_item(self, element: str, value: str) -> Any:
        return self.connection.put(f"config/{element.strip('/')}/{encode_path(value)}")

    def delete_config_item(self, element: str, value: str) -> Any:
        return self.connection.delete(f"config/{element.strip('/')}/{encode_path(value)}")

    def add_local_a_record(self, host: str, ip: str) -> Any:
        return self.add_config_item("dns/hosts", f"{ip} {host}")

    def remove_local_a_record(self, host: str, ip: str) -> Any:
        return self.delete_config_item("dns/hosts", f"{ip} {host}")

    def add_local_cname(self, host: str, target: str, ttl: int = 300) -> Any:
        return self.add_config_item("dns/cnameRecords", f"{host},{target},{ttl}")

    def remove_local_cname(self, host: str, target: str, ttl: int = 300) -> Any:
        return self.delete_config_item("dns/cnameRecords", f"{host},{target},{ttl}")
