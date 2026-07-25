from __future__ import annotations

from typing import Any

from pihole6api.connection import PiHole6Connection, encode_path


class PiHole6GroupManagement:
    def __init__(self, connection: PiHole6Connection) -> None:
        self.connection = connection

    def add_group(
        self, name: str | list[str], comment: str | None = None, enabled: bool = True
    ) -> Any:
        payload = {
            "name": name if isinstance(name, list) else [name],
            "comment": comment,
            "enabled": bool(enabled),
        }
        return self.connection.post("groups", data=payload)

    def batch_delete_groups(self, group_names: list[str]) -> Any:
        if not isinstance(group_names, list):
            raise TypeError("group_names must be a list")
        return self.connection.post(
            "groups:batchDelete", data=[{"item": name} for name in group_names]
        )

    def get_group(self, name: str) -> Any:
        return self.connection.get(f"groups/{encode_path(name)}")

    def get_groups(self) -> Any:
        return self.connection.get("groups")

    def update_group(
        self,
        name: str,
        new_name: str | None = None,
        comment: str | None = None,
        enabled: bool = True,
    ) -> Any:
        return self.connection.put(
            f"groups/{encode_path(name)}",
            data={
                "name": new_name or name,
                "comment": comment,
                "enabled": bool(enabled),
            },
        )

    def delete_group(self, name: str) -> Any:
        return self.connection.delete(f"groups/{encode_path(name)}")
