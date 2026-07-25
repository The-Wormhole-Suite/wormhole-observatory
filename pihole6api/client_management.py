from __future__ import annotations

from typing import Any

from pihole6api.connection import PiHole6Connection, encode_path


class PiHole6ClientManagement:
    def __init__(self, connection: PiHole6Connection) -> None:
        self.connection = connection

    def add_client(
        self,
        client: str | list[str],
        comment: str | None = None,
        groups: list[int] | None = None,
    ) -> Any:
        payload = {
            "client": client if isinstance(client, list) else [client],
            "comment": comment,
            "groups": groups or [],
        }
        return self.connection.post("clients", data=payload)

    def batch_delete_clients(self, clients: list[dict[str, str]]) -> Any:
        if not isinstance(clients, list):
            raise TypeError("clients must be a list")
        return self.connection.post("clients:batchDelete", data=clients)

    def get_client_suggestions(self) -> Any:
        return self.connection.get("clients/_suggestions")

    def get_client(self, client: str) -> Any:
        return self.connection.get(f"clients/{encode_path(client)}")

    def get_clients(self) -> Any:
        return self.connection.get("clients")

    def update_client(
        self,
        client: str,
        comment: str | None = None,
        groups: list[int] | None = None,
    ) -> Any:
        return self.connection.put(
            f"clients/{encode_path(client)}",
            data={"comment": comment, "groups": groups or []},
        )

    def delete_client(self, client: str) -> Any:
        return self.connection.delete(f"clients/{encode_path(client)}")
