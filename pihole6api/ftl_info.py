from __future__ import annotations

from typing import Any

from pihole6api.connection import PiHole6Connection, encode_path


class PiHole6FtlInfo:
    def __init__(self, connection: PiHole6Connection) -> None:
        self.connection = connection

    def get_endpoints(self) -> Any:
        return self.connection.get("endpoints")

    def get_client_info(self) -> Any:
        return self.connection.get("info/client")

    def get_database_info(self) -> Any:
        return self.connection.get("info/database")

    def get_ftl_info(self) -> Any:
        return self.connection.get("info/ftl")

    def get_host_info(self) -> Any:
        return self.connection.get("info/host")

    def get_login_info(self) -> Any:
        return self.connection.get("info/login")

    def get_diagnosis_messages(self) -> Any:
        return self.connection.get("info/messages")

    def delete_diagnosis_message(self, message_id: str | int) -> Any:
        return self.connection.delete(f"info/messages/{encode_path(str(message_id))}")

    def get_diagnosis_message_count(self) -> Any:
        return self.connection.get("info/messages/count")

    def get_metrics_info(self) -> Any:
        return self.connection.get("info/metrics")

    def get_sensors_info(self) -> Any:
        return self.connection.get("info/sensors")

    def get_system_info(self) -> Any:
        return self.connection.get("info/system")

    def get_version(self) -> Any:
        return self.connection.get("info/version")

    def get_dnsmasq_logs(self, next_id: int | None = None) -> Any:
        return self.connection.get(
            "logs/dnsmasq", params={"nextID": next_id} if next_id is not None else None
        )

    def get_ftl_logs(self, next_id: int | None = None) -> Any:
        return self.connection.get(
            "logs/ftl", params={"nextID": next_id} if next_id is not None else None
        )

    def get_webserver_logs(self, next_id: int | None = None) -> Any:
        return self.connection.get(
            "logs/webserver", params={"nextID": next_id} if next_id is not None else None
        )
