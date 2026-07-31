from __future__ import annotations

from typing import Any, Literal

from pihole6api.connection import PiHole6Connection, encode_path

ListType = Literal["allow", "block"]


def _validate_list_type(list_type: str) -> None:
    if list_type not in {"allow", "block"}:
        raise ValueError("list_type must be 'allow' or 'block'")


class PiHole6ListManagement:
    def __init__(self, connection: PiHole6Connection) -> None:
        self.connection = connection

    def add_list(
        self,
        address: str | list[str],
        list_type: ListType,
        comment: str | None = None,
        groups: list[int] | None = None,
        enabled: bool = True,
    ) -> Any:
        _validate_list_type(list_type)
        payload = {
            "address": address if isinstance(address, list) else [address],
            "type": list_type,
            "comment": comment,
            "groups": groups or [],
            "enabled": bool(enabled),
        }
        return self.connection.post("lists", data=payload)

    def batch_delete_lists(self, lists: list[dict[str, str]]) -> Any:
        if not isinstance(lists, list):
            raise TypeError("lists must be a list")
        return self.connection.post("lists:batchDelete", data=lists)

    def get_list(self, address: str, list_type: ListType) -> Any:
        _validate_list_type(list_type)
        return self.connection.get(f"lists/{encode_path(address)}", params={"type": list_type})

    def get_lists(self, list_type: ListType | None = None) -> Any:
        if list_type is not None:
            _validate_list_type(list_type)
        return self.connection.get("lists", params={"type": list_type} if list_type else None)

    def update_list(
        self,
        address: str,
        list_type: ListType,
        comment: str | None = None,
        groups: list[int] | None = None,
        enabled: bool = True,
    ) -> Any:
        _validate_list_type(list_type)
        return self.connection.put(
            f"lists/{encode_path(address)}",
            data={
                "type": list_type,
                "comment": comment,
                "groups": groups or [],
                "enabled": bool(enabled),
            },
        )

    def delete_list(self, address: str, list_type: ListType) -> Any:
        _validate_list_type(list_type)
        return self.connection.delete(f"lists/{encode_path(address)}", params={"type": list_type})

    def search_list(
        self,
        domain: str,
        num: int | None = None,
        partial: bool = False,
        debug: bool = False,
    ) -> Any:
        params: dict[str, Any] = {
            "partial": str(partial).lower(),
            "debug": str(debug).lower(),
        }
        if num is not None:
            params["N"] = max(1, int(num))
        return self.connection.get(f"search/{encode_path(domain)}", params=params)
