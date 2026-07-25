from __future__ import annotations

from typing import Any, Literal

from pihole6api.connection import PiHole6Connection, encode_path

DomainType = Literal["allow", "deny"]
DomainKind = Literal["exact", "regex"]


def _validate(domain_type: str, kind: str) -> None:
    if domain_type not in {"allow", "deny"}:
        raise ValueError("domain_type must be 'allow' or 'deny'")
    if kind not in {"exact", "regex"}:
        raise ValueError("kind must be 'exact' or 'regex'")


class PiHole6DomainManagement:
    def __init__(self, connection: PiHole6Connection) -> None:
        self.connection = connection

    def batch_delete_domains(self, domains: list[dict[str, str]]) -> Any:
        if not isinstance(domains, list):
            raise TypeError("domains must be a list")
        return self.connection.post("domains:batchDelete", data=domains)

    def add_domain(
        self,
        domain: str | list[str],
        domain_type: DomainType,
        kind: DomainKind,
        comment: str | None = None,
        groups: list[int] | None = None,
        enabled: bool = True,
    ) -> Any:
        _validate(domain_type, kind)
        payload = {
            "domain": domain if isinstance(domain, list) else [domain],
            "comment": comment,
            "groups": groups or [],
            "enabled": bool(enabled),
        }
        return self.connection.post(f"domains/{domain_type}/{kind}", data=payload)

    def get_domain(self, domain: str, domain_type: DomainType, kind: DomainKind) -> Any:
        _validate(domain_type, kind)
        return self.connection.get(
            f"domains/{domain_type}/{kind}/{encode_path(domain)}"
        )

    def get_domains(
        self,
        domain_type: DomainType | None = None,
        kind: DomainKind | None = None,
    ) -> Any:
        if domain_type is None:
            return self.connection.get("domains")
        if kind is None:
            raise ValueError("kind is required when domain_type is specified")
        _validate(domain_type, kind)
        return self.connection.get(f"domains/{domain_type}/{kind}")

    def update_domain(
        self,
        domain: str,
        domain_type: DomainType,
        kind: DomainKind,
        *,
        new_type: DomainType | None = None,
        new_kind: DomainKind | None = None,
        comment: str | None = None,
        groups: list[int] | None = None,
        enabled: bool = True,
    ) -> Any:
        _validate(domain_type, kind)
        target_type = new_type or domain_type
        target_kind = new_kind or kind
        _validate(target_type, target_kind)
        payload = {
            "type": target_type,
            "kind": target_kind,
            "comment": comment,
            "groups": groups or [],
            "enabled": bool(enabled),
        }
        return self.connection.put(
            f"domains/{domain_type}/{kind}/{encode_path(domain)}", data=payload
        )

    def delete_domain(
        self, domain: str, domain_type: DomainType, kind: DomainKind
    ) -> Any:
        _validate(domain_type, kind)
        return self.connection.delete(
            f"domains/{domain_type}/{kind}/{encode_path(domain)}"
        )

    def get_all_domains(self) -> dict[str, Any]:
        return {
            "allow": self.get_domains("allow", "exact"),
            "deny": self.get_domains("deny", "exact"),
        }
