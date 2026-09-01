from __future__ import annotations

from pihole6api.actions import PiHole6Actions
from pihole6api.client_management import PiHole6ClientManagement
from pihole6api.config import PiHole6Configuration
from pihole6api.connection import PiHole6Connection
from pihole6api.dhcp import PiHole6Dhcp
from pihole6api.dns_control import PiHole6DnsControl
from pihole6api.domain_management import PiHole6DomainManagement
from pihole6api.ftl_info import PiHole6FtlInfo
from pihole6api.group_management import PiHole6GroupManagement
from pihole6api.list_management import PiHole6ListManagement
from pihole6api.metrics import PiHole6Metrics
from pihole6api.network_info import PiHole6NetworkInfo


class PiHole6Client:
    def __init__(
        self,
        base_url: str,
        password: str = "",
        *,
        app_password: str | None = None,
        ca_bundle_path: str = "",
        verify_tls: bool | str | None = None,
        timeout: float = 10.0,
        max_retries: int = 2,
    ) -> None:
        credential = app_password if app_password is not None else password
        self.connection = PiHole6Connection(
            base_url,
            credential,
            ca_bundle_path=ca_bundle_path,
            verify_tls=verify_tls,
            timeout=timeout,
            max_retries=max_retries,
        )
        self.metrics = PiHole6Metrics(self.connection)
        self.dns_control = PiHole6DnsControl(self.connection)
        self.group_management = PiHole6GroupManagement(self.connection)
        self.domain_management = PiHole6DomainManagement(self.connection)
        self.client_management = PiHole6ClientManagement(self.connection)
        self.list_management = PiHole6ListManagement(self.connection)
        self.ftl_info = PiHole6FtlInfo(self.connection)
        self.config = PiHole6Configuration(self.connection)
        self.network_info = PiHole6NetworkInfo(self.connection)
        self.actions = PiHole6Actions(self.connection)
        self.dhcp = PiHole6Dhcp(self.connection)

    def __enter__(self) -> PiHole6Client:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def get_padd_summary(self, full: bool = False):
        return self.connection.get("padd", params={"full": str(full).lower()})

    def close(self) -> None:
        self.connection.close()

    def close_session(self) -> None:
        self.connection.close_session()
