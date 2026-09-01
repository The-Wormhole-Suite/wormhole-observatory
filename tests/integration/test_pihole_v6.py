from __future__ import annotations

import os
import uuid

import pytest

from pihole6api.client import PiHole6Client

BASE_URL = os.getenv("PIHOLE_INTEGRATION_URL", "").strip()
PASSWORD = os.getenv("PIHOLE_INTEGRATION_PASSWORD", "")
EXPECTED_FTL_MINOR = os.getenv("PIHOLE_EXPECTED_FTL_MINOR", "").strip()

pytestmark = pytest.mark.skipif(
    not BASE_URL,
    reason="Pi-hole integration target is not configured",
)


def _local_ftl_version(payload: object) -> str:
    assert isinstance(payload, dict)
    version = payload.get("version")
    assert isinstance(version, dict)
    ftl = version.get("ftl")
    assert isinstance(ftl, dict)

    # Pi-hole v6 exposes the local component under ftl.local. Keep support for
    # early v6 response fixtures that exposed version directly below ftl.
    local = ftl.get("local")
    value = local.get("version") if isinstance(local, dict) else ftl.get("version")
    assert isinstance(value, str) and value
    return value.removeprefix("v")


def test_real_pihole_v6_api_contract() -> None:
    marker_domain = f"wormhole-ci-{uuid.uuid4().hex[:12]}.invalid"

    with PiHole6Client(
        BASE_URL,
        PASSWORD,
        timeout=15,
        max_retries=2,
    ) as client:
        version_payload = client.ftl_info.get_version()
        ftl_version = _local_ftl_version(version_payload)
        if EXPECTED_FTL_MINOR:
            assert (
                ftl_version.startswith(EXPECTED_FTL_MINOR + ".")
                or ftl_version == EXPECTED_FTL_MINOR
            )

        endpoints = client.ftl_info.get_endpoints()
        assert isinstance(endpoints, dict)

        blocking = client.dns_control.get_blocking_status()
        assert isinstance(blocking, dict)
        assert "blocking" in blocking

        created = False
        try:
            add_result = client.domain_management.add_domain(
                marker_domain,
                "allow",
                "exact",
                comment="Wormhole Observatory integration test",
            )
            created = True
            assert isinstance(add_result, dict)

            get_result = client.domain_management.get_domain(
                marker_domain,
                "allow",
                "exact",
            )
            assert isinstance(get_result, dict)
            domains = get_result.get("domains")
            assert isinstance(domains, list)
            assert any(
                isinstance(item, dict) and item.get("domain") == marker_domain
                for item in domains
            )
        finally:
            if created:
                client.domain_management.delete_domain(
                    marker_domain,
                    "allow",
                    "exact",
                )
