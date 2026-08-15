from __future__ import annotations

from pihole_manager.pihole_service import _extract_version


def test_extract_version_understands_real_v6_component_shape() -> None:
    payload = {
        "version": {
            "core": {"local": {"version": "v6.4.3"}},
            "web": {"local": {"version": "v6.5"}},
            "ftl": {"local": {"version": "v6.6.2"}},
        }
    }

    assert _extract_version(payload) == "v6.6.2"
