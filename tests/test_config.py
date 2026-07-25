from __future__ import annotations

import json

from pihole_manager.config import load_options, options_path, save_options


def test_legacy_configuration_is_migrated(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    options_path().write_text(
        json.dumps(
            {
                "pihole": {
                    "host": "https://pi.hole/admin",
                    "app_password": "application-password",
                    "verify_tls": False,
                },
                "logging": {"to_file": False, "file": "legacy.log"},
                "scans": {"batch": 42},
                "llm": {"profile_active_index": 1, "batch": 7},
                "prompt_profiles": [
                    {"name": "one", "system": "s", "user_template": "{domain}"},
                    {"name": "two", "system": "s", "user_template": "{domain}"},
                ],
            }
        ),
        encoding="utf-8",
    )

    options = load_options()

    assert options.schema_version == 2
    assert options.pihole.base_url == "https://pi.hole/admin"
    assert options.pihole.password == "application-password"
    assert options.pihole.verify_tls is False
    assert options.logging.enabled is False
    assert options.logging.filename == "legacy.log"
    assert options.scans.batch_size == 42
    assert options.llm.batch_size == 7
    assert options.llm.active_profile_index == 1


def test_save_options_is_valid_and_round_trips(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    options = load_options()
    options.pihole.base_url = "http://dns.local"
    options.llm.categories = ["Tracker", "tracker", ""]
    options.logging.level = "invalid"

    save_options(options)
    loaded = load_options()

    assert loaded.pihole.base_url == "http://dns.local"
    assert loaded.llm.categories == ["tracker"]
    assert loaded.logging.level == "INFO"
    assert json.loads(options_path().read_text(encoding="utf-8"))["schema_version"] == 2
