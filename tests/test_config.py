from __future__ import annotations

import json

import pytest

from pihole_manager.config import (
    UnsupportedConfigVersionError,
    load_options,
    options_path,
    save_options,
)


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
                "locks": {"enabled": True, "reconcile_interval_sec": 15},
                "prompt_profiles": [
                    {"name": "one", "system": "s", "user_template": "{domain}"},
                    {"name": "two", "system": "s", "user_template": "{domain}"},
                ],
            }
        ),
        encoding="utf-8",
    )

    options = load_options()

    assert options.schema_version == 16
    assert options.ui.table_visible_columns["review"][1:3] == ["order", "queued"]
    assert options.pihole.base_url == "https://pi.hole/admin"
    assert options.pihole.password == "application-password"
    assert options.pihole.verify_tls is False
    assert options.logging.enabled is False
    assert options.logging.filename == "legacy.log"
    assert options.scans.batch_size == 42
    assert options.llm.batch_size == 7
    assert options.llm.active_profile_index == 1
    assert not hasattr(options, "locks")
    save_options(options)
    assert "locks" not in json.loads(options_path().read_text(encoding="utf-8"))


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
    assert json.loads(options_path().read_text(encoding="utf-8"))["schema_version"] == 16


def test_table_column_preferences_round_trip(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    options = load_options()
    options.ui.table_visible_columns["lists"] = ["domain", "tags"]
    options.ui.table_column_widths["lists"]["domain"] = 444

    save_options(options)
    loaded = load_options()

    assert loaded.ui.table_visible_columns["lists"] == ["domain", "tags"]
    assert loaded.ui.table_column_widths["lists"]["domain"] == 444
    assert "comment" not in loaded.ui.table_visible_columns["lists"]


def test_legacy_research_master_switch_disables_sources(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    options_path().write_text(
        json.dumps(
            {
                "research": {"enabled": False, "run_before_llm": True},
                "research_providers": [{"name": "RDAP", "kind": "rdap", "enabled": True}],
            }
        ),
        encoding="utf-8",
    )

    options = load_options()

    assert options.research_providers[0].enabled is False
    assert options.ui.show_tooltips is True
    assert options.llm.tag_recheck_days["unknown"] == 3


def test_unstructured_research_sources_are_removed_during_migration(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    options_path().write_text(
        json.dumps(
            {
                "schema_version": 7,
                "research_providers": [
                    {"name": "RDAP", "kind": "rdap", "enabled": True},
                    {"name": "GitHub", "kind": "github_code", "enabled": True},
                    {"name": "Brave", "kind": "brave_search", "enabled": True},
                    {"name": "VirusTotal", "kind": "virustotal", "enabled": False},
                ],
            }
        ),
        encoding="utf-8",
    )

    options = load_options()

    kinds = [provider.kind for provider in options.research_providers]
    assert "github_code" not in kinds
    assert "brave_search" not in kinds
    assert "rdap" in kinds
    assert "virustotal" in kinds
    assert "adguard_services" in kinds


def test_legacy_prerelease_setting_migrates_to_update_channel(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    options_path().write_text(
        json.dumps(
            {
                "schema_version": 12,
                "updates": {
                    "check_automatically": True,
                    "include_prereleases": True,
                    "check_interval_hours": 6,
                },
            }
        ),
        encoding="utf-8",
    )

    options = load_options()

    assert options.updates.channel == "prerelease"
    save_options(options)
    saved = json.loads(options_path().read_text(encoding="utf-8"))
    assert "include_prereleases" not in saved["updates"]
    assert saved["updates"]["channel"] == "prerelease"


def test_development_update_channel_migrates_to_prerelease(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    options_path().write_text(
        json.dumps({"updates": {"channel": "development"}}),
        encoding="utf-8",
    )

    options = load_options()

    assert options.updates.channel == "prerelease"


def test_default_queue_filter_excludes_arpa(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))

    options = load_options()

    assert options.scans.excluded_domain_suffixes == [".arpa"]
    rdap = next(item for item in options.research_providers if item.kind == "rdap")
    assert rdap.base_url == "https://data.iana.org/rdap/dns.json"


def test_malformed_option_values_fall_back_without_losing_valid_sections(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    options_path().write_text(
        json.dumps(
            {
                "pihole": {"base_url": "https://dns.example", "timeout_sec": "invalid"},
                "scans": "invalid section",
                "notify": {"rate_limit_sec": "invalid", "enable_sound": "false"},
                "llm": {"max_retries": "invalid"},
            }
        ),
        encoding="utf-8",
    )

    options = load_options()

    assert options.pihole.base_url == "https://dns.example"
    assert options.pihole.timeout_sec == 10.0
    assert options.scans.batch_size == 200
    assert options.notify.rate_limit_sec == 5
    assert options.notify.enable_sound is False
    assert options.llm.max_retries == 2


def test_invalid_ui_values_are_normalized(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    options_path().write_text(
        json.dumps(
            {
                "ui": {
                    "theme": "neon",
                    "show_tooltips": "false",
                    "evidence_test_skip_api_key_sources": "true",
                    "evidence_test_skip_missing_api_keys": "invalid",
                }
            }
        ),
        encoding="utf-8",
    )

    options = load_options()

    assert options.ui.theme == "system"
    assert options.ui.show_tooltips is False
    assert options.ui.evidence_test_skip_api_key_sources is True
    assert options.ui.evidence_test_skip_missing_api_keys is True


def test_newer_configuration_schema_is_rejected(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    options_path().write_text(
        json.dumps({"schema_version": 999}),
        encoding="utf-8",
    )

    with pytest.raises(UnsupportedConfigVersionError, match="newer Pi-hole Manager"):
        load_options()
