from __future__ import annotations

import json

from pihole_manager import credentials
from pihole_manager.config import load_options, options_path, save_options


class FakeKeyring:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, key: str):
        return self.values.get((service, key))

    def set_password(self, service: str, key: str, value: str) -> None:
        self.values[(service, key)] = value

    def delete_password(self, service: str, key: str) -> None:
        self.values.pop((service, key), None)


def test_secrets_are_saved_in_keyring_and_removed_from_json(monkeypatch, tmp_path) -> None:
    fake = FakeKeyring()
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    monkeypatch.setattr(credentials, "_keyring_module", lambda: fake)

    options = load_options()
    options.pihole.password = "pihole-secret"
    options.llm_providers[0].api_key = "llm-secret"
    options.research_providers[0].api_key = "research-secret"
    provider_id = options.llm_providers[0].provider_id
    research_kind = options.research_providers[0].kind

    save_options(options)

    raw = json.loads(options_path().read_text(encoding="utf-8"))
    assert raw["pihole"]["password"] == ""
    assert raw["llm_providers"][0]["api_key"] == ""
    assert raw["research_providers"][0]["api_key"] == ""
    assert fake.get_password(credentials.SERVICE_NAME, "pihole/password") == "pihole-secret"
    assert (
        fake.get_password(credentials.SERVICE_NAME, f"llm/{provider_id}/api_key")
        == "llm-secret"
    )
    assert (
        fake.get_password(credentials.SERVICE_NAME, f"research/{research_kind}/api_key")
        == "research-secret"
    )

    loaded = load_options()
    assert loaded.pihole.password == "pihole-secret"
    assert loaded.llm_providers[0].api_key == "llm-secret"
    assert loaded.research_providers[0].api_key == "research-secret"


def test_legacy_plaintext_secret_is_migrated_and_scrubbed(monkeypatch, tmp_path) -> None:
    fake = FakeKeyring()
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    monkeypatch.setattr(credentials, "_keyring_module", lambda: fake)
    options_path().write_text(
        json.dumps(
            {
                "schema_version": 17,
                "pihole": {"password": "legacy-secret"},
            }
        ),
        encoding="utf-8",
    )

    options = load_options()

    assert options.pihole.password == "legacy-secret"
    assert fake.get_password(credentials.SERVICE_NAME, "pihole/password") == "legacy-secret"
    raw = json.loads(options_path().read_text(encoding="utf-8"))
    assert raw["pihole"]["password"] == ""


def test_plaintext_is_preserved_when_keyring_backend_is_unavailable(monkeypatch, tmp_path) -> None:
    class BrokenKeyring:
        def get_password(self, service: str, key: str):
            raise RuntimeError("backend unavailable")

        def set_password(self, service: str, key: str, value: str) -> None:
            raise RuntimeError("backend unavailable")

        def delete_password(self, service: str, key: str) -> None:
            raise RuntimeError("backend unavailable")

    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    monkeypatch.setattr(credentials, "_keyring_module", lambda: BrokenKeyring())

    options = load_options()
    options.pihole.password = "must-not-be-lost"
    save_options(options)

    raw = json.loads(options_path().read_text(encoding="utf-8"))
    assert raw["pihole"]["password"] == "must-not-be-lost"
