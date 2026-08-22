from __future__ import annotations

import json

from pihole_manager import credentials
from pihole_manager.config import PiHoleOptions
from pihole_manager.pihole_instances import (
    PiHoleInstance,
    PiHoleInstanceRegistry,
    load_pihole_instances,
    options_from_instance,
    registry_path,
    save_pihole_instances,
)


class FakeKeyring:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}
        self.deleted: list[tuple[str, str]] = []
        self.fail = False

    def get_password(self, service: str, key: str):
        if self.fail:
            raise RuntimeError("backend unavailable")
        return self.values.get((service, key))

    def set_password(self, service: str, key: str, value: str) -> None:
        if self.fail:
            raise RuntimeError("backend unavailable")
        self.values[(service, key)] = value

    def delete_password(self, service: str, key: str) -> None:
        if self.fail:
            raise RuntimeError("backend unavailable")
        self.deleted.append((service, key))
        self.values.pop((service, key), None)


def test_missing_registry_migrates_current_pihole(monkeypatch, tmp_path) -> None:
    fake = FakeKeyring()
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    monkeypatch.setattr(credentials, "_keyring_module", lambda: fake)
    active = PiHoleOptions(
        base_url="https://home-pihole.local",
        password="home-secret",
        verify_tls=False,
        timeout_sec=7.0,
    )

    registry = load_pihole_instances(active)

    assert len(registry.instances) == 1
    instance = registry.active()
    assert instance.name == "Primary Pi-hole"
    assert instance.base_url == "https://home-pihole.local"
    assert instance.password == "home-secret"
    raw = json.loads(registry_path().read_text(encoding="utf-8"))
    assert raw["schema_version"] == 1
    assert raw["instances"][0]["password"] == ""
    key = f"pihole-instance/{instance.instance_id}/password"
    assert fake.get_password(credentials.SERVICE_NAME, key) == "home-secret"


def test_multiple_instances_round_trip_with_distinct_credentials(monkeypatch, tmp_path) -> None:
    fake = FakeKeyring()
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    monkeypatch.setattr(credentials, "_keyring_module", lambda: fake)
    home = PiHoleInstance(
        instance_id="home",
        name="Home",
        base_url="http://home.local",
        password="home-secret",
    )
    office = PiHoleInstance(
        instance_id="office",
        name="Office",
        base_url="https://office.local",
        password="office-secret",
        timeout_sec=15.0,
    )
    save_pihole_instances(
        PiHoleInstanceRegistry(active_instance_id="office", instances=[home, office])
    )

    registry = load_pihole_instances(options_from_instance(office))

    assert registry.active_instance_id == "office"
    assert [item.name for item in registry.instances] == ["Home", "Office"]
    assert [item.password for item in registry.instances] == [
        "home-secret",
        "office-secret",
    ]
    assert fake.get_password(
        credentials.SERVICE_NAME, "pihole-instance/home/password"
    ) == "home-secret"
    assert fake.get_password(
        credentials.SERVICE_NAME, "pihole-instance/office/password"
    ) == "office-secret"


def test_removing_instance_deletes_its_stored_password(monkeypatch, tmp_path) -> None:
    fake = FakeKeyring()
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    monkeypatch.setattr(credentials, "_keyring_module", lambda: fake)
    home = PiHoleInstance(instance_id="home", name="Home", password="home-secret")
    office = PiHoleInstance(instance_id="office", name="Office", password="office-secret")
    save_pihole_instances(
        PiHoleInstanceRegistry(active_instance_id="home", instances=[home, office])
    )

    save_pihole_instances(
        PiHoleInstanceRegistry(active_instance_id="home", instances=[home])
    )

    removed = (credentials.SERVICE_NAME, "pihole-instance/office/password")
    assert removed in fake.deleted
    assert removed not in fake.values


def test_plaintext_fallback_survives_unavailable_keyring(monkeypatch, tmp_path) -> None:
    fake = FakeKeyring()
    fake.fail = True
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    monkeypatch.setattr(credentials, "_keyring_module", lambda: fake)
    instance = PiHoleInstance(
        instance_id="home",
        name="Home",
        password="must-not-be-lost",
    )

    save_pihole_instances(
        PiHoleInstanceRegistry(active_instance_id="home", instances=[instance])
    )

    raw = json.loads(registry_path().read_text(encoding="utf-8"))
    assert raw["instances"][0]["password"] == "must-not-be-lost"


def test_registry_rejects_duplicate_names(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    first = PiHoleInstance(instance_id="one", name="Same")
    second = PiHoleInstance(instance_id="two", name="same")

    try:
        save_pihole_instances(
            PiHoleInstanceRegistry(active_instance_id="one", instances=[first, second])
        )
    except ValueError as exc:
        assert "names" in str(exc)
    else:
        raise AssertionError("duplicate Pi-hole instance names must be rejected")
