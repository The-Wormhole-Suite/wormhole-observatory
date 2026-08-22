from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

from pihole_manager.config import PiHoleOptions, app_directory
from pihole_manager.credentials import (
    CredentialReadState,
    _delete_secret,
    _read_secret,
    _write_secret,
)

REGISTRY_SCHEMA_VERSION = 1
_REGISTRY_LOCK = threading.RLock()


@dataclass(slots=True)
class PiHoleInstance:
    instance_id: str = field(default_factory=lambda: f"pihole-{uuid4().hex}")
    name: str = "Primary Pi-hole"
    base_url: str = "http://pi.hole"
    password: str = ""
    verify_tls: bool = True
    timeout_sec: float = 10.0


@dataclass(slots=True)
class PiHoleInstanceRegistry:
    schema_version: int = REGISTRY_SCHEMA_VERSION
    active_instance_id: str = ""
    instances: list[PiHoleInstance] = field(default_factory=list)

    def active(self) -> PiHoleInstance:
        for instance in self.instances:
            if instance.instance_id == self.active_instance_id:
                return instance
        if not self.instances:
            raise RuntimeError("Pi-hole instance registry is empty")
        self.active_instance_id = self.instances[0].instance_id
        return self.instances[0]


def registry_path() -> Path:
    return app_directory() / "pihole_instances.json"


def instance_from_options(
    options: PiHoleOptions,
    *,
    instance_id: str | None = None,
    name: str = "Primary Pi-hole",
) -> PiHoleInstance:
    return PiHoleInstance(
        instance_id=instance_id or f"pihole-{uuid4().hex}",
        name=name,
        base_url=str(options.base_url or "http://pi.hole").strip(),
        password=str(options.password or ""),
        verify_tls=bool(options.verify_tls),
        timeout_sec=max(1.0, float(options.timeout_sec)),
    )


def options_from_instance(instance: PiHoleInstance) -> PiHoleOptions:
    return PiHoleOptions(
        base_url=instance.base_url,
        password=instance.password,
        verify_tls=instance.verify_tls,
        timeout_sec=instance.timeout_sec,
    )


def _instance_key(instance_id: str) -> str:
    return f"pihole-instance/{instance_id}/password"


def _normalize_instance(raw: dict[str, Any], index: int, used_ids: set[str]) -> PiHoleInstance:
    instance_id = str(raw.get("instance_id") or "").strip()
    if not instance_id or instance_id in used_ids:
        instance_id = f"pihole-{uuid4().hex}"
    used_ids.add(instance_id)
    name = str(raw.get("name") or f"Pi-hole {index + 1}").strip() or f"Pi-hole {index + 1}"
    base_url = str(raw.get("base_url") or "http://pi.hole").strip() or "http://pi.hole"
    try:
        timeout = max(1.0, float(raw.get("timeout_sec", 10.0)))
    except (TypeError, ValueError):
        timeout = 10.0
    return PiHoleInstance(
        instance_id=instance_id,
        name=name,
        base_url=base_url,
        password=str(raw.get("password") or ""),
        verify_tls=bool(raw.get("verify_tls", True)),
        timeout_sec=timeout,
    )


def _hydrate_password(instance: PiHoleInstance) -> bool:
    key = _instance_key(instance.instance_id)
    plaintext = str(instance.password or "")
    state, stored = _read_secret(key)
    if state is CredentialReadState.PRESENT:
        instance.password = stored
        return bool(plaintext)
    return bool(
        state is CredentialReadState.MISSING
        and plaintext
        and _write_secret(key, plaintext)
    )


def _read_registry(active_options: PiHoleOptions) -> tuple[PiHoleInstanceRegistry, bool]:
    path = registry_path()
    if not path.exists():
        first = instance_from_options(active_options)
        return PiHoleInstanceRegistry(
            active_instance_id=first.instance_id,
            instances=[first],
        ), True
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        first = instance_from_options(active_options)
        return PiHoleInstanceRegistry(
            active_instance_id=first.instance_id,
            instances=[first],
        ), True
    if not isinstance(raw, dict):
        first = instance_from_options(active_options)
        return PiHoleInstanceRegistry(
            active_instance_id=first.instance_id,
            instances=[first],
        ), True
    try:
        schema_version = int(raw.get("schema_version") or 0)
    except (TypeError, ValueError):
        schema_version = 0
    if schema_version > REGISTRY_SCHEMA_VERSION:
        raise RuntimeError(
            "Pi-hole instance registry was created by a newer application version "
            f"(schema {schema_version}; supported up to {REGISTRY_SCHEMA_VERSION})."
        )
    used_ids: set[str] = set()
    instances = [
        _normalize_instance(item, index, used_ids)
        for index, item in enumerate(raw.get("instances") or [])
        if isinstance(item, dict)
    ]
    if not instances:
        instances = [instance_from_options(active_options)]
    active_id = str(raw.get("active_instance_id") or "").strip()
    if active_id not in {item.instance_id for item in instances}:
        active_id = instances[0].instance_id
    registry = PiHoleInstanceRegistry(
        active_instance_id=active_id,
        instances=instances,
    )
    active_url = str(active_options.base_url or "").strip()
    matching_active = next(
        (
            item
            for item in instances
            if item.base_url == active_url
            and item.verify_tls == bool(active_options.verify_tls)
            and item.timeout_sec == max(1.0, float(active_options.timeout_sec))
        ),
        None,
    )
    if matching_active is not None:
        registry.active_instance_id = matching_active.instance_id
        matching_active.password = str(active_options.password or matching_active.password)
    elif len(instances) == 1:
        active = registry.active()
        active.base_url = active_url or active.base_url
        active.password = str(active_options.password or active.password)
        active.verify_tls = bool(active_options.verify_tls)
        active.timeout_sec = max(1.0, float(active_options.timeout_sec))
    return registry, schema_version != REGISTRY_SCHEMA_VERSION


def load_pihole_instances(active_options: PiHoleOptions) -> PiHoleInstanceRegistry:
    with _REGISTRY_LOCK:
        registry, should_rewrite = _read_registry(active_options)
        migrated_secret = False
        for instance in registry.instances:
            migrated_secret = _hydrate_password(instance) or migrated_secret
        if should_rewrite or migrated_secret or not registry_path().exists():
            save_pihole_instances(registry)
        return registry


def _existing_instance_ids() -> set[str]:
    path = registry_path()
    if not path.exists():
        return set()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    if not isinstance(raw, dict):
        return set()
    return {
        str(item.get("instance_id") or "").strip()
        for item in raw.get("instances") or []
        if isinstance(item, dict) and str(item.get("instance_id") or "").strip()
    }


def save_pihole_instances(registry: PiHoleInstanceRegistry) -> None:
    if not registry.instances:
        raise ValueError("At least one Pi-hole instance is required")
    ids = [str(item.instance_id or "").strip() for item in registry.instances]
    if any(not item for item in ids) or len(ids) != len(set(ids)):
        raise ValueError("Pi-hole instance IDs must be non-empty and unique")
    names = [str(item.name or "").strip().casefold() for item in registry.instances]
    if any(not item for item in names) or len(names) != len(set(names)):
        raise ValueError("Pi-hole instance names must be non-empty and unique")
    if registry.active_instance_id not in set(ids):
        raise ValueError("Active Pi-hole instance is not present in the registry")

    payload = {
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "active_instance_id": registry.active_instance_id,
        "instances": [asdict(item) for item in registry.instances],
    }
    for index, instance in enumerate(registry.instances):
        key = _instance_key(instance.instance_id)
        password = str(instance.password or "")
        if password:
            if _write_secret(key, password):
                payload["instances"][index]["password"] = ""
        else:
            _delete_secret(key)
            payload["instances"][index]["password"] = ""

    path = registry_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with _REGISTRY_LOCK:
        removed_ids = _existing_instance_ids() - set(ids)
        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=path.parent, delete=False
            ) as handle:
                json.dump(payload, handle, indent=2, ensure_ascii=False)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
                temp_path = Path(handle.name)
            os.replace(temp_path, path)
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
        for instance_id in removed_ids:
            _delete_secret(_instance_key(instance_id))
