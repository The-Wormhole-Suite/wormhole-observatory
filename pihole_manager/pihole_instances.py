from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pihole6api.connection import PiHole6Connection

from .config import AppOptions, PiHoleOptions

DEFAULT_INSTANCE_ID = "default"


@dataclass
class PiHoleInstance:
    instance_id: str
    name: str
    base_url: str
    password: str = ""
    verify_tls: bool = True
    timeout_sec: int = 10

    def normalized_name(self) -> str:
        return self.name.strip() or self.base_url.strip() or self.instance_id


def normalize_instance_id(value: str) -> str:
    cleaned = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(value or "").strip())
    cleaned = "-".join(part for part in cleaned.split("-") if part)
    return cleaned[:64]


def derived_instance_id(base_url: str, name: str = "") -> str:
    parsed = urlsplit(str(base_url or "").strip())
    candidate = normalize_instance_id(name or parsed.hostname or "")
    if candidate:
        return candidate
    digest = hashlib.sha256(str(base_url or "").encode("utf-8")).hexdigest()[:12]
    return f"instance-{digest}"


def instance_from_options(options: PiHoleOptions, *, name: str = "Primary Pi-hole") -> PiHoleInstance:
    return PiHoleInstance(
        instance_id=DEFAULT_INSTANCE_ID,
        name=name,
        base_url=str(options.base_url or "").strip(),
        password=str(options.password or ""),
        verify_tls=True,
        timeout_sec=max(1, int(options.timeout_sec or 10)),
    )


def build_connection(instance: PiHoleInstance) -> PiHole6Connection:
    return PiHole6Connection(
        instance.base_url,
        instance.password,
        verify_tls=instance.verify_tls,
        timeout=instance.timeout_sec,
    )


def _parse_instance(raw: dict[str, Any]) -> PiHoleInstance | None:
    base_url = str(raw.get("base_url") or "").strip()
    if not base_url:
        return None
    name = str(raw.get("name") or "").strip()
    instance_id = normalize_instance_id(str(raw.get("instance_id") or ""))
    if not instance_id:
        instance_id = derived_instance_id(base_url, name)
    return PiHoleInstance(
        instance_id=instance_id,
        name=name or base_url,
        base_url=base_url,
        password=str(raw.get("password") or ""),
        verify_tls=True,
        timeout_sec=max(1, int(raw.get("timeout_sec") or 10)),
    )


def load_instances(options: AppOptions, home: Path) -> list[PiHoleInstance]:
    instances = [instance_from_options(options.pihole)]
    path = home / "pihole_instances.json"
    if not path.exists():
        return instances
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return instances
    raw_items = payload.get("instances") if isinstance(payload, dict) else None
    if not isinstance(raw_items, list):
        return instances
    seen = {DEFAULT_INSTANCE_ID}
    for raw in raw_items:
        if not isinstance(raw, dict):
            continue
        instance = _parse_instance(raw)
        if instance is None or instance.instance_id in seen:
            continue
        seen.add(instance.instance_id)
        instances.append(instance)
    return instances


def save_instances(instances: list[PiHoleInstance], home: Path) -> None:
    home.mkdir(parents=True, exist_ok=True)
    path = home / "pihole_instances.json"
    payload = {
        "version": 1,
        "instances": [asdict(instance) for instance in instances if instance.instance_id != DEFAULT_INSTANCE_ID],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def sync_active_instance(options: AppOptions, instances: list[PiHoleInstance]) -> None:
    active_options = options.pihole
    active = next((item for item in instances if item.instance_id == DEFAULT_INSTANCE_ID), None)
    if active is None:
        active = instance_from_options(active_options)
        instances.insert(0, active)
    active.base_url = str(active_options.base_url or "").strip()
    active.password = str(active_options.password or "")
    active.verify_tls = True
    active.timeout_sec = max(1, int(active_options.timeout_sec or 10))


def find_matching_instance(
    instances: list[PiHoleInstance],
    active_options: PiHoleOptions,
) -> PiHoleInstance | None:
    for item in instances:
        if (
            item.base_url == str(active_options.base_url or "").strip()
            and item.password == str(active_options.password or "")
            and item.verify_tls is True
            and item.timeout_sec == max(1, int(active_options.timeout_sec or 10))
        ):
            return item
    return None
