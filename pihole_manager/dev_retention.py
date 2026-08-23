from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def select_dev_release_deletions(
    releases: list[dict[str, Any]],
    *,
    now: datetime,
    min_age_days: int = 30,
    keep_latest: int = 10,
) -> list[dict[str, Any]]:
    candidates = [
        item
        for item in releases
        if bool(item.get("prerelease")) and str(item.get("tag_name") or "").startswith("dev-")
    ]
    candidates.sort(key=lambda item: _timestamp(str(item["created_at"])), reverse=True)
    protected_ids = {int(item["id"]) for item in candidates[: max(0, keep_latest)]}
    cutoff = now.astimezone(timezone.utc) - timedelta(days=max(0, min_age_days))
    return [
        item
        for item in candidates
        if int(item["id"]) not in protected_ids
        and _timestamp(str(item["created_at"])) < cutoff
    ]


def _container_tags(version: dict[str, Any]) -> list[str]:
    metadata = version.get("metadata") or {}
    container = metadata.get("container") or {}
    return [str(tag) for tag in container.get("tags") or []]


def select_dev_package_version_deletions(
    versions: list[dict[str, Any]],
    *,
    now: datetime,
    min_age_days: int = 30,
    keep_latest: int = 10,
) -> list[dict[str, Any]]:
    # Only sha-* tagged versions are safe to identify as superseded development manifests.
    # Untagged package versions are deliberately left alone because their origin is ambiguous.
    candidates = []
    for item in versions:
        tags = _container_tags(item)
        if tags and all(tag.startswith("sha-") for tag in tags):
            candidates.append(item)
    candidates.sort(key=lambda item: _timestamp(str(item["created_at"])), reverse=True)
    protected_ids = {int(item["id"]) for item in candidates[: max(0, keep_latest)]}
    cutoff = now.astimezone(timezone.utc) - timedelta(days=max(0, min_age_days))
    return [
        item
        for item in candidates
        if int(item["id"]) not in protected_ids
        and _timestamp(str(item["created_at"])) < cutoff
    ]
