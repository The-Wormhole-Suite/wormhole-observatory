from __future__ import annotations

from datetime import UTC, datetime

from pihole_manager.dev_retention import (
    select_dev_package_version_deletions,
    select_dev_release_deletions,
)

_NOW = datetime(2026, 8, 23, tzinfo=UTC)


def _release(index: int, *, days_old: int, tag: str | None = None, prerelease: bool = True):
    created = datetime.fromtimestamp(_NOW.timestamp() - days_old * 86400, tz=UTC)
    return {
        "id": index,
        "tag_name": tag or f"dev-{index}-abcdef12",
        "prerelease": prerelease,
        "created_at": created.isoformat().replace("+00:00", "Z"),
    }


def _version(index: int, *, days_old: int, tags: list[str]):
    created = datetime.fromtimestamp(_NOW.timestamp() - days_old * 86400, tz=UTC)
    return {
        "id": index,
        "created_at": created.isoformat().replace("+00:00", "Z"),
        "metadata": {"container": {"tags": tags}},
    }


def test_release_cleanup_protects_age_latest_and_non_dev_releases():
    releases = [_release(index, days_old=60 + index) for index in range(1, 13)]
    releases += [
        _release(20, days_old=90, tag="v0.3.6", prerelease=False),
        _release(21, days_old=90, tag="preview-manual", prerelease=True),
        _release(22, days_old=5),
    ]
    deleted = select_dev_release_deletions(releases, now=_NOW, min_age_days=30, keep_latest=10)
    deleted_ids = {item["id"] for item in deleted}
    assert 20 not in deleted_ids
    assert 21 not in deleted_ids
    assert 22 not in deleted_ids
    assert len(deleted_ids) == 3


def test_package_cleanup_only_targets_old_sha_only_versions():
    versions = [
        _version(index, days_old=60 + index, tags=[f"sha-{index:040x}"])
        for index in range(1, 13)
    ]
    versions += [
        _version(20, days_old=100, tags=["0.3.6", "latest", "sha-stable"]),
        _version(21, days_old=100, tags=[]),
        _version(22, days_old=5, tags=["sha-young"]),
        _version(23, days_old=100, tags=["dev", "sha-current"]),
    ]
    deleted = select_dev_package_version_deletions(
        versions,
        now=_NOW,
        min_age_days=30,
        keep_latest=10,
    )
    deleted_ids = {item["id"] for item in deleted}
    assert 20 not in deleted_ids
    assert 21 not in deleted_ids
    assert 22 not in deleted_ids
    assert 23 not in deleted_ids
    assert len(deleted_ids) == 3
