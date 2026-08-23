from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from pihole_manager.dev_retention import (
    select_dev_package_version_deletions,
    select_dev_release_deletions,
)


class GitHubApi:
    def __init__(self, token: str, api_url: str = "https://api.github.com") -> None:
        self.token = token
        self.api_url = api_url.rstrip("/")

    def _request(self, path: str, *, method: str = "GET") -> tuple[Any, dict[str, str]]:
        request = urllib.request.Request(
            f"{self.api_url}{path}",
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "wormhole-observatory-dev-retention",
            },
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
            payload = json.loads(body) if body else None
            return payload, dict(response.headers.items())

    def list_all(self, path: str) -> list[dict[str, Any]]:
        page = 1
        items: list[dict[str, Any]] = []
        while True:
            separator = "&" if "?" in path else "?"
            payload, _ = self._request(f"{path}{separator}per_page=100&page={page}")
            batch = list(payload or [])
            items.extend(batch)
            if len(batch) < 100:
                return items
            page += 1

    def delete(self, path: str, *, ignore_missing: bool = False) -> None:
        try:
            self._request(path, method="DELETE")
        except urllib.error.HTTPError as exc:
            if ignore_missing and exc.code in {404, 422}:
                return
            raise


def _positive_int(name: str, default: int) -> int:
    try:
        return max(0, int(os.getenv(name, str(default))))
    except ValueError as exc:
        raise SystemExit(f"{name} must be an integer") from exc


def _delete_releases(api: GitHubApi, repository: str, *, dry_run: bool) -> int:
    releases = api.list_all(f"/repos/{repository}/releases")
    selected = select_dev_release_deletions(
        releases,
        now=datetime.now(timezone.utc),
        min_age_days=_positive_int("DEV_RETENTION_DAYS", 30),
        keep_latest=_positive_int("DEV_RETENTION_KEEP", 10),
    )
    for item in selected:
        tag = str(item["tag_name"])
        print(f"delete dev prerelease: {tag}")
        if dry_run:
            continue
        api.delete(f"/repos/{repository}/releases/{int(item['id'])}")
        encoded = urllib.parse.quote(tag, safe="")
        api.delete(f"/repos/{repository}/git/refs/tags/{encoded}", ignore_missing=True)
    return len(selected)


def _delete_packages(api: GitHubApi, owner: str, package: str, *, dry_run: bool) -> int:
    encoded_package = urllib.parse.quote(package, safe="")
    path = f"/orgs/{owner}/packages/container/{encoded_package}/versions"
    versions = api.list_all(path)
    selected = select_dev_package_version_deletions(
        versions,
        now=datetime.now(timezone.utc),
        min_age_days=_positive_int("DEV_RETENTION_DAYS", 30),
        keep_latest=_positive_int("DEV_RETENTION_KEEP", 10),
    )
    for item in selected:
        version_id = int(item["id"])
        print(f"delete superseded dev container version: {version_id}")
        if not dry_run:
            api.delete(f"{path}/{version_id}")
    return len(selected)


def main() -> int:
    parser = argparse.ArgumentParser(description="Clean old Wormhole development builds safely.")
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--releases-only", action="store_true")
    scope.add_argument("--packages-only", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    token = os.getenv("GITHUB_TOKEN", "").strip()
    repository = os.getenv("GITHUB_REPOSITORY", "").strip()
    if not token or "/" not in repository:
        raise SystemExit("GITHUB_TOKEN and GITHUB_REPOSITORY are required")
    owner, package = repository.split("/", 1)
    api = GitHubApi(token, os.getenv("GITHUB_API_URL", "https://api.github.com"))

    deleted = 0
    if not args.packages_only:
        deleted += _delete_releases(api, repository, dry_run=args.dry_run)
    if not args.releases_only:
        deleted += _delete_packages(api, owner, package, dry_run=args.dry_run)
    print(f"cleanup candidates processed: {deleted}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
