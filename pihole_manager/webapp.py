from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files


@dataclass(frozen=True, slots=True)
class WebAsset:
    content: bytes
    content_type: str
    cache_control: str


_ROUTES: dict[str, tuple[str, str, str]] = {
    "/app/": ("index.html", "text/html; charset=utf-8", "no-cache"),
    "/app/app.css": ("app.css", "text/css; charset=utf-8", "public, max-age=3600"),
    "/app/app.js": ("app.js", "text/javascript; charset=utf-8", "public, max-age=3600"),
    "/app/icon.svg": ("icon.svg", "image/svg+xml", "public, max-age=86400"),
    "/manifest.webmanifest": (
        "manifest.webmanifest",
        "application/manifest+json; charset=utf-8",
        "public, max-age=3600",
    ),
    "/sw.js": ("sw.js", "text/javascript; charset=utf-8", "no-cache"),
}


def get_web_asset(path: str) -> WebAsset | None:
    definition = _ROUTES.get(path)
    if definition is None:
        return None
    filename, content_type, cache_control = definition
    try:
        content = files("pihole_manager").joinpath("webapp", filename).read_bytes()
    except (FileNotFoundError, OSError):
        return None
    return WebAsset(content, content_type, cache_control)
