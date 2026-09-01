from __future__ import annotations

from pihole_manager.webapp import get_web_asset


def test_pwa_deep_link_is_integrated_into_main_app() -> None:
    asset = get_web_asset("/app/app.js")
    assert asset is not None
    script = asset.content.decode("utf-8")
    assert "deepLinkDomain" in script
    assert "/v1/reviews/${encodeURIComponent(domain)}" in script
    assert 'searchParams.delete("domain")' in script


def test_obsolete_deep_link_asset_is_not_served() -> None:
    assert get_web_asset("/app/deep-link.js") is None
