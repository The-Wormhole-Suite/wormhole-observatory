from __future__ import annotations

from pihole_manager.webapp import get_web_asset


def test_pwa_exposes_all_review_decisions() -> None:
    asset = get_web_asset("/app/app.js")
    assert asset is not None
    script = asset.content.decode("utf-8")
    assert 'decisionButton("Allow", "allow"' in script
    assert 'decisionButton("Deny", "deny"' in script
    assert 'decisionButton("Ignore", "ignore"' in script
    assert '"postpone"' in script
    assert '"never_ask"' in script
    assert '/decision`' in script
