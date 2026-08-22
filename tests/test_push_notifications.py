from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from pihole_manager import credentials, push_notifications
from pihole_manager.push_notifications import (
    PushNotificationOptions,
    build_review_link,
    load_push_options,
    save_push_options,
    send_ntfy,
    send_unifiedpush,
)


class FakeKeyring:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, key: str):
        return self.values.get((service, key))

    def set_password(self, service: str, key: str, value: str) -> None:
        self.values[(service, key)] = value

    def delete_password(self, service: str, key: str) -> None:
        self.values.pop((service, key), None)


def test_push_secrets_are_stored_in_keyring(monkeypatch, tmp_path) -> None:
    fake = FakeKeyring()
    monkeypatch.setenv("PIHOLE_MANAGER_HOME", str(tmp_path))
    monkeypatch.setattr(credentials, "_keyring_module", lambda: fake)

    options = PushNotificationOptions(
        ntfy_enabled=True,
        ntfy_topic="wormhole-test",
        ntfy_token="ntfy-secret",
        unifiedpush_enabled=True,
        unifiedpush_endpoint="https://push.example.test/subscription",
        unifiedpush_p256dh="public-key",
        unifiedpush_auth="auth-secret",
        review_base_url="https://review.example.test/app/",
    )
    save_push_options(options)

    raw = json.loads(push_notifications.push_options_path().read_text(encoding="utf-8"))
    assert raw["ntfy_token"] == ""
    assert raw["unifiedpush_endpoint"] == ""
    assert raw["unifiedpush_auth"] == ""
    assert raw["unifiedpush_vapid_private_key"] == ""
    assert fake.get_password(credentials.SERVICE_NAME, "push/ntfy_token") == "ntfy-secret"
    assert fake.get_password(
        credentials.SERVICE_NAME, "push/unifiedpush_endpoint"
    ) == "https://push.example.test/subscription"
    assert fake.get_password(credentials.SERVICE_NAME, "push/unifiedpush_auth") == "auth-secret"
    assert fake.get_password(
        credentials.SERVICE_NAME, "push/unifiedpush_vapid_private_key"
    )

    loaded = load_push_options()
    assert loaded.ntfy_token == "ntfy-secret"
    assert loaded.unifiedpush_endpoint == "https://push.example.test/subscription"
    assert loaded.unifiedpush_auth == "auth-secret"
    assert loaded.unifiedpush_vapid_private_key


def test_build_review_link_normalizes_domain_and_preserves_query() -> None:
    link = build_review_link("https://review.example.test/app?mode=compact", "EXAMPLE.COM.")
    assert link == "https://review.example.test/app/?mode=compact&domain=example.com"


def test_ntfy_uses_json_publish_and_click_deep_link(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class Response:
        def raise_for_status(self) -> None:
            return None

    def post(url: str, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return Response()

    monkeypatch.setattr(push_notifications.requests, "post", post)
    options = PushNotificationOptions(
        ntfy_enabled=True,
        ntfy_base_url="https://ntfy.example.test",
        ntfy_topic="wormhole",
        ntfy_token="secret",
        review_base_url="https://review.example.test/app/",
    )

    send_ntfy(options, "Review", "Unicode ✓", domain="Example.COM")

    assert captured["url"] == "https://ntfy.example.test/"
    assert captured["headers"] == {"Authorization": "Bearer secret"}
    payload = captured["json"]
    assert isinstance(payload, dict)
    assert payload["topic"] == "wormhole"
    assert payload["message"] == "Unicode ✓"
    assert payload["click"] == "https://review.example.test/app/?domain=example.com"
    assert payload["cache"] is False


def test_unifiedpush_encrypts_webpush_payload_with_deep_link(monkeypatch) -> None:
    captured: dict[str, object] = {}
    private_key = push_notifications._generate_vapid_private_key()

    monkeypatch.setattr(
        push_notifications,
        "_validate_unifiedpush_endpoint",
        lambda endpoint, allow_private: None,
    )

    def fake_webpush(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(status_code=201)

    monkeypatch.setattr(push_notifications, "webpush", fake_webpush)
    options = PushNotificationOptions(
        unifiedpush_enabled=True,
        unifiedpush_endpoint="https://push.example.test/subscription",
        unifiedpush_p256dh="p256dh",
        unifiedpush_auth="auth",
        unifiedpush_vapid_private_key=private_key,
        unifiedpush_vapid_subject="mailto:test@example.test",
        review_base_url="https://review.example.test/app/",
    )

    send_unifiedpush(options, "Review", "Check domain", domain="tracker.example")

    assert captured["subscription_info"] == {
        "endpoint": "https://push.example.test/subscription",
        "keys": {"p256dh": "p256dh", "auth": "auth"},
    }
    assert captured["content_encoding"] == "aes128gcm"
    assert captured["vapid_private_key"] == private_key
    assert captured["vapid_claims"] == {"sub": "mailto:test@example.test"}
    payload = json.loads(str(captured["data"]))
    assert payload["domain"] == "tracker.example"
    assert payload["url"] == "https://review.example.test/app/?domain=tracker.example"


def test_unifiedpush_rejects_private_endpoint_without_opt_in(monkeypatch) -> None:
    monkeypatch.setattr(
        push_notifications.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, None, ("192.168.1.20", 443))],
    )
    options = PushNotificationOptions(
        unifiedpush_enabled=True,
        unifiedpush_endpoint="https://push.internal/subscription",
        unifiedpush_p256dh="p256dh",
        unifiedpush_auth="auth",
        unifiedpush_vapid_private_key=push_notifications._generate_vapid_private_key(),
        review_base_url="https://review.example.test/app/",
    )

    with pytest.raises(ValueError, match="non-global"):
        send_unifiedpush(options, "Review", "Check domain")
