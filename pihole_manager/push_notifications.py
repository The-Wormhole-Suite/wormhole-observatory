from __future__ import annotations

import base64
import ipaddress
import json
import logging
import os
import socket
import threading
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pywebpush import WebPushException, webpush

from pihole_manager.config import options_path
from pihole_manager.credentials import (
    CredentialReadState,
    _delete_secret,
    _read_secret,
    _write_secret,
)

log = logging.getLogger(__name__)

_PUSH_SCHEMA_VERSION = 1
_PUSH_LOCK = threading.RLock()
_SECRET_FIELDS = {
    "ntfy_token": "push/ntfy_token",
    "unifiedpush_endpoint": "push/unifiedpush_endpoint",
    "unifiedpush_auth": "push/unifiedpush_auth",
    "unifiedpush_vapid_private_key": "push/unifiedpush_vapid_private_key",
}


@dataclass(slots=True)
class PushNotificationOptions:
    schema_version: int = _PUSH_SCHEMA_VERSION
    ntfy_enabled: bool = False
    ntfy_base_url: str = "https://ntfy.sh"
    ntfy_topic: str = ""
    ntfy_token: str = ""
    unifiedpush_enabled: bool = False
    unifiedpush_endpoint: str = ""
    unifiedpush_p256dh: str = ""
    unifiedpush_auth: str = ""
    unifiedpush_vapid_private_key: str = ""
    unifiedpush_vapid_subject: str = "mailto:wormhole-observatory@localhost"
    unifiedpush_allow_private_endpoint: bool = False
    review_base_url: str = ""
    timeout_sec: float = 10.0


def push_options_path() -> Path:
    return options_path().with_name("push_notifications.json")


def _generate_vapid_private_key() -> str:
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def unifiedpush_vapid_public_key(options: PushNotificationOptions) -> str:
    private_pem = options.unifiedpush_vapid_private_key.strip()
    if not private_pem:
        return ""
    private_key = serialization.load_pem_private_key(private_pem.encode("ascii"), password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("UnifiedPush VAPID key is not an EC private key")
    raw = private_key.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _coerce(raw: Any) -> PushNotificationOptions:
    result = PushNotificationOptions()
    if not isinstance(raw, dict):
        return result
    valid = {item.name for item in fields(result)}
    for key, value in raw.items():
        if key in valid and key != "schema_version":
            setattr(result, key, value)
    result.schema_version = _PUSH_SCHEMA_VERSION
    return result


def _hydrate_secrets(options: PushNotificationOptions) -> bool:
    migrated = False
    for attribute, key in _SECRET_FIELDS.items():
        plaintext = str(getattr(options, attribute, "") or "")
        state, stored = _read_secret(key)
        if state is CredentialReadState.PRESENT:
            setattr(options, attribute, stored)
            migrated = migrated or bool(plaintext)
        elif state is CredentialReadState.MISSING and plaintext and _write_secret(key, plaintext):
            migrated = True
    return migrated


def load_push_options(path: Path | None = None) -> PushNotificationOptions:
    target = path or push_options_path()
    with _PUSH_LOCK:
        try:
            raw = json.loads(target.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raw = {}
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("Could not read push notification settings: %s", exc)
            raw = {}
        options = _coerce(raw)
        migrated = _hydrate_secrets(options)
        if migrated:
            save_push_options(options, target)
        return options


def save_push_options(options: PushNotificationOptions, path: Path | None = None) -> None:
    target = path or push_options_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    if options.unifiedpush_enabled and not options.unifiedpush_vapid_private_key.strip():
        options.unifiedpush_vapid_private_key = _generate_vapid_private_key()
    payload = asdict(options)
    payload["schema_version"] = _PUSH_SCHEMA_VERSION
    for attribute, key in _SECRET_FIELDS.items():
        value = str(getattr(options, attribute, "") or "")
        if value:
            if _write_secret(key, value):
                payload[attribute] = ""
        else:
            _delete_secret(key)
            payload[attribute] = ""
    encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    temp = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    with _PUSH_LOCK:
        temp.write_text(encoded, encoding="utf-8")
        os.replace(temp, target)


def build_review_link(base_url: str, domain: str | None = None) -> str:
    value = base_url.strip()
    if not value:
        return ""
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Review base URL must be an absolute HTTP(S) URL")
    path = parsed.path or "/app/"
    if not path.endswith("/"):
        path += "/"
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if domain:
        query["domain"] = domain.strip().lower().rstrip(".")
    return urlunsplit((parsed.scheme, parsed.netloc, path, urlencode(query), ""))


def _validate_unifiedpush_endpoint(endpoint: str, allow_private: bool) -> None:
    parsed = urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("UnifiedPush endpoint must be an absolute HTTPS URL")
    if allow_private:
        return
    try:
        addresses = socket.getaddrinfo(
            parsed.hostname,
            parsed.port or 443,
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise ValueError("UnifiedPush endpoint hostname could not be resolved") from exc
    if not addresses:
        raise ValueError("UnifiedPush endpoint hostname did not resolve")
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if not ip.is_global:
            raise ValueError(
                "UnifiedPush endpoint resolves to a non-global address; enable the explicit "
                "private-endpoint option only for a trusted self-hosted push server"
            )


def send_ntfy(
    options: PushNotificationOptions,
    title: str,
    message: str,
    *,
    domain: str | None = None,
) -> None:
    if not options.ntfy_enabled:
        return
    topic = options.ntfy_topic.strip()
    base_url = options.ntfy_base_url.strip().rstrip("/")
    if not topic or not base_url:
        raise ValueError("ntfy requires a base URL and topic")
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("ntfy base URL must be an absolute HTTP(S) URL")
    headers = {
        "Title": title,
        "Tags": "wormhole,review",
        "Cache": "no",
    }
    link = build_review_link(options.review_base_url, domain)
    if link:
        headers["Click"] = link
    token = options.ntfy_token.strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = requests.post(
        f"{base_url}/{quote(topic, safe='')}",
        data=message.encode("utf-8"),
        headers=headers,
        timeout=max(1.0, float(options.timeout_sec)),
    )
    response.raise_for_status()


def send_unifiedpush(
    options: PushNotificationOptions,
    title: str,
    message: str,
    *,
    domain: str | None = None,
) -> None:
    if not options.unifiedpush_enabled:
        return
    endpoint = options.unifiedpush_endpoint.strip()
    p256dh = options.unifiedpush_p256dh.strip()
    auth = options.unifiedpush_auth.strip()
    private_key = options.unifiedpush_vapid_private_key.strip()
    subject = options.unifiedpush_vapid_subject.strip()
    if not endpoint or not p256dh or not auth:
        raise ValueError("UnifiedPush requires endpoint, p256dh, and auth registration values")
    if not private_key:
        raise ValueError("UnifiedPush VAPID private key is missing")
    if not subject:
        raise ValueError("UnifiedPush VAPID subject is missing")
    _validate_unifiedpush_endpoint(endpoint, options.unifiedpush_allow_private_endpoint)
    payload = json.dumps(
        {
            "type": "wormhole_review",
            "title": title,
            "message": message,
            "domain": domain or "",
            "url": build_review_link(options.review_base_url, domain),
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
    if len(payload.encode("utf-8")) > 3500:
        raise ValueError("UnifiedPush payload is too large")
    try:
        webpush(
            subscription_info={
                "endpoint": endpoint,
                "keys": {"p256dh": p256dh, "auth": auth},
            },
            data=payload,
            vapid_private_key=private_key,
            vapid_claims={"sub": subject},
            content_encoding="aes128gcm",
            timeout=max(1.0, float(options.timeout_sec)),
        )
    except WebPushException:
        raise


def send_push_notifications(
    title: str,
    message: str,
    *,
    domain: str | None = None,
    options: PushNotificationOptions | None = None,
) -> list[str]:
    settings = options or load_push_options()
    errors: list[str] = []
    if settings.ntfy_enabled:
        try:
            send_ntfy(settings, title, message, domain=domain)
        except Exception as exc:
            log.warning("ntfy notification failed: %s", exc)
            errors.append(f"ntfy: {exc}")
    if settings.unifiedpush_enabled:
        try:
            send_unifiedpush(settings, title, message, domain=domain)
        except Exception as exc:
            log.warning("UnifiedPush notification failed: %s", exc)
            errors.append(f"UnifiedPush: {exc}")
    return errors
