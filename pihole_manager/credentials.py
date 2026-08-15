from __future__ import annotations

import logging
from dataclasses import asdict
from typing import Any

log = logging.getLogger(__name__)

SERVICE_NAME = "The Wormhole Suite - Wormhole Observatory"


def _keyring_module():
    try:
        import keyring
    except ImportError:
        return None
    return keyring


def _read_secret(key: str) -> str:
    keyring = _keyring_module()
    if keyring is None:
        return ""
    try:
        return str(keyring.get_password(SERVICE_NAME, key) or "")
    except Exception as exc:  # backend failures must not make configuration unreadable
        log.warning("Credential store is unavailable while reading %s: %s", key, exc)
        return ""


def _write_secret(key: str, value: str) -> bool:
    keyring = _keyring_module()
    if keyring is None:
        return False
    try:
        keyring.set_password(SERVICE_NAME, key, value)
        return True
    except Exception as exc:  # keep plaintext as a no-data-loss fallback
        log.warning("Credential store is unavailable while writing %s: %s", key, exc)
        return False


def _delete_secret(key: str) -> bool:
    keyring = _keyring_module()
    if keyring is None:
        return False
    try:
        keyring.delete_password(SERVICE_NAME, key)
        return True
    except Exception:
        # Missing credentials and unavailable delete support are both harmless here.
        return False


def _credential_slots(options: Any):
    yield "pihole/password", options.pihole, "password"
    for provider in options.llm_providers:
        provider_id = str(provider.provider_id or "").strip()
        if provider_id:
            yield f"llm/{provider_id}/api_key", provider, "api_key"
    for provider in options.research_providers:
        kind = str(provider.kind or "").strip().lower()
        if kind:
            yield f"research/{kind}/api_key", provider, "api_key"


def hydrate_credentials(options: Any) -> bool:
    """Hydrate secrets from the OS store and migrate legacy plaintext secrets.

    Returns True when at least one plaintext credential was successfully copied
    into the OS credential store and the caller can safely rewrite options.json.
    """

    migrated = False
    for key, owner, attribute in _credential_slots(options):
        plaintext = str(getattr(owner, attribute, "") or "")
        stored = _read_secret(key)
        if stored:
            setattr(owner, attribute, stored)
            if plaintext:
                migrated = True
            continue
        if plaintext and _write_secret(key, plaintext):
            migrated = True
    return migrated


def secure_options_payload(options: Any) -> dict[str, Any]:
    """Return a serializable options payload with stored secrets removed.

    If an OS credential backend is unavailable, a non-empty secret is retained
    in the payload rather than being silently lost. This preserves compatibility
    on headless/minimal systems while desktop systems use their native store.
    """

    payload = asdict(options)

    password = str(options.pihole.password or "")
    if password:
        if _write_secret("pihole/password", password):
            payload["pihole"]["password"] = ""
    else:
        _delete_secret("pihole/password")
        payload["pihole"]["password"] = ""

    llm_payload = payload.get("llm_providers", [])
    for index, provider in enumerate(options.llm_providers):
        provider_id = str(provider.provider_id or "").strip()
        api_key = str(provider.api_key or "")
        if not provider_id:
            continue
        key = f"llm/{provider_id}/api_key"
        if api_key:
            if _write_secret(key, api_key):
                llm_payload[index]["api_key"] = ""
        else:
            _delete_secret(key)
            llm_payload[index]["api_key"] = ""

    research_payload = payload.get("research_providers", [])
    for index, provider in enumerate(options.research_providers):
        kind = str(provider.kind or "").strip().lower()
        api_key = str(provider.api_key or "")
        if not kind:
            continue
        key = f"research/{kind}/api_key"
        if api_key:
            if _write_secret(key, api_key):
                research_payload[index]["api_key"] = ""
        else:
            _delete_secret(key)
            research_payload[index]["api_key"] = ""

    return payload
