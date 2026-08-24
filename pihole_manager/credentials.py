from __future__ import annotations

import logging
import threading
from dataclasses import asdict
from enum import StrEnum
from typing import Any

log = logging.getLogger(__name__)

SERVICE_NAME = "The Wormhole Suite - Wormhole Observatory"
_STATE_LOCK = threading.RLock()


class CredentialReadState(StrEnum):
    PRESENT = "present"
    MISSING = "missing"
    UNAVAILABLE = "unavailable"


_READ_STATES: dict[str, CredentialReadState] = {}


def _keyring_module():
    try:
        import keyring
    except ImportError:
        return None
    return keyring


def _set_read_state(key: str, state: CredentialReadState) -> None:
    with _STATE_LOCK:
        _READ_STATES[key] = state


def _read_secret(key: str) -> tuple[CredentialReadState, str]:
    keyring = _keyring_module()
    if keyring is None:
        _set_read_state(key, CredentialReadState.UNAVAILABLE)
        return CredentialReadState.UNAVAILABLE, ""
    try:
        value = str(keyring.get_password(SERVICE_NAME, key) or "")
    except Exception:  # backend failures must not make configuration unreadable
        log.warning("Credential store is unavailable while reading %s", key)
        _set_read_state(key, CredentialReadState.UNAVAILABLE)
        return CredentialReadState.UNAVAILABLE, ""
    state = CredentialReadState.PRESENT if value else CredentialReadState.MISSING
    _set_read_state(key, state)
    return state, value


def _write_secret(key: str, value: str) -> bool:
    keyring = _keyring_module()
    if keyring is None:
        return False
    try:
        keyring.set_password(SERVICE_NAME, key, value)
        _set_read_state(key, CredentialReadState.PRESENT)
        return True
    except Exception:  # keep plaintext as a no-data-loss fallback
        log.warning("Credential store is unavailable while writing %s", key)
        return False


def _delete_secret(key: str) -> bool:
    with _STATE_LOCK:
        if _READ_STATES.get(key) is CredentialReadState.UNAVAILABLE:
            return False
    keyring = _keyring_module()
    if keyring is None:
        return False
    try:
        keyring.delete_password(SERVICE_NAME, key)
        _set_read_state(key, CredentialReadState.MISSING)
        return True
    except Exception:
        # Missing credentials and unavailable delete support are both harmless here.
        return False


def _credential_slots(options: Any):
    yield "pihole/password", options.pihole, "password"
    yield "external_trigger/token", options.external_trigger, "token"
    for provider in options.llm_providers:
        provider_id = str(provider.provider_id or "").strip()
        if provider_id:
            yield f"llm/{provider_id}/api_key", provider, "api_key"
    for provider in options.research_providers:
        kind = str(provider.kind or "").strip().lower()
        if kind:
            yield f"research/{kind}/api_key", provider, "api_key"


def load_credentials(options: Any) -> None:
    for key, target, attr in _credential_slots(options):
        state, value = _read_secret(key)
        if state is CredentialReadState.PRESENT:
            setattr(target, attr, value)


def persist_credentials(options: Any) -> None:
    for key, target, attr in _credential_slots(options):
        value = str(getattr(target, attr, "") or "")
        if value:
            _write_secret(key, value)
        else:
            _delete_secret(key)


def redact_credentials(options: Any) -> dict[str, Any]:
    payload = asdict(options)
    pihole = payload.get("pihole")
    if isinstance(pihole, dict):
        pihole["password"] = ""
    external_trigger = payload.get("external_trigger")
    if isinstance(external_trigger, dict):
        external_trigger["token"] = ""
    for key in ("llm_providers", "research_providers"):
        values = payload.get(key)
        if isinstance(values, list):
            for value in values:
                if isinstance(value, dict):
                    value["api_key"] = ""
    return payload
