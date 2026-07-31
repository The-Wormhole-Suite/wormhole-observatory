from __future__ import annotations

import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any

import requests

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class DiscoveredLocalProvider:
    name: str
    preset_id: str
    base_url: str
    models: tuple[str, ...] = ()
    notes: str = ""


@dataclass(frozen=True, slots=True)
class _Probe:
    name: str
    preset_id: str
    base_url: str
    probe: Callable[[requests.Session, float], tuple[bool, list[str], str]]


def discover_local_providers(timeout_sec: float = 0.8) -> list[DiscoveredLocalProvider]:
    """Probe common loopback-only local LLM endpoints.

    The function never scans the LAN. It contacts only 127.0.0.1 on well-known
    ports and uses read-only health or model-list endpoints.
    """
    timeout = max(0.2, float(timeout_sec))
    probes = (
        _Probe("Ollama (local)", "ollama", "http://127.0.0.1:11434/v1", _probe_ollama),
        _Probe("LM Studio (local)", "lm_studio", "http://127.0.0.1:1234/v1", _probe_lm_studio),
        _Probe("LocalAI (local)", "localai", "http://127.0.0.1:8080/v1", _probe_localai),
        _Probe(
            "llama.cpp server (local)",
            "llama_cpp",
            "http://127.0.0.1:8080/v1",
            _probe_llama_cpp,
        ),
        _Probe(
            "vLLM (local/server)",
            "vllm",
            "http://127.0.0.1:8000/v1",
            _probe_vllm,
        ),
        _Probe(
            "LiteLLM Proxy",
            "litellm",
            "http://127.0.0.1:4000/v1",
            _probe_litellm,
        ),
    )

    results: list[DiscoveredLocalProvider] = []
    with ThreadPoolExecutor(max_workers=len(probes), thread_name_prefix="LocalLLMProbe") as pool:
        futures = {pool.submit(_run_probe, probe, timeout): probe for probe in probes}
        for future in as_completed(futures):
            probe = futures[future]
            try:
                detected, models, note = future.result()
            except Exception as exc:
                log.debug("Local LLM probe %s failed: %s", probe.name, exc)
                continue
            if detected:
                results.append(
                    DiscoveredLocalProvider(
                        name=probe.name,
                        preset_id=probe.preset_id,
                        base_url=probe.base_url,
                        models=tuple(sorted(set(models), key=str.casefold)),
                        notes=note,
                    )
                )

    # LocalAI and llama.cpp commonly share port 8080. Prefer the stronger
    # LocalAI fingerprint when both probes happen to respond successfully.
    if any(item.preset_id == "localai" for item in results):
        results = [item for item in results if item.preset_id != "llama_cpp"]
    return sorted(results, key=lambda item: item.name.casefold())


def _run_probe(
    probe: _Probe,
    timeout: float,
) -> tuple[bool, list[str], str]:
    session = requests.Session()
    session.trust_env = False
    try:
        return probe.probe(session, timeout)
    finally:
        session.close()


def _get_json(
    session: requests.Session,
    url: str,
    timeout: float,
) -> tuple[int, Any]:
    try:
        response = session.get(
            url,
            headers={"Accept": "application/json", "User-Agent": "Pi-Hole-Manager"},
            timeout=(timeout, timeout),
        )
    except requests.RequestException:
        return 0, None
    try:
        payload = response.json()
    except ValueError:
        payload = None
    return response.status_code, payload


def _openai_model_ids(payload: Any) -> list[str]:
    items = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        return []
    return [
        str(item.get("id") or "").strip()
        for item in items
        if isinstance(item, dict) and str(item.get("id") or "").strip()
    ]


def _probe_ollama(
    session: requests.Session,
    timeout: float,
) -> tuple[bool, list[str], str]:
    status, payload = _get_json(session, "http://127.0.0.1:11434/api/tags", timeout)
    if (
        status != 200
        or not isinstance(payload, dict)
        or not isinstance(payload.get("models"), list)
    ):
        return False, [], ""
    models = [
        str(item.get("model") or item.get("name") or "").strip()
        for item in payload["models"]
        if isinstance(item, dict) and str(item.get("model") or item.get("name") or "").strip()
    ]
    return True, models, "Detected through Ollama's local /api/tags endpoint."


def _probe_lm_studio(
    session: requests.Session,
    timeout: float,
) -> tuple[bool, list[str], str]:
    status, payload = _get_json(session, "http://127.0.0.1:1234/api/v1/models", timeout)
    if status == 200 and isinstance(payload, dict) and isinstance(payload.get("models"), list):
        models = [
            str(item.get("key") or item.get("id") or "").strip()
            for item in payload["models"]
            if isinstance(item, dict)
            and str(item.get("key") or item.get("id") or "").strip()
            and str(item.get("type") or "llm") == "llm"
        ]
        return True, models, "Detected through LM Studio's native local API."

    status, payload = _get_json(session, "http://127.0.0.1:1234/v1/models", timeout)
    models = _openai_model_ids(payload)
    if status == 200 and models:
        return True, models, "Detected through LM Studio's OpenAI-compatible endpoint."
    if status in {401, 403}:
        return True, [], "LM Studio appears to require an API token."
    return False, [], ""


def _probe_localai(
    session: requests.Session,
    timeout: float,
) -> tuple[bool, list[str], str]:
    status, payload = _get_json(
        session,
        "http://127.0.0.1:8080/.well-known/localai.json",
        timeout,
    )
    if status == 200 and isinstance(payload, dict) and payload.get("endpoints"):
        _, models_payload = _get_json(session, "http://127.0.0.1:8080/v1/models", timeout)
        return (
            True,
            _openai_model_ids(models_payload),
            "Detected through LocalAI discovery metadata.",
        )

    status, payload = _get_json(session, "http://127.0.0.1:8080/version", timeout)
    if status == 200 and isinstance(payload, dict) and payload.get("version"):
        _, models_payload = _get_json(session, "http://127.0.0.1:8080/v1/models", timeout)
        return (
            True,
            _openai_model_ids(models_payload),
            "Detected through LocalAI's version endpoint.",
        )
    return False, [], ""


def _probe_llama_cpp(
    session: requests.Session,
    timeout: float,
) -> tuple[bool, list[str], str]:
    status, payload = _get_json(session, "http://127.0.0.1:8080/health", timeout)
    if status not in {200, 503} or not isinstance(payload, dict):
        return False, [], ""
    if status == 200 and payload.get("status") != "ok":
        return False, [], ""
    _, models_payload = _get_json(session, "http://127.0.0.1:8080/v1/models", timeout)
    note = "Detected through llama.cpp's health endpoint."
    if status == 503:
        note = "llama.cpp was detected, but its model is still loading."
    return True, _openai_model_ids(models_payload), note


def _probe_vllm(
    session: requests.Session,
    timeout: float,
) -> tuple[bool, list[str], str]:
    return _probe_openai_endpoint(
        session,
        "http://127.0.0.1:8000/v1/models",
        timeout,
        "Detected an OpenAI-compatible service on vLLM's default port.",
    )


def _probe_litellm(
    session: requests.Session,
    timeout: float,
) -> tuple[bool, list[str], str]:
    return _probe_openai_endpoint(
        session,
        "http://127.0.0.1:4000/v1/models",
        timeout,
        "Detected an OpenAI-compatible service on LiteLLM's default port.",
    )


def _probe_openai_endpoint(
    session: requests.Session,
    url: str,
    timeout: float,
    note: str,
) -> tuple[bool, list[str], str]:
    status, payload = _get_json(session, url, timeout)
    models = _openai_model_ids(payload)
    if status == 200 and isinstance(payload, dict) and isinstance(payload.get("data"), list):
        return True, models, note
    if status in {401, 403}:
        return True, [], note + " Authentication is required to list models."
    return False, [], ""
