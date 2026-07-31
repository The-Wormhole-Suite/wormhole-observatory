from __future__ import annotations

from typing import Any

from pihole_manager import local_discovery


class _Response:
    def __init__(self, status_code: int, payload: Any) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> Any:
        return self._payload


class _Session:
    def __init__(self, responses: dict[str, _Response]) -> None:
        self.responses = responses

    def get(self, url: str, **_kwargs: Any) -> _Response:
        return self.responses.get(url, _Response(404, {}))


def test_ollama_probe_reads_native_model_list() -> None:
    session = _Session(
        {
            "http://127.0.0.1:11434/api/tags": _Response(
                200,
                {"models": [{"model": "qwen3:8b"}, {"name": "gemma3:4b"}]},
            )
        }
    )

    detected, models, note = local_discovery._probe_ollama(session, 0.5)

    assert detected is True
    assert models == ["qwen3:8b", "gemma3:4b"]
    assert "Ollama" in note


def test_lm_studio_probe_uses_native_api_and_filters_embeddings() -> None:
    session = _Session(
        {
            "http://127.0.0.1:1234/api/v1/models": _Response(
                200,
                {
                    "models": [
                        {"key": "qwen/local", "type": "llm"},
                        {"key": "nomic/embed", "type": "embedding"},
                    ]
                },
            )
        }
    )

    detected, models, _note = local_discovery._probe_lm_studio(session, 0.5)

    assert detected is True
    assert models == ["qwen/local"]


def test_localai_probe_uses_well_known_fingerprint() -> None:
    session = _Session(
        {
            "http://127.0.0.1:8080/.well-known/localai.json": _Response(
                200,
                {"version": "v3", "endpoints": {"models": "/v1/models"}},
            ),
            "http://127.0.0.1:8080/v1/models": _Response(
                200,
                {"data": [{"id": "local-model"}]},
            ),
        }
    )

    detected, models, note = local_discovery._probe_localai(session, 0.5)

    assert detected is True
    assert models == ["local-model"]
    assert "LocalAI" in note


def test_discovery_never_contains_non_loopback_targets(monkeypatch) -> None:
    contacted: list[str] = []

    class RecordingSession:
        trust_env = True

        def get(self, url: str, **_kwargs: Any) -> _Response:
            contacted.append(url)
            return _Response(404, {})

        def close(self) -> None:
            return None

    monkeypatch.setattr(local_discovery.requests, "Session", RecordingSession)

    assert local_discovery.discover_local_providers(0.2) == []
    assert contacted
    assert all(url.startswith("http://127.0.0.1:") for url in contacted)
