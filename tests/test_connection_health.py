from __future__ import annotations

from typing import Any

import pytest
import requests

from pihole6api.connection import PiHole6Connection
from pihole6api.errors import PiHole6AuthenticationError, PiHole6ConnectionError, PiHole6HTTPError
from pihole6api.health import ConnectionState


class FakeResponse:
    def __init__(self, status_code: int, payload: Any = None, *, reason: str = "") -> None:
        self.status_code = status_code
        self._payload = payload
        self.reason = reason
        self.content = b"{}" if payload is not None else b""
        self.text = "{}" if payload is not None else ""

    def json(self) -> Any:
        return self._payload


class FakeSession:
    def __init__(
        self,
        responses: list[FakeResponse] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.responses = responses or []
        self.error = error

    def mount(self, *_: Any, **__: Any) -> None:
        return None

    def request(self, **_: Any) -> FakeResponse:
        if self.error is not None:
            raise self.error
        return self.responses.pop(0)

    def close(self) -> None:
        return None


def test_successful_request_marks_connection_online() -> None:
    connection = PiHole6Connection(
        "http://pi.hole",
        session=FakeSession([FakeResponse(200, {"ok": True})]),  # type: ignore[arg-type]
    )

    assert connection.get("info/version") == {"ok": True}
    health = connection.health
    assert health.state is ConnectionState.ONLINE
    assert health.status_code == 200
    assert health.last_success_at > 0
    assert health.consecutive_failures == 0


def test_network_failure_marks_connection_offline() -> None:
    connection = PiHole6Connection(
        "http://pi.hole",
        session=FakeSession(error=requests.ConnectionError("refused")),  # type: ignore[arg-type]
    )

    with pytest.raises(PiHole6ConnectionError):
        connection.get("info/version")

    health = connection.health
    assert health.state is ConnectionState.OFFLINE
    assert health.consecutive_failures == 1
    assert "refused" in health.last_error


def test_invalid_session_marks_authentication_error() -> None:
    connection = PiHole6Connection(
        "http://pi.hole",
        "wrong-password",
        session=FakeSession(  # type: ignore[arg-type]
            [FakeResponse(200, {"session": {"valid": False, "message": "bad password"}})]
        ),
    )

    with pytest.raises(PiHole6AuthenticationError):
        connection.get("info/version")

    assert connection.health.state is ConnectionState.AUTH_ERROR
    assert "bad password" in connection.health.last_error


def test_server_failure_marks_connection_degraded() -> None:
    connection = PiHole6Connection(
        "http://pi.hole",
        session=FakeSession(  # type: ignore[arg-type]
            [FakeResponse(503, {"error": {"message": "starting"}}, reason="Unavailable")]
        ),
    )

    with pytest.raises(PiHole6HTTPError):
        connection.get("info/version")

    health = connection.health
    assert health.state is ConnectionState.DEGRADED
    assert health.status_code == 503
    assert "Unavailable" in health.last_error


@pytest.mark.parametrize("status_code", [400, 404])
def test_client_error_marks_api_error(status_code: int) -> None:
    connection = PiHole6Connection(
        "http://pi.hole",
        session=FakeSession(  # type: ignore[arg-type]
            [FakeResponse(status_code, {"error": {"message": "invalid API request"}})]
        ),
    )

    with pytest.raises(PiHole6HTTPError):
        connection.get("info/version")

    assert connection.health.state is ConnectionState.API_ERROR
    assert connection.health.status_code == status_code


def test_forbidden_response_marks_authentication_error() -> None:
    connection = PiHole6Connection(
        "http://pi.hole",
        session=FakeSession(  # type: ignore[arg-type]
            [FakeResponse(403, {"error": {"message": "forbidden"}})]
        ),
    )

    with pytest.raises(PiHole6HTTPError):
        connection.get("info/version")

    assert connection.health.state is ConnectionState.AUTH_ERROR


def test_tls_failure_has_distinct_health_state() -> None:
    connection = PiHole6Connection(
        "https://pi.hole",
        session=FakeSession(  # type: ignore[arg-type]
            error=requests.exceptions.SSLError("certificate verify failed")
        ),
    )

    with pytest.raises(PiHole6ConnectionError, match="TLS verification failed"):
        connection.get("info/version")

    assert connection.health.state is ConnectionState.TLS_ERROR


def test_close_marks_connection_closed() -> None:
    connection = PiHole6Connection(
        "http://pi.hole",
        session=FakeSession(),  # type: ignore[arg-type]
    )
    connection.close()
    assert connection.health.state is ConnectionState.CLOSED
