from __future__ import annotations

from typing import Any

import pytest
import requests

from pihole6api.connection import PiHole6Connection, normalize_api_url
from pihole6api.errors import PiHole6HTTPError


class FakeResponse:
    def __init__(
        self,
        status_code: int,
        payload: Any = None,
        *,
        reason: str = "",
        content: bytes | None = None,
    ) -> None:
        self.status_code = status_code
        self._payload = payload
        self.reason = reason
        if content is None:
            content = b"{}" if payload is not None else b""
        self.content = content
        self.text = content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class FakeSession:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self.responses = responses
        self.calls: list[dict[str, Any]] = []
        self.closed = False

    def mount(self, *_: Any, **__: Any) -> None:
        return None

    def request(self, **kwargs: Any) -> FakeResponse:
        self.calls.append(kwargs)
        return self.responses.pop(0)

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("pi.hole", "http://pi.hole/api/"),
        ("https://pi.hole/admin", "https://pi.hole/api/"),
        ("https://pi.hole/admin/index.php", "https://pi.hole/api/"),
        ("http://pi.hole/api", "http://pi.hole/api/"),
        ("https://host.example/pihole/admin/", "https://host.example/pihole/api/"),
    ],
)
def test_normalize_api_url(value: str, expected: str) -> None:
    assert normalize_api_url(value) == expected


def test_authenticated_request_uses_session_headers_and_tls_setting() -> None:
    fake = FakeSession(
        [
            FakeResponse(
                200,
                {"session": {"valid": True, "sid": "sid-1", "csrf": "csrf-1", "validity": 300}},
            ),
            FakeResponse(200, {"version": {"ftl": {"version": "v6.0"}}}),
        ]
    )
    connection = PiHole6Connection(
        "https://pi.hole/admin",
        "secret",
        verify_tls=False,
        session=fake,  # type: ignore[arg-type]
    )

    payload = connection.get("info/version")

    assert payload["version"]["ftl"]["version"] == "v6.0"
    assert fake.calls[0]["url"] == "https://pi.hole/api/auth"
    assert fake.calls[0]["json"] == {"password": "secret"}
    assert fake.calls[1]["headers"]["X-FTL-SID"] == "sid-1"
    assert fake.calls[1]["headers"]["X-FTL-CSRF"] == "csrf-1"
    assert fake.calls[1]["verify"] is False


def test_http_error_is_raised_instead_of_returned_as_success() -> None:
    fake = FakeSession(
        [
            FakeResponse(
                400,
                {"error": {"message": "invalid request"}},
                reason="Bad Request",
            )
        ]
    )
    connection = PiHole6Connection("http://pi.hole", session=fake)  # type: ignore[arg-type]

    with pytest.raises(PiHole6HTTPError) as exc_info:
        connection.get("info/version")

    assert exc_info.value.status_code == 400
    assert "invalid request" in str(exc_info.value)


def test_non_json_success_returns_text() -> None:
    decode_error = requests.JSONDecodeError("invalid", "plain", 0)
    fake = FakeSession([FakeResponse(200, decode_error, content=b"plain response")])
    connection = PiHole6Connection("http://pi.hole", session=fake)  # type: ignore[arg-type]

    assert connection.get("plain") == "plain response"
