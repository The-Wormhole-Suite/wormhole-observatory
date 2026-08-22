from __future__ import annotations

import http.client
import json

from pihole_manager.config import ExternalTriggerOptions
from pihole_manager.external_trigger import ExternalTriggerServer
from pihole_manager.webapp import get_web_asset


def _get(server: ExternalTriggerServer, path: str, token: str = ""):
    address = server.address
    assert address is not None
    host, port = address
    connection = http.client.HTTPConnection(host, port, timeout=3)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    body = response.read()
    result = response.status, dict(response.getheaders()), body
    connection.close()
    return result


def test_review_app_shell_is_public_but_contains_no_token() -> None:
    server = ExternalTriggerServer(
        ExternalTriggerOptions(enabled=True, port=0, token="server-secret")
    )
    server.start()
    try:
        status, headers, body = _get(server, "/app/")
        text = body.decode("utf-8")
        assert status == 200
        assert "Wormhole Observatory" in text
        assert "server-secret" not in text
        assert "Content-Security-Policy" in headers
        assert headers["Referrer-Policy"] == "no-referrer"

        status, _headers, body = _get(server, "/v1/status")
        assert status == 401
        assert json.loads(body)["error"] == "unauthorized"
    finally:
        server.stop()


def test_review_app_manifest_and_service_worker_are_packaged() -> None:
    manifest = get_web_asset("/manifest.webmanifest")
    service_worker = get_web_asset("/sw.js")
    assert manifest is not None
    assert service_worker is not None

    payload = json.loads(manifest.content)
    assert payload["start_url"] == "/app/"
    assert payload["display"] == "standalone"
    worker_text = service_worker.content.decode("utf-8")
    assert 'url.pathname.startsWith("/v1/")' in worker_text
    assert 'url.pathname === "/health"' in worker_text


def test_root_redirects_to_review_app() -> None:
    server = ExternalTriggerServer(
        ExternalTriggerOptions(enabled=True, port=0, token="server-secret")
    )
    server.start()
    try:
        status, headers, body = _get(server, "/")
        assert status == 307
        assert headers["Location"] == "/app/"
        assert body == b""
    finally:
        server.stop()
