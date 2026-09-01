from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from pihole6api.errors import (
    PiHole6AuthenticationError,
    PiHole6ConnectionError,
    PiHole6HTTPError,
)
from pihole6api.health import ConnectionHealth, ConnectionState

log = logging.getLogger(__name__)


def normalize_api_url(base_url: str) -> str:
    value = base_url.strip()
    if not value:
        raise ValueError("Pi-hole base URL must not be empty")
    if "://" not in value:
        value = f"http://{value}"

    parsed = urlsplit(value)
    if not parsed.hostname:
        raise ValueError(f"Invalid Pi-hole base URL: {base_url!r}")
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Pi-hole base URL must use http or https")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Pi-hole credentials must not be embedded in the base URL")

    path = parsed.path.rstrip("/")
    if path.endswith("/admin/index.php"):
        path = path[: -len("/admin/index.php")]
    elif path.endswith("/admin"):
        path = path[: -len("/admin")]
    if path.endswith("/api"):
        path = path[: -len("/api")]

    api_path = f"{path}/api/" if path else "/api/"
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, api_path, "", ""))


class PiHole6Connection:
    def __init__(
        self,
        base_url: str,
        password: str = "",
        *,
        ca_bundle_path: str = "",
        verify_tls: bool | str | None = None,
        timeout: float = 10.0,
        max_retries: int = 2,
        session: requests.Session | None = None,
    ) -> None:
        self.base_url = normalize_api_url(base_url)
        self.password = password or ""
        if verify_tls is False:
            raise ValueError(
                "Disabling TLS certificate verification is no longer supported; "
                "configure ca_bundle_path for private certificate authorities."
            )
        legacy_ca_bundle = verify_tls.strip() if isinstance(verify_tls, str) else ""
        configured_ca_bundle = str(ca_bundle_path or "").strip()
        if legacy_ca_bundle and configured_ca_bundle and legacy_ca_bundle != configured_ca_bundle:
            raise ValueError("Conflicting CA bundle paths were provided")
        self.ca_bundle_path = configured_ca_bundle or legacy_ca_bundle
        self.timeout = max(1.0, float(timeout))
        self.session_id: str | None = None
        self.csrf_token: str | None = None
        self.validity: int | None = None
        self._lock = threading.RLock()
        self._closed = False
        self._health = ConnectionHealth()

        self.session = session or requests.Session()
        retries = max(0, int(max_retries))
        retry = Retry(
            total=retries,
            connect=0,
            read=min(1, retries),
            status=retries,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
            respect_retry_after_header=True,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=4, pool_maxsize=8)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    @property
    def health(self) -> ConnectionHealth:
        with self._lock:
            return self._health

    def _record_response(self, response: requests.Response, latency_ms: int) -> None:
        now = time.time()
        status = int(response.status_code)
        previous = self._health
        if 200 <= status < 300:
            state = ConnectionState.ONLINE
            failures = 0
            last_success = now
            error = ""
        elif status in {401, 403}:
            state = ConnectionState.AUTH_ERROR
            failures = previous.consecutive_failures + 1
            last_success = previous.last_success_at
            error = response.reason or "Authentication failed"
        elif status == 429 or status >= 500:
            state = ConnectionState.DEGRADED
            failures = previous.consecutive_failures + 1
            last_success = previous.last_success_at
            error = response.reason or f"HTTP {status}"
        else:
            state = ConnectionState.API_ERROR
            failures = previous.consecutive_failures + 1
            last_success = previous.last_success_at
            error = response.reason or f"HTTP {status}"
        self._health = ConnectionHealth(
            state=state,
            last_checked_at=now,
            last_success_at=last_success,
            latency_ms=max(0, int(latency_ms)),
            consecutive_failures=failures,
            status_code=status,
            last_error=error,
        )

    def _record_failure(self, state: ConnectionState, error: object) -> None:
        previous = self._health
        self._health = ConnectionHealth(
            state=state,
            last_checked_at=time.time(),
            last_success_at=previous.last_success_at,
            latency_ms=0,
            consecutive_failures=previous.consecutive_failures + 1,
            status_code=0,
            last_error=str(error),
        )

    def _record_auth_error(self, message: str) -> None:
        self._record_failure(ConnectionState.AUTH_ERROR, message)

    def __enter__(self) -> PiHole6Connection:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _url(self, endpoint: str) -> str:
        return f"{self.base_url}{endpoint.lstrip('/')}"

    def _authenticate(self) -> None:
        if not self.password:
            return
        with self._lock:
            if self.session_id:
                return
            response = self._send_raw(
                "POST",
                "auth",
                json_data={"password": self.password},
                authenticated=False,
            )
            data = self._decode_json(response)
            session = data.get("session") if isinstance(data, dict) else None
            if not isinstance(session, dict) or not session.get("valid"):
                message = self._error_message(data, "Authentication failed")
                self._record_auth_error(message)
                raise PiHole6AuthenticationError(message)
            self.session_id = str(session.get("sid") or "") or None
            self.csrf_token = str(session.get("csrf") or "") or None
            validity = session.get("validity")
            self.validity = int(validity) if validity is not None else None
            if not self.session_id:
                message = "Authentication returned no session ID"
                self._record_auth_error(message)
                raise PiHole6AuthenticationError(message)

    def _headers(self) -> dict[str, str]:
        if self.password and not self.session_id:
            self._authenticate()
        headers = {"Accept": "application/json"}
        if self.session_id:
            headers["X-FTL-SID"] = self.session_id
        if self.csrf_token:
            headers["X-FTL-CSRF"] = self.csrf_token
        return headers

    def _send_raw(
        self,
        method: str,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        json_data: Any = None,
        files: Any = None,
        form_data: Any = None,
        authenticated: bool = True,
    ) -> requests.Response:
        if self._closed:
            raise PiHole6ConnectionError("Connection is already closed")
        url = self._url(endpoint)
        headers = self._headers() if authenticated else {"Accept": "application/json"}
        started = time.perf_counter()
        try:
            request_kwargs: dict[str, Any] = {
                "method": method,
                "url": url,
                "headers": headers,
                "params": params,
                "json": json_data,
                "files": files,
                "data": form_data,
                "timeout": self.timeout,
            }
            if self.ca_bundle_path:
                request_kwargs["verify"] = self.ca_bundle_path
            response = self.session.request(**request_kwargs)
        except requests.exceptions.SSLError as exc:
            self._record_failure(ConnectionState.TLS_ERROR, exc)
            raise PiHole6ConnectionError(
                f"TLS verification failed for {url}. Check the certificate or configured CA bundle."
            ) from exc
        except requests.Timeout as exc:
            self._record_failure(ConnectionState.OFFLINE, exc)
            raise PiHole6ConnectionError(f"Request timed out: {url}") from exc
        except requests.ConnectionError as exc:
            self._record_failure(ConnectionState.OFFLINE, exc)
            raise PiHole6ConnectionError(
                f"Could not connect to {url}. Check the Pi-hole address, protocol, and port."
            ) from exc
        except (
            requests.exceptions.InvalidSchema,
            requests.exceptions.InvalidURL,
            requests.exceptions.MissingSchema,
        ) as exc:
            self._record_failure(ConnectionState.INVALID_CONFIG, exc)
            raise PiHole6ConnectionError(f"Invalid Pi-hole URL: {url}") from exc
        except requests.RequestException as exc:
            self._record_failure(ConnectionState.API_ERROR, exc)
            raise PiHole6ConnectionError(f"Request failed for {url}: {exc}") from exc
        latency_ms = round((time.perf_counter() - started) * 1000)
        self._record_response(response, latency_ms)
        return response

    def request(
        self,
        method: str,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        data: Any = None,
        files: Any = None,
        binary: bool = False,
    ) -> Any:
        with self._lock:
            method = method.upper()
            multipart = files is not None
            response = self._send_raw(
                method,
                endpoint,
                params=params,
                json_data=None if multipart else data,
                files=files,
                form_data=data if multipart else None,
            )

            if response.status_code == 401 and self.password:
                self.session_id = None
                self.csrf_token = None
                response = self._send_raw(
                    method,
                    endpoint,
                    params=params,
                    json_data=None if multipart else data,
                    files=files,
                    form_data=data if multipart else None,
                )

            if not 200 <= response.status_code < 300:
                payload = self._try_json(response)
                message = self._error_message(payload, response.reason or "Request failed")
                if response.status_code == 401:
                    raise PiHole6AuthenticationError(message)
                raise PiHole6HTTPError(response.status_code, message, payload)

            if binary:
                return response.content
            if response.status_code == 204 or not response.content.strip():
                return {}
            payload = self._try_json(response)
            return payload if payload is not None else response.text

    @staticmethod
    def _try_json(response: requests.Response) -> Any:
        try:
            return response.json()
        except requests.JSONDecodeError:
            return None

    @classmethod
    def _decode_json(cls, response: requests.Response) -> dict[str, Any]:
        if not 200 <= response.status_code < 300:
            payload = cls._try_json(response)
            message = cls._error_message(payload, response.reason or "Request failed")
            if response.status_code == 401:
                raise PiHole6AuthenticationError(message)
            raise PiHole6HTTPError(response.status_code, message, payload)
        payload = cls._try_json(response)
        if not isinstance(payload, dict):
            raise PiHole6HTTPError(response.status_code, "Expected a JSON object", payload)
        return payload

    @staticmethod
    def _error_message(payload: Any, fallback: str) -> str:
        if isinstance(payload, dict):
            error = payload.get("error")
            if isinstance(error, dict):
                return str(error.get("message") or error.get("key") or fallback)
            session = payload.get("session")
            if isinstance(session, dict):
                return str(session.get("message") or fallback)
        return fallback

    def get(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        *,
        binary: bool = False,
    ) -> Any:
        return self.request("GET", endpoint, params=params, binary=binary)

    def post(self, endpoint: str, data: Any = None, files: Any = None) -> Any:
        return self.request("POST", endpoint, data=data, files=files)

    def put(self, endpoint: str, data: Any = None) -> Any:
        return self.request("PUT", endpoint, data=data)

    def patch(self, endpoint: str, data: Any = None) -> Any:
        return self.request("PATCH", endpoint, data=data)

    def delete(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        data: Any = None,
    ) -> Any:
        return self.request("DELETE", endpoint, params=params, data=data)

    def upload(
        self,
        endpoint: str,
        file_path: str | Path,
        data: dict[str, Any] | None = None,
    ) -> Any:
        path = Path(file_path)
        with path.open("rb") as handle:
            files = {"file": (path.name, handle, "application/gzip")}
            return self.post(endpoint, data=data or {}, files=files)

    def close_session(self) -> None:
        with self._lock:
            if self.session_id:
                try:
                    self.delete("auth")
                finally:
                    self.session_id = None
                    self.csrf_token = None
                    self.validity = None

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self.close_session()
            except Exception:
                log.debug("Pi-hole session logout failed", exc_info=True)
            finally:
                self.session.close()
                self._closed = True
                previous = self._health
                self._health = ConnectionHealth(
                    state=ConnectionState.CLOSED,
                    last_checked_at=time.time(),
                    last_success_at=previous.last_success_at,
                    latency_ms=previous.latency_ms,
                    consecutive_failures=previous.consecutive_failures,
                    status_code=previous.status_code,
                    last_error=previous.last_error,
                )


def encode_path(value: str) -> str:
    return quote(value, safe="")
