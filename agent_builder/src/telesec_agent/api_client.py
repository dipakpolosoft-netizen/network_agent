"""Small outbound HTTPS client for the agent protocol."""

from __future__ import annotations

import json
import ssl
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from telesec_agent.config import validate_server_url


class ApiClientError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class TelesecApiClient:
    def __init__(self, server_url: str, *, timeout_seconds: float = 15.0):
        self.server_url = validate_server_url(server_url)
        self.timeout_seconds = timeout_seconds
        self.ssl_context = ssl.create_default_context()

    def enroll(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/agent/enroll", payload)

    def heartbeat(
        self,
        payload: dict[str, Any],
        *,
        credential: str,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            "/agent/heartbeat",
            payload,
            credential=credential,
        )

    def next_command(self, *, credential: str) -> dict[str, Any] | None:
        response = self._request(
            "GET",
            "/agent/commands/next",
            credential=credential,
        )
        return response or None

    def command_event(
        self,
        command_id: str,
        payload: dict[str, Any],
        *,
        credential: str,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/agent/commands/{command_id}/events",
            payload,
            credential=credential,
        )

    def upload_discovery(
        self,
        discovery_id: str,
        payload: dict[str, Any],
        *,
        credential: str,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/agent/discoveries/{discovery_id}/devices",
            payload,
            credential=credential,
        )

    def discovery_control(
        self,
        discovery_id: str,
        *,
        credential: str,
    ) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/agent/discoveries/{discovery_id}/control",
            credential=credential,
        )

    def upload_scan_progress(
        self,
        scan_id: str,
        payload: dict[str, Any],
        *,
        credential: str,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/agent/scans/{scan_id}/progress",
            payload,
            credential=credential,
        )

    def upload_host_result(
        self,
        scan_id: str,
        device_id: str,
        payload: dict[str, Any],
        *,
        credential: str,
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            f"/agent/scans/{scan_id}/hosts/{device_id}/result",
            payload,
            credential=credential,
        )

    def scan_control(self, scan_id: str, *, credential: str) -> dict[str, Any]:
        return self._request(
            "GET",
            f"/agent/scans/{scan_id}/control",
            credential=credential,
        )

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        credential: str | None = None,
    ) -> dict[str, Any]:
        body = (
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
            if payload is not None
            else None
        )
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "Telesec-Network-Agent/0.1.0",
        }
        if credential:
            headers["Authorization"] = f"Bearer {credential}"
        request = Request(
            f"{self.server_url}{path}",
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with urlopen(
                request,
                timeout=self.timeout_seconds,
                context=self.ssl_context,
            ) as response:
                response_body = response.read().decode("utf-8")
                return json.loads(response_body) if response_body else {}
        except HTTPError as exc:
            detail = self._error_detail(exc)
            raise ApiClientError(detail, status_code=exc.code) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise ApiClientError(f"Unable to reach Telesec server: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ApiClientError("Telesec server returned invalid JSON") from exc

    @staticmethod
    def _error_detail(error: HTTPError) -> str:
        try:
            document = json.loads(error.read().decode("utf-8"))
            return str(document.get("detail") or f"Server returned HTTP {error.code}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return f"Server returned HTTP {error.code}"
