"""Outbound API client shared by central scanner processes."""

from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import UUID

from forgesec_api.workers.models import Capability


class WorkerRuntimeError(RuntimeError):
    pass


class WorkerLeaseLost(WorkerRuntimeError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _base_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise WorkerRuntimeError("Worker API URL must be an origin")
    if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1"}:
        raise WorkerRuntimeError("A non-loopback worker API URL requires HTTPS")
    return value.rstrip("/")


class WorkerClient:
    def __init__(
        self,
        url: str,
        worker_id: str,
        credential: str,
        *,
        capability: Capability,
        version: str,
    ):
        self.url = _base_url(url)
        self.worker_id = str(UUID(worker_id))
        self.credential = credential
        self.capability = capability
        self.version = version
        self.opener = build_opener(_NoRedirect)

    def request(
        self, method: str, path: str, payload: dict | None = None
    ) -> dict | None:
        body = json.dumps(payload).encode() if payload is not None else None
        request = Request(
            f"{self.url}{path}",
            data=body,
            method=method,
            headers={
                "Authorization": f"Bearer {self.credential}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with self.opener.open(request, timeout=15) as response:
                if response.status == 204:
                    return None
                try:
                    result = json.loads(response.read(512 * 1024))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise WorkerRuntimeError(
                        "Worker API returned invalid JSON"
                    ) from exc
                if not isinstance(result, dict):
                    raise WorkerRuntimeError("Worker API returned invalid data")
                return result
        except HTTPError as exc:
            raise WorkerRuntimeError(
                f"Worker API rejected {path}: HTTP {exc.code}"
            ) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise WorkerRuntimeError("Worker API connection failed") from exc

    def heartbeat(self) -> None:
        self.request(
            "POST",
            "/worker/heartbeat",
            {
                "schema_version": "1.0",
                "worker_id": self.worker_id,
                "version": self.version,
                "available_capabilities": [self.capability],
            },
        )

    def claim(self) -> dict | None:
        return self.request("GET", "/worker/jobs/next")

    def renew(
        self, job: dict, *, progress: int | None = None, phase: str | None = None
    ) -> None:
        self.request(
            "POST",
            f"/worker/jobs/{UUID(job['job_id'])}/heartbeat",
            {"lease_id": job["lease_id"], "progress": progress, "phase": phase},
        )

    def finish(self, job: dict, status: str, summary: str, evidence: dict) -> None:
        self.request(
            "POST",
            f"/worker/jobs/{UUID(job['job_id'])}/result",
            {
                "schema_version": "1.0",
                "lease_id": job["lease_id"],
                "status": status,
                "summary": summary,
                "evidence": evidence,
            },
        )
