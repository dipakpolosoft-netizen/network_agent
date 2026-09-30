"""Read-only readiness checks for a central worker host."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener

from forgesec_api.workers.greenbone_runtime import GreenboneSettings
from forgesec_api.workers.nuclei_runtime import TEMPLATE_PATH, verify_binary
from forgesec_api.workers.runtime_client import (
    WorkerClient,
    WorkerRuntimeError,
    _NoRedirect,
)
from forgesec_api.workers.ssh_inventory_runtime import SshInventorySettings

CAPABILITIES = {
    "nuclei": "vulnerability_assessment",
    "greenbone": "greenbone_assessment",
    "ssh": "credentialed_inventory",
}


def local_issues(kind: str) -> list[str]:
    issues: list[str] = []
    required = ("FORGESEC_API_URL", "FORGESEC_WORKER_ID", "FORGESEC_WORKER_CREDENTIAL")
    missing = [name for name in required if not os.environ.get(name, "").strip()]
    if missing:
        issues.append("Missing worker identity/configuration: " + ", ".join(missing))
    else:
        try:
            WorkerClient(
                os.environ["FORGESEC_API_URL"],
                os.environ["FORGESEC_WORKER_ID"],
                os.environ["FORGESEC_WORKER_CREDENTIAL"],
                capability=CAPABILITIES[kind],
                version="preflight",
            )
        except (ValueError, WorkerRuntimeError):
            issues.append("Worker API URL or worker ID is invalid")

    if kind == "nuclei":
        binary = os.environ.get("FORGESEC_NUCLEI_BINARY", "")
        if not binary or not Path(binary).is_file():
            issues.append("FORGESEC_NUCLEI_BINARY must point to an installed binary")
        else:
            try:
                verify_binary(Path(binary))
            except WorkerRuntimeError as exc:
                issues.append(str(exc))
        if not TEMPLATE_PATH.is_file():
            issues.append("The bundled ForgeSec Nuclei template is missing")
    elif kind == "greenbone":
        if os.name != "posix":
            issues.append("Greenbone worker requires a Unix socket host")
        if importlib.util.find_spec("gvm") is None:
            issues.append("Install the API greenbone extra on this worker host")
        try:
            settings = GreenboneSettings.from_env()
            if not settings.socket_path.is_socket():
                issues.append("Greenbone gvmd socket is unavailable")
        except (OSError, WorkerRuntimeError) as exc:
            issues.append(str(exc))
    else:
        if os.name != "posix":
            issues.append("SSH inventory worker requires a Linux host")
        if importlib.util.find_spec("paramiko") is None:
            issues.append("Install the API ssh-inventory extra on this worker host")
        try:
            SshInventorySettings.from_env()
        except (OSError, WorkerRuntimeError) as exc:
            issues.append(str(exc))
    return issues


def api_health_issue(url: str) -> str | None:
    request = Request(
        f"{url.rstrip('/')}/health", headers={"Accept": "application/json"}
    )
    try:
        with build_opener(_NoRedirect).open(request, timeout=8) as response:
            health = json.loads(response.read(4096))
        if not isinstance(health, dict) or (
            health.get("status") != "ok" or health.get("service") != "forgesec-api"
        ):
            return "API health response does not identify ForgeSec"
        if (
            urlsplit(url).hostname not in {"localhost", "127.0.0.1", "::1"}
            and health.get("environment") != "production"
        ):
            return "Remote worker API is not running in production mode"
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, TypeError):
        return "API health is unreachable or invalid from this worker host"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", choices=CAPABILITIES, required=True)
    parser.add_argument(
        "--offline", action="store_true", help="Skip API health request"
    )
    args = parser.parse_args()
    issues = local_issues(args.worker)
    if not issues and not args.offline:
        health_issue = api_health_issue(os.environ["FORGESEC_API_URL"])
        if health_issue:
            issues.append(health_issue)
    if issues:
        for issue in issues:
            print(f"FAIL {issue}")
        return 1
    print("Worker host preflight passed. No job was claimed or target contacted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
