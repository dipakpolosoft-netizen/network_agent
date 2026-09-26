"""Outbound central worker for one approved, read-only Nuclei template."""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from forgesec_api.workers.models import NucleiEvidence
from forgesec_api.workers.runtime_client import (
    WorkerClient,
    WorkerLeaseLost,
    WorkerRuntimeError,
)
from forgesec_api.workers.runtime_client import (
    _base_url as _base_url,
)

TEMPLATE_ID = "forgesec-http-missing-x-content-type-options"
TEMPLATE_PATH = Path(__file__).parent / "templates" / f"{TEMPLATE_ID}.yaml"
MAX_RUN_SECONDS = 120
MAX_OUTPUT_BYTES = 64 * 1024
POLL_SECONDS = 5
VERSION = "0.1.0-nuclei"


def _target(job: dict) -> str:
    if (
        job.get("schema_version") != "1.0"
        or job.get("capability") != "vulnerability_assessment"
        or job.get("template_profile") != "http_baseline"
    ):
        raise WorkerRuntimeError("Unsupported scanner job")
    try:
        UUID(job["job_id"])
        UUID(job["lease_id"])
        address = ipaddress.IPv4Address(job["target_ip"])
        port = int(job["target_port"])
    except (KeyError, ValueError, TypeError) as exc:
        raise WorkerRuntimeError("Invalid scanner job target") from exc
    if port < 1 or port > 65535 or job.get("target_scheme") not in {"http", "https"}:
        raise WorkerRuntimeError("Invalid scanner job protocol")
    return f"{job['target_scheme']}://{address}:{port}"


def build_command(binary: Path, target: str, output: Path) -> list[str]:
    if not binary.is_file() or not TEMPLATE_PATH.is_file():
        raise WorkerRuntimeError("Nuclei binary or ForgeSec template is missing")
    return [
        str(binary.resolve()),
        "-u",
        target,
        "-t",
        str(TEMPLATE_PATH.resolve()),
        "-jle",
        str(output),
        "-silent",
        "-nc",
        "-or",
        "-ot",
        "-ni",
        "-duc",
        "-dr",
        "-rl",
        "2",
        "-c",
        "1",
        "-timeout",
        "5",
        "-retries",
        "0",
    ]


def _matched_target(value: str, target: str) -> bool:
    try:
        candidate = urlsplit(value)
        expected = urlsplit(target)
        return (
            candidate.scheme == expected.scheme
            and candidate.hostname == expected.hostname
            and candidate.port == expected.port
            and candidate.username is None
            and candidate.password is None
            and candidate.path in {"", "/"}
            and not candidate.query
            and not candidate.fragment
        )
    except ValueError:
        return False


def parse_findings(output: Path, target: str) -> list[dict[str, str]]:
    if not output.exists():
        return []
    if output.stat().st_size > MAX_OUTPUT_BYTES:
        raise WorkerRuntimeError("Nuclei output exceeded the evidence limit")
    findings: list[dict[str, str]] = []
    for line in output.read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise WorkerRuntimeError("Nuclei output was not valid JSONL") from exc
        if not isinstance(item, dict):
            raise WorkerRuntimeError("Nuclei output was not a finding object")
        matched_at = item.get("matched-at")
        if (
            item.get("template-id") != TEMPLATE_ID
            or not isinstance(matched_at, str)
            or not _matched_target(matched_at, target)
        ):
            raise WorkerRuntimeError("Nuclei returned out-of-policy evidence")
        if findings:
            raise WorkerRuntimeError("Nuclei returned duplicate template evidence")
        findings.append(
            {
                "template_id": TEMPLATE_ID,
                "severity": "low",
                "title": "Missing X-Content-Type-Options header",
                "matched_at": matched_at,
            }
        )
    return findings


def _child_env(temp_dir: Path) -> dict[str, str]:
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "TMP", "TEMP", "LANG"}
    environment = {
        key: value for key, value in os.environ.items() if key.upper() in allowed
    }
    environment.update({"HOME": str(temp_dir), "USERPROFILE": str(temp_dir)})
    environment["XDG_CONFIG_HOME"] = str(temp_dir)
    environment["APPDATA"] = str(temp_dir)
    return environment


def run_nuclei(
    job: dict,
    binary: Path,
    *,
    on_tick: Callable[[], None],
) -> dict[str, Any]:
    target = _target(job)
    with tempfile.TemporaryDirectory(prefix="forgesec-nuclei-") as directory:
        temporary = Path(directory)
        output = temporary / "findings.jsonl"
        command = build_command(binary, target, output)
        with (temporary / "stderr.log").open("wb") as stderr:
            process = subprocess.Popen(
                command,
                cwd=temporary,
                env=_child_env(temporary),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=stderr,
            )
            deadline = time.monotonic() + MAX_RUN_SECONDS
            try:
                while process.poll() is None:
                    if time.monotonic() >= deadline:
                        raise WorkerRuntimeError("Nuclei exceeded the 120-second limit")
                    on_tick()
                    time.sleep(1)
            except Exception:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                raise
        if process.returncode != 0:
            raise WorkerRuntimeError(f"Nuclei exited with code {process.returncode}")
        evidence = {
            "schema_version": "1.0",
            "engine": "nuclei",
            "target_url": target,
            "template_profile": "http_baseline",
            "findings": parse_findings(output, target),
        }
        return NucleiEvidence.model_validate(evidence).model_dump(mode="json")


def run_forever(client: WorkerClient, binary: Path) -> None:
    if not binary.is_file() or not TEMPLATE_PATH.is_file():
        raise WorkerRuntimeError("Nuclei binary or ForgeSec template is missing")
    last_heartbeat = 0.0
    while True:
        try:
            now = time.monotonic()
            if now - last_heartbeat >= 25:
                client.heartbeat()
                last_heartbeat = now
            job = client.claim()
            if job is None:
                time.sleep(POLL_SECONDS)
                continue
            last_renewal = time.monotonic()

            def keep_lease(claimed_job: dict = job) -> None:
                nonlocal last_heartbeat, last_renewal
                current = time.monotonic()
                if current - last_heartbeat >= 25:
                    client.heartbeat()
                    last_heartbeat = current
                if current - last_renewal >= 45:
                    try:
                        client.renew(claimed_job)
                    except WorkerRuntimeError as exc:
                        raise WorkerLeaseLost("Scanner lease was lost") from exc
                    last_renewal = current

            try:
                evidence = run_nuclei(job, binary, on_tick=keep_lease)
                client.finish(
                    job,
                    "completed",
                    f"{len(evidence['findings'])} web configuration observations",
                    evidence,
                )
            except WorkerLeaseLost:
                print("Scanner lease was lost; child process stopped", file=sys.stderr)
            except WorkerRuntimeError as exc:
                client.finish(job, "failed", str(exc)[:2000], {})
        except WorkerRuntimeError as exc:
            if "HTTP 401" in str(exc):
                raise
            print(str(exc), file=sys.stderr)
            time.sleep(10)


def main() -> None:
    client = WorkerClient(
        os.environ["FORGESEC_API_URL"],
        os.environ["FORGESEC_WORKER_ID"],
        os.environ["FORGESEC_WORKER_CREDENTIAL"],
        capability="vulnerability_assessment",
        version=VERSION,
    )
    binary = Path(os.environ["FORGESEC_NUCLEI_BINARY"]).resolve()
    try:
        run_forever(client, binary)
    except KeyboardInterrupt:
        return


if __name__ == "__main__":
    main()
