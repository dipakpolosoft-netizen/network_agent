"""Central single-host Greenbone worker using an existing local gvmd installation."""

from __future__ import annotations

import ipaddress
import os
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from forgesec_api.workers.models import GreenboneEvidence
from forgesec_api.workers.runtime_client import (
    WorkerClient,
    WorkerLeaseLost,
    WorkerRuntimeError,
)

VERSION = "0.1.0-greenbone"
MAX_SCAN_SECONDS = 4 * 3600
POLL_SECONDS = 10
MAX_FINDINGS = 50


@dataclass(frozen=True)
class GreenboneSettings:
    socket_path: Path
    username: str
    password: str
    config_id: str
    scanner_id: str
    port_list_id: str

    @classmethod
    def from_env(cls) -> GreenboneSettings:
        required = (
            "FORGESEC_GREENBONE_SOCKET",
            "FORGESEC_GREENBONE_USERNAME",
            "FORGESEC_GREENBONE_PASSWORD",
            "FORGESEC_GREENBONE_CONFIG_ID",
            "FORGESEC_GREENBONE_SCANNER_ID",
            "FORGESEC_GREENBONE_PORT_LIST_ID",
        )
        missing = [name for name in required if not os.environ.get(name)]
        if missing:
            raise WorkerRuntimeError("Missing Greenbone worker configuration")
        try:
            ids = [str(UUID(os.environ[name])) for name in required[-3:]]
        except ValueError as exc:
            raise WorkerRuntimeError("Greenbone resource IDs must be UUIDs") from exc
        return cls(
            socket_path=Path(os.environ[required[0]]).resolve(),
            username=os.environ[required[1]],
            password=os.environ[required[2]],
            config_id=ids[0],
            scanner_id=ids[1],
            port_list_id=ids[2],
        )


def open_gmp(settings: GreenboneSettings):
    try:
        from gvm.connections import UnixSocketConnection
        from gvm.protocols.gmp import GMP
        from gvm.transforms import EtreeCheckCommandTransform
    except ImportError as exc:
        raise WorkerRuntimeError(
            "Install the greenbone API extra on the worker"
        ) from exc
    connection = UnixSocketConnection(path=settings.socket_path, timeout=60)
    return GMP(connection, transform=EtreeCheckCommandTransform())


def _target(job: dict) -> str:
    if (
        job.get("schema_version") != "1.0"
        or job.get("capability") != "greenbone_assessment"
        or job.get("assessment_profile") != "greenbone_single_host"
        or job.get("profile") != "full_tcp"
        or job.get("target_port") is not None
        or job.get("target_scheme") is not None
        or job.get("template_profile") is not None
    ):
        raise WorkerRuntimeError("Unsupported Greenbone job")
    try:
        UUID(job["job_id"])
        UUID(job["lease_id"])
        UUID(job["source_asset_id"])
        UUID(job["source_scan_id"])
        return str(ipaddress.IPv4Address(job["target_ip"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise WorkerRuntimeError("Invalid Greenbone job target") from exc


def _id(response) -> str:
    try:
        return str(UUID(response.get("id")))
    except (TypeError, ValueError) as exc:
        raise WorkerRuntimeError("Greenbone did not return a resource ID") from exc


def _task_name(job_id: str) -> str:
    return f"ForgeSec advanced {UUID(job_id)}"


def _find_named(response, tag: str, name: str):
    matches = [item for item in response.findall(tag) if item.findtext("name") == name]
    if len(matches) > 1:
        raise WorkerRuntimeError("Duplicate Greenbone resources for this job")
    return matches[0] if matches else None


def _task_status(response) -> tuple[str, int | None, str | None]:
    task = response.find("task")
    if task is None:
        raise WorkerRuntimeError("Greenbone task is missing")
    phase = task.findtext("status") or "Unknown"
    raw_progress = task.findtext("progress")
    try:
        progress = max(0, min(100, int(raw_progress))) if raw_progress else None
    except ValueError:
        progress = None
    report = task.find("last_report/report")
    report_id = report.get("id") if report is not None else None
    return phase, progress, report_id


def _findings(response, target_ip: str, report_id: str) -> tuple[list[dict], bool]:
    report = response.find("report")
    if report is None or report.get("id") != report_id:
        raise WorkerRuntimeError("Greenbone returned the wrong report")
    findings: list[dict] = []
    results = report.findall(".//results/result")
    for item in results[:MAX_FINDINGS]:
        host = item.findtext("host")
        if host != target_ip:
            raise WorkerRuntimeError("Greenbone reported an out-of-scope host")
        try:
            result_id = str(UUID(item.get("id")))
            severity = float(item.findtext("severity") or "0")
        except (TypeError, ValueError) as exc:
            raise WorkerRuntimeError("Greenbone result is malformed") from exc
        refs = item.findall("nvt/refs/ref")
        cves = [
            ref.get("id")
            for ref in refs
            if ref.get("type", "").lower() == "cve" and ref.get("id")
        ][:10]
        findings.append(
            {
                "result_id": result_id,
                "name": (item.findtext("name") or "Unnamed finding")[:200],
                "severity": severity,
                "host": host,
                "port": (item.findtext("port") or "")[:48],
                "nvt_oid": (item.find("nvt").get("oid") or "")[:128]
                if item.find("nvt") is not None
                else None,
                "cves": cves,
            }
        )
    return findings, len(results) > MAX_FINDINGS


def run_greenbone(
    job: dict,
    settings: GreenboneSettings,
    *,
    on_tick: Callable[[int | None, str], None],
    gmp_factory: Callable = open_gmp,
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    target_ip = _target(job)
    name = _task_name(job["job_id"])
    task_id: str | None = None
    started = False
    try:
        with gmp_factory(settings) as gmp:
            gmp.authenticate(settings.username, settings.password)
            on_tick(None, "Preparing")
            target = _find_named(
                gmp.get_targets(filter_string=f"name~{job['job_id']} rows=-1"),
                "target",
                name,
            )
            if target is None:
                target_id = _id(
                    gmp.create_target(
                        name=name,
                        hosts=[target_ip],
                        port_list_id=settings.port_list_id,
                    )
                )
            else:
                target_id = _id(target)
                saved = gmp.get_target(target_id).find("target")
                if (
                    saved is None
                    or saved.findtext("hosts") != target_ip
                    or saved.find("port_list") is None
                    or saved.find("port_list").get("id") != settings.port_list_id
                    or any(
                        saved.find(tag) is not None and saved.find(tag).get("id")
                        for tag in (
                            "ssh_credential",
                            "smb_credential",
                            "esxi_credential",
                            "snmp_credential",
                        )
                    )
                ):
                    raise WorkerRuntimeError("Greenbone target changed since creation")
            on_tick(None, "Preparing")
            task = _find_named(
                gmp.get_tasks(filter_string=f"name~{job['job_id']} rows=-1"),
                "task",
                name,
            )
            if task is None:
                task_id = _id(
                    gmp.create_task(
                        name=name,
                        config_id=settings.config_id,
                        target_id=target_id,
                        scanner_id=settings.scanner_id,
                    )
                )
            else:
                task_id = _id(task)
            current = gmp.get_task(task_id)
            saved_task = current.find("task")
            if (
                saved_task is None
                or saved_task.find("target") is None
                or saved_task.find("target").get("id") != target_id
                or saved_task.find("config") is None
                or saved_task.find("config").get("id") != settings.config_id
                or saved_task.find("scanner") is None
                or saved_task.find("scanner").get("id") != settings.scanner_id
                or (
                    saved_task.find("schedule") is not None
                    and saved_task.find("schedule").get("id")
                )
                or saved_task.find("alerts/alert") is not None
            ):
                raise WorkerRuntimeError("Greenbone task configuration changed")
            phase, progress, report_id = _task_status(current)
            if phase == "New":
                on_tick(None, "Starting")
                response = gmp.start_task(task_id)
                report_id = response.findtext("report_id") or report_id
                started = True
            elif phase in {"Requested", "Queued", "Running", "Done"}:
                started = phase != "Done"
            else:
                raise WorkerRuntimeError(f"Greenbone task cannot resume from {phase}")
            deadline = time.monotonic() + MAX_SCAN_SECONDS
            while phase != "Done":
                if time.monotonic() >= deadline:
                    raise WorkerRuntimeError("Greenbone scan exceeded four hours")
                on_tick(progress, phase)
                sleep(POLL_SECONDS)
                current = gmp.get_task(task_id)
                phase, progress, latest_report = _task_status(current)
                report_id = latest_report or report_id
                if phase in {
                    "Stopped",
                    "Interrupted",
                    "Stop Requested",
                    "Delete Requested",
                }:
                    raise WorkerRuntimeError(f"Greenbone task ended in {phase}")
            on_tick(100, "Collecting results")
            if not report_id:
                raise WorkerRuntimeError("Greenbone task has no report")
            report_id = str(UUID(report_id))
            response = gmp.get_report(
                report_id,
                filter_string="rows=51 sort-reverse=severity",
                details=True,
            )
            findings, truncated = _findings(response, target_ip, report_id)
            evidence = {
                "schema_version": "1.0",
                "engine": "greenbone",
                "target_ip": target_ip,
                "assessment_profile": "greenbone_single_host",
                "task_id": task_id,
                "report_id": report_id,
                "findings": findings,
                "truncated": truncated,
            }
            return GreenboneEvidence.model_validate(evidence).model_dump(mode="json")
    except BaseException:
        if task_id and started:
            try:
                with gmp_factory(settings) as gmp:
                    gmp.authenticate(settings.username, settings.password)
                    gmp.stop_task(task_id)
            except Exception:
                print(
                    "Could not stop Greenbone task after worker failure",
                    file=sys.stderr,
                )
        raise


def run_forever(client: WorkerClient, settings: GreenboneSettings) -> None:
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

            def keep_lease(
                progress: int | None, phase: str, claimed_job: dict = job
            ) -> None:
                nonlocal last_heartbeat, last_renewal
                current = time.monotonic()
                if current - last_heartbeat >= 25:
                    client.heartbeat()
                    last_heartbeat = current
                if current - last_renewal >= 30:
                    try:
                        client.renew(claimed_job, progress=progress, phase=phase)
                    except WorkerRuntimeError as exc:
                        raise WorkerLeaseLost("Greenbone job lease was lost") from exc
                    last_renewal = current

            try:
                evidence = run_greenbone(job, settings, on_tick=keep_lease)
                client.finish(
                    job,
                    "completed",
                    f"{len(evidence['findings'])} Greenbone findings returned",
                    evidence,
                )
            except WorkerLeaseLost:
                print("Greenbone lease lost; stop requested", file=sys.stderr)
            except WorkerRuntimeError as exc:
                client.finish(job, "failed", str(exc)[:2000], {})
            except Exception:
                client.finish(job, "failed", "Greenbone manager request failed", {})
        except WorkerRuntimeError as exc:
            if "HTTP 401" in str(exc):
                raise
            print(str(exc), file=sys.stderr)
            time.sleep(10)


def main() -> None:
    if os.name != "posix":
        raise WorkerRuntimeError("The Greenbone worker requires a Unix socket host")
    settings = GreenboneSettings.from_env()
    if not settings.socket_path.is_socket():
        raise WorkerRuntimeError("Greenbone gvmd socket is unavailable")
    client = WorkerClient(
        os.environ["FORGESEC_API_URL"],
        os.environ["FORGESEC_WORKER_ID"],
        os.environ["FORGESEC_WORKER_CREDENTIAL"],
        capability="greenbone_assessment",
        version=VERSION,
    )
    try:
        run_forever(client, settings)
    except KeyboardInterrupt:
        return


if __name__ == "__main__":
    main()
