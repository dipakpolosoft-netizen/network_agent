"""Bounded per-device scan execution with progress and cancellation."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from pathlib import Path
from typing import Any, Protocol

from forgesec_agent.enrollment import AgentIdentity, timestamp
from forgesec_agent.scanning.classifier import classify, exposure_flags
from forgesec_agent.scanning.nmap_runner import (
    NmapExecutionError,
    ScanCancelled,
    ScanTimedOut,
)
from forgesec_agent.scanning.parser import parse_host_scan_xml
from forgesec_agent.storage import AgentStorage


class ScanProtocolClient(Protocol):
    def heartbeat(
        self, payload: dict[str, Any], *, credential: str
    ) -> dict[str, Any]: ...

    def command_event(
        self,
        command_id: str,
        payload: dict[str, Any],
        *,
        credential: str,
    ) -> dict[str, Any]: ...

    def upload_scan_progress(
        self, scan_id: str, payload: dict[str, Any], *, credential: str
    ) -> dict[str, Any]: ...

    def upload_host_result(
        self,
        scan_id: str,
        device_id: str,
        payload: dict[str, Any],
        *,
        credential: str,
    ) -> dict[str, Any]: ...

    def scan_control(self, scan_id: str, *, credential: str) -> dict[str, Any]: ...


class HostScanner(Protocol):
    def scan_host(
        self,
        ip: str,
        profile: str,
        *,
        cancel_requested: Callable[[], bool],
    ) -> str: ...


class CancellationProbe:
    def __init__(
        self,
        client: ScanProtocolClient,
        identity: AgentIdentity,
        scan_id: str,
        keepalive: Callable[[], None],
    ):
        self.client = client
        self.identity = identity
        self.scan_id = scan_id
        self.keepalive = keepalive
        self._lock = threading.Lock()
        self._last_control_check = 0.0
        self._last_keepalive = 0.0
        self._cancelled = False

    def __call__(self) -> bool:
        with self._lock:
            now = time.monotonic()
            if now - self._last_keepalive >= 20:
                self.keepalive()
                self._last_keepalive = now
            if now - self._last_control_check >= 2:
                control = self.client.scan_control(
                    self.scan_id,
                    credential=self.identity.credential,
                )
                self._cancelled = bool(control["cancel_requested"])
                self._last_control_check = now
            return self._cancelled


class ScanScheduler:
    def __init__(
        self,
        scanner: HostScanner,
        storage: AgentStorage,
        scan_data_root: Path,
    ):
        self.scanner = scanner
        self.storage = storage
        self.scan_data_root = scan_data_root
        self._state_lock = threading.RLock()
        self._upload_lock = threading.Lock()
        self._states: dict[str, str] = {}

    def run(
        self,
        *,
        scan_id: str,
        profile: str,
        targets: list[dict[str, Any]],
        concurrency: int,
        identity: AgentIdentity,
        client: ScanProtocolClient,
        keepalive: Callable[[], None],
    ) -> str:
        workers = max(1, min(concurrency, 3, len(targets)))
        self._states = {target["device_id"]: "queued" for target in targets}
        probe = CancellationProbe(client, identity, scan_id, keepalive)
        self._report(scan_id, identity, client, "running", "queued")
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(
                    self._scan_one,
                    scan_id,
                    profile,
                    target,
                    identity,
                    client,
                    probe,
                ): target["device_id"]
                for target in targets
            }
            for future in as_completed(futures):
                device_id = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    with self._state_lock:
                        self._states[device_id] = "failed"
                    self._write_failure(
                        scan_id,
                        targets,
                        device_id,
                        identity,
                        client,
                        "failed",
                        str(exc),
                    )
                    self._report(scan_id, identity, client, "running", "scanning")
        counts = self._counts()
        if counts["failed"] or counts["cancelled"]:
            final_status = (
                "cancelled" if counts["cancelled"] == len(targets) else "partial"
            )
        else:
            final_status = "completed"
        self._report(scan_id, identity, client, final_status, "completed")
        return final_status

    def _scan_one(
        self,
        scan_id: str,
        profile: str,
        target: dict[str, Any],
        identity: AgentIdentity,
        client: ScanProtocolClient,
        probe: CancellationProbe,
    ) -> None:
        device_id = target["device_id"]
        if probe():
            self._finish_failure(
                scan_id, target, identity, client, "cancelled", "Scan cancelled"
            )
            return
        with self._state_lock:
            self._states[device_id] = "running"
        self._report(scan_id, identity, client, "running", "scanning")
        started_at = timestamp()
        try:
            xml_output = self.scanner.scan_host(
                target["ip"],
                profile,
                cancel_requested=probe,
            )
            parsed = parse_host_scan_xml(xml_output)
            device_type, confidence = classify(
                parsed["ports"],
                parsed["os_matches"],
                target,
            )
            result = {
                "schema_version": "1.0",
                "message_type": "host_scan.result",
                "scan_id": scan_id,
                "agent_id": identity.agent_id,
                "device_id": device_id,
                "ip": target["ip"],
                "status": "completed",
                "started_at": started_at,
                "completed_at": timestamp(),
                "hostname": (
                    parsed["hostname"]
                    or target.get("hostname")
                    or target.get("snmp_name")
                ),
                "device_type": device_type,
                "classification_confidence": confidence,
                "ports": parsed["ports"],
                "os_matches": parsed["os_matches"],
                "exposure_flags": exposure_flags(parsed["ports"]),
                "error": None,
            }
            self._persist(scan_id, device_id, xml_output, result)
            client.upload_host_result(
                scan_id,
                device_id,
                result,
                credential=identity.credential,
            )
            with self._state_lock:
                self._states[device_id] = "completed"
        except ScanCancelled as exc:
            self._finish_failure(
                scan_id, target, identity, client, "cancelled", str(exc), started_at
            )
        except ScanTimedOut as exc:
            self._finish_failure(
                scan_id, target, identity, client, "timed_out", str(exc), started_at
            )
        except NmapExecutionError as exc:
            self._finish_failure(
                scan_id, target, identity, client, "failed", str(exc), started_at
            )
        self._report(scan_id, identity, client, "running", "scanning")

    def _finish_failure(
        self,
        scan_id: str,
        target: dict[str, Any],
        identity: AgentIdentity,
        client: ScanProtocolClient,
        status: str,
        error: str,
        started_at: str | None = None,
    ) -> None:
        result = self._failure_result(
            scan_id, target, identity, status, error, started_at
        )
        self._persist(scan_id, target["device_id"], None, result)
        client.upload_host_result(
            scan_id,
            target["device_id"],
            result,
            credential=identity.credential,
        )
        with self._state_lock:
            self._states[target["device_id"]] = (
                "cancelled" if status == "cancelled" else "failed"
            )

    def _write_failure(
        self,
        scan_id: str,
        targets: list[dict[str, Any]],
        device_id: str,
        identity: AgentIdentity,
        client: ScanProtocolClient,
        status: str,
        error: str,
    ) -> None:
        target = next(item for item in targets if item["device_id"] == device_id)
        result = self._failure_result(scan_id, target, identity, status, error, None)
        self._persist(scan_id, device_id, None, result)
        with suppress(Exception):
            client.upload_host_result(
                scan_id,
                device_id,
                result,
                credential=identity.credential,
            )

    @staticmethod
    def _failure_result(
        scan_id: str,
        target: dict[str, Any],
        identity: AgentIdentity,
        status: str,
        error: str,
        started_at: str | None,
    ) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "message_type": "host_scan.result",
            "scan_id": scan_id,
            "agent_id": identity.agent_id,
            "device_id": target["device_id"],
            "ip": target["ip"],
            "status": status,
            "started_at": started_at or timestamp(),
            "completed_at": timestamp(),
            "hostname": target.get("hostname") or target.get("snmp_name"),
            "device_type": target.get("device_type"),
            "classification_confidence": target.get("classification_confidence"),
            "ports": [],
            "os_matches": [],
            "exposure_flags": [],
            "error": error[:4096],
        }

    def _persist(
        self,
        scan_id: str,
        device_id: str,
        xml_output: str | None,
        result: dict[str, Any],
    ) -> None:
        root = self.scan_data_root / scan_id
        if xml_output is not None:
            self.storage.write_text(root / "raw" / f"{device_id}.xml", xml_output)
        self.storage.write_json(root / "hosts" / f"{device_id}.json", result)

    def _counts(self) -> dict[str, int]:
        with self._state_lock:
            values = list(self._states.values())
        return {
            "queued": values.count("queued"),
            "running": values.count("running"),
            "completed": values.count("completed"),
            "failed": values.count("failed"),
            "cancelled": values.count("cancelled"),
        }

    def _report(
        self,
        scan_id: str,
        identity: AgentIdentity,
        client: ScanProtocolClient,
        status: str,
        stage: str,
    ) -> None:
        with self._upload_lock:
            counts = self._counts()
            client.upload_scan_progress(
                scan_id,
                {
                    "schema_version": "1.0",
                    "message_type": "scan.progress",
                    "scan_id": scan_id,
                    "agent_id": identity.agent_id,
                    "status": status,
                    "stage": stage,
                    "total": len(self._states),
                    **counts,
                    "updated_at": timestamp(),
                },
                credential=identity.credential,
            )
