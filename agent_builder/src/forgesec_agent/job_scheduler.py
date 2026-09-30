"""Bounded per-device scan execution with progress and cancellation."""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from pathlib import Path
from typing import Any, Protocol

from forgesec_agent.api_client import ApiClientError
from forgesec_agent.enrollment import AgentIdentity, timestamp
from forgesec_agent.scanning.classifier import classify, exposure_flags
from forgesec_agent.scanning.nmap_runner import (
    NmapExecutionError,
    ScanCancelled,
    ScanTimedOut,
)
from forgesec_agent.scanning.parser import NmapParseError, parse_host_scan_xml
from forgesec_agent.storage import AgentStorage

LOGGER = logging.getLogger(__name__)


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
    ):
        self.client = client
        self.identity = identity
        self.scan_id = scan_id
        self._lock = threading.Lock()
        self._last_control_check = 0.0
        self._cancelled = False

    def __call__(self) -> bool:
        with self._lock:
            now = time.monotonic()
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
        keepalive_interval_seconds: float = 20.0,
    ):
        self.scanner = scanner
        self.storage = storage
        self.scan_data_root = scan_data_root
        self.keepalive_interval_seconds = keepalive_interval_seconds
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
        probe = CancellationProbe(client, identity, scan_id)
        stop_keepalive = threading.Event()

        def report_while_running() -> None:
            while not stop_keepalive.wait(self.keepalive_interval_seconds):
                try:
                    keepalive()
                except Exception:
                    LOGGER.warning("Scan heartbeat failed; retrying", exc_info=True)
                if stop_keepalive.is_set():
                    break
                try:
                    self._report(scan_id, identity, client, "running", "scanning")
                except Exception:
                    LOGGER.warning(
                        "Scan progress refresh failed; retrying", exc_info=True
                    )

        heartbeat_thread = threading.Thread(
            target=report_while_running,
            name="forgesec-scan-heartbeat",
            daemon=True,
        )
        heartbeat_thread.start()
        try:
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
                        saved = self.storage.read_json(
                            self.scan_data_root
                            / scan_id
                            / "hosts"
                            / f"{device_id}.json"
                        )
                        if saved:
                            LOGGER.error(
                                "Host evidence retained locally after delivery failure",
                                exc_info=True,
                            )
                        else:
                            self._write_failure(
                                scan_id,
                                targets,
                                device_id,
                                identity,
                                client,
                                "failed",
                                str(exc),
                            )
                        self._report_activity(scan_id, identity, client)
        finally:
            stop_keepalive.set()
            heartbeat_thread.join(timeout=30)
            if heartbeat_thread.is_alive():
                LOGGER.warning("Scan heartbeat did not stop before final progress")
        counts = self._counts()
        if counts["completed"] == len(targets):
            final_status = "completed"
        elif counts["cancelled"] == len(targets):
            final_status = "cancelled"
        elif counts["failed"] == len(targets):
            final_status = "failed"
        else:
            final_status = "partial"
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
        self._report_activity(scan_id, identity, client)
        started_at = timestamp()
        xml_output: str | None = None
        try:
            xml_output = self.scanner.scan_host(
                target["ip"],
                profile,
                cancel_requested=probe,
            )
            parsed = parse_host_scan_xml(xml_output, expected_ip=target["ip"])
            completed_at = timestamp()
            for port in parsed["ports"]:
                port["evidence_source"] = "nmap"
                port["recorded_at"] = completed_at
            device_type, confidence = classify(
                parsed["ports"],
                parsed["os_matches"],
                target,
            )
            prior_type = target.get("device_type")
            prior_confidence = target.get("classification_confidence") or 0.0
            if prior_type not in {None, "unknown"} and prior_confidence >= confidence:
                device_type, confidence = prior_type, prior_confidence
            result = {
                "schema_version": "1.0",
                "message_type": "host_scan.result",
                "scan_id": scan_id,
                "agent_id": identity.agent_id,
                "device_id": device_id,
                "ip": target["ip"],
                "status": "completed",
                "started_at": started_at,
                "completed_at": completed_at,
                "hostname": (
                    parsed["hostname"]
                    or target.get("hostname")
                    or target.get("snmp_name")
                ),
                "hostname_source": (
                    "nmap" if parsed["hostname"] else
                    "discovery" if target.get("hostname") else
                    "snmp" if target.get("snmp_name") else None
                ),
                "device_type": device_type,
                "classification_confidence": confidence,
                "ports": parsed["ports"],
                "os_matches": parsed["os_matches"],
                "exposure_flags": exposure_flags(parsed["ports"]),
                "raw_xml_sha256": hashlib.sha256(
                    xml_output.encode("utf-8")
                ).hexdigest(),
                "error": None,
            }
            self._persist(scan_id, device_id, xml_output, result)
            self._upload_result(scan_id, device_id, result, identity, client)
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
        except NmapParseError as exc:
            self._finish_failure(
                scan_id, target, identity, client, "failed", str(exc),
                started_at, raw_xml=xml_output,
            )
        self._report_activity(scan_id, identity, client)

    def _finish_failure(
        self,
        scan_id: str,
        target: dict[str, Any],
        identity: AgentIdentity,
        client: ScanProtocolClient,
        status: str,
        error: str,
        started_at: str | None = None,
        raw_xml: str | None = None,
    ) -> None:
        result = self._failure_result(
            scan_id, target, identity, status, error, started_at
        )
        if raw_xml is not None:
            result["raw_xml_sha256"] = hashlib.sha256(
                raw_xml.encode("utf-8")
            ).hexdigest()
        self._persist(scan_id, target["device_id"], raw_xml, result)
        self._upload_result(scan_id, target["device_id"], result, identity, client)
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
            "hostname_source": (
                "discovery" if target.get("hostname") else
                "snmp" if target.get("snmp_name") else None
            ),
            "device_type": target.get("device_type"),
            "classification_confidence": target.get("classification_confidence"),
            "ports": [],
            "os_matches": [],
            "exposure_flags": [],
            "raw_xml_sha256": None,
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

    @staticmethod
    def _upload_result(
        scan_id: str,
        device_id: str,
        result: dict[str, Any],
        identity: AgentIdentity,
        client: ScanProtocolClient,
    ) -> None:
        for attempt in range(3):
            try:
                client.upload_host_result(
                    scan_id, device_id, result, credential=identity.credential
                )
                return
            except (ApiClientError, OSError) as exc:
                if isinstance(exc, ApiClientError) and exc.status_code not in {
                    None, 408, 429, 500, 502, 503, 504,
                }:
                    raise
                if attempt == 2:
                    raise
                LOGGER.warning(
                    "Host result delivery failed; retrying attempt %s", attempt + 2
                )
                time.sleep(attempt + 1)

    def _report_activity(
        self, scan_id: str, identity: AgentIdentity, client: ScanProtocolClient
    ) -> None:
        try:
            self._report(scan_id, identity, client, "running", "scanning")
        except Exception:
            LOGGER.warning("Scan progress refresh failed; retrying", exc_info=True)

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
            with self._state_lock:
                counts = self._counts()
                running_device_ids = [
                    device_id
                    for device_id, state in self._states.items()
                    if state == "running"
                ]
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
                    "running_device_ids": running_device_ids,
                    **counts,
                    "updated_at": timestamp(),
                },
                credential=identity.credential,
            )
