"""Validate selections and persist scan progress and host results."""

from __future__ import annotations

from uuid import uuid4

from telesec_api.activity import record_activity
from telesec_api.agents.service import AgentService
from telesec_api.commands.service import CommandService
from telesec_api.discoveries.service import DiscoveryNotFound, DiscoveryService
from telesec_api.scans.models import HostScanResult, ScanProgress
from telesec_api.settings import Settings
from telesec_api.storage import JsonStore
from telesec_api.time import isoformat, utc_now


class ScanError(RuntimeError):
    pass


class ScanNotFound(ScanError):
    pass


class InvalidScanSelection(ScanError):
    pass


class ScanOwnershipError(ScanError):
    pass


class ScanService:
    def __init__(
        self,
        store: JsonStore,
        settings: Settings,
        agents: AgentService,
        discoveries: DiscoveryService,
        commands: CommandService,
    ):
        self.store = store
        self.settings = settings
        self.agents = agents
        self.discoveries = discoveries
        self.commands = commands

    def create(
        self,
        *,
        discovery_id: str,
        device_ids: list[str],
        profile: str,
    ) -> dict:
        if len(device_ids) != len(set(device_ids)):
            raise InvalidScanSelection("Each selected device must be unique")
        if not 1 <= len(device_ids) <= self.settings.max_scan_targets:
            raise InvalidScanSelection(
                f"Select between 1 and {self.settings.max_scan_targets} devices"
            )
        try:
            discovery = self.discoveries.get(discovery_id)
        except DiscoveryNotFound as exc:
            raise ScanNotFound from exc
        if discovery["status"] not in {"completed", "partial"}:
            raise InvalidScanSelection("Discovery is not ready for device selection")
        available = {device["device_id"]: device for device in discovery["devices"]}
        targets: list[dict] = []
        for device_id in device_ids:
            device = available.get(device_id)
            if device is None:
                raise InvalidScanSelection(
                    f"Device {device_id} is not in this discovery"
                )
            if device["is_agent"]:
                raise InvalidScanSelection("The scanning agent cannot target itself")
            targets.append(
                {
                    "device_id": device_id,
                    "ip": device["ip"],
                    "hostname": device.get("hostname"),
                    "status": "queued",
                }
            )
        agent = self.agents.get_public(discovery["agent_id"])
        if agent["status"] == "offline":
            raise InvalidScanSelection("Agent is offline")
        scan_id = str(uuid4())
        command = self.commands.create(
            agent_id=discovery["agent_id"],
            command_type="scan_devices",
            payload={
                "scan_id": scan_id,
                "discovery_id": discovery_id,
                "profile": profile,
                "concurrency": self.settings.scan_concurrency,
                "targets": [
                    {"device_id": target["device_id"], "ip": target["ip"]}
                    for target in targets
                ],
            },
        )
        now = isoformat(utc_now())
        record = {
            "scan_id": scan_id,
            "command_id": command["command_id"],
            "discovery_id": discovery_id,
            "agent_id": discovery["agent_id"],
            "profile": profile,
            "status": "queued",
            "total": len(targets),
            "queued": len(targets),
            "running": 0,
            "completed": 0,
            "failed": 0,
            "cancelled": 0,
            "cancel_requested": False,
            "stage": "queued",
            "targets": targets,
            "results": [],
            "created_at": now,
            "started_at": None,
            "completed_at": None,
        }
        self.store.write("scans", scan_id, record)
        record_activity(
            self.store,
            event_type="scan.queued",
            message=f"Scan queued for {len(targets)} selected devices",
            resource_type="scan",
            resource_id=scan_id,
            details={"profile": profile, "device_count": len(targets)},
        )
        return record

    def save_progress(self, agent_id: str, progress: ScanProgress) -> dict:
        scan_id = str(progress.scan_id)
        with self.store.locked():
            record = self._owned(scan_id, agent_id)
            if progress.total != record["total"]:
                raise InvalidScanSelection("Progress total does not match scan")
            accounted = (
                progress.queued
                + progress.running
                + progress.completed
                + progress.failed
                + progress.cancelled
            )
            if accounted != record["total"]:
                raise InvalidScanSelection("Progress counts do not add up to total")
            record.update(
                {
                    "status": progress.status,
                    "stage": progress.stage,
                    "queued": progress.queued,
                    "running": progress.running,
                    "completed": progress.completed,
                    "failed": progress.failed,
                    "cancelled": progress.cancelled,
                }
            )
            if progress.status == "running" and not record["started_at"]:
                record["started_at"] = isoformat(progress.updated_at)
            if progress.status in {"completed", "partial", "failed", "cancelled"}:
                record["completed_at"] = isoformat(progress.updated_at)
            self.store.write("scans", scan_id, record)
            return record

    def save_result(
        self,
        *,
        scan_id: str,
        device_id: str,
        agent_id: str,
        result: HostScanResult,
    ) -> dict:
        with self.store.locked():
            record = self._owned(scan_id, agent_id)
            if str(result.scan_id) != scan_id or result.device_id != device_id:
                raise InvalidScanSelection("Host result identity mismatch")
            target = next(
                (item for item in record["targets"] if item["device_id"] == device_id),
                None,
            )
            if target is None or target["ip"] != result.ip:
                raise InvalidScanSelection("Host result is not a selected target")
            target["status"] = result.status
            serialized = result.model_dump(mode="json")
            record["results"] = [
                item for item in record["results"] if item["device_id"] != device_id
            ]
            record["results"].append(serialized)
            self.store.write("scans", scan_id, record)
            return record

    def request_cancel(self, scan_id: str) -> dict:
        with self.store.locked():
            record = self.get(scan_id)
            if record["status"] in {"completed", "partial", "failed", "cancelled"}:
                return record
            record["cancel_requested"] = True
            record["stage"] = "cancelling"
            self.store.write("scans", scan_id, record)
            return record

    def control(self, scan_id: str, agent_id: str) -> dict:
        record = self._owned(scan_id, agent_id)
        return {
            "scan_id": scan_id,
            "cancel_requested": record["cancel_requested"],
        }

    def get(self, scan_id: str) -> dict:
        record = self.store.read("scans", scan_id)
        if record is None:
            raise ScanNotFound
        return record

    def list(self, agent_id: str | None = None) -> list[dict]:
        records = self.store.list("scans")
        if agent_id is not None:
            records = [item for item in records if item["agent_id"] == agent_id]
        records.sort(key=lambda item: item["created_at"], reverse=True)
        return records

    def observed_cpes(self, scan_id: str, device_id: str) -> set[str]:
        record = self.get(scan_id)
        result = next(
            (item for item in record["results"] if item["device_id"] == device_id),
            None,
        )
        if result is None:
            raise InvalidScanSelection("No completed result exists for this device")
        return {
            cpe
            for port in result["ports"]
            if isinstance((cpe := port.get("cpe")), str) and cpe
        }

    def _owned(self, scan_id: str, agent_id: str) -> dict:
        record = self.get(scan_id)
        if record["agent_id"] != agent_id:
            raise ScanOwnershipError
        return record
