"""Validate selections and persist scan progress and host results."""

from __future__ import annotations

from collections import Counter
from uuid import uuid4

from forgesec_api.activity import record_activity
from forgesec_api.agents.service import AgentService
from forgesec_api.assets.service import AssetService
from forgesec_api.commands.service import CommandNotFound, CommandService
from forgesec_api.discoveries.service import DiscoveryNotFound, DiscoveryService
from forgesec_api.scans.models import HostScanResult, ScanProgress
from forgesec_api.settings import Settings
from forgesec_api.sites.service import SiteService
from forgesec_api.storage import JsonStore
from forgesec_api.time import isoformat, utc_now


class ScanError(RuntimeError):
    pass


class ScanNotFound(ScanError):
    pass


class InvalidScanSelection(ScanError):
    pass


class ScanOwnershipError(ScanError):
    pass


NETWORK_DEVICE_TYPES = {
    "access-point",
    "firewall",
    "network-device",
    "router",
    "switch",
    "voip-phone",
}
SERVER_DEVICE_TYPES = {"database-server", "domain-controller", "nas", "server"}
WORKSTATION_DEVICE_TYPES = {"workstation"}
MANAGEMENT_PORTS = {
    ("tcp", 22),
    ("tcp", 23),
    ("tcp", 80),
    ("tcp", 443),
    ("tcp", 3389),
    ("tcp", 5985),
    ("tcp", 5986),
    ("tcp", 8080),
    ("tcp", 8443),
    ("udp", 161),
}
MAX_CHANGE_ITEMS = 128


class ScanService:
    def __init__(
        self,
        store: JsonStore,
        settings: Settings,
        agents: AgentService,
        discoveries: DiscoveryService,
        commands: CommandService,
        sites: SiteService,
        assets: AssetService,
    ):
        self.store = store
        self.settings = settings
        self.agents = agents
        self.discoveries = discoveries
        self.commands = commands
        self.sites = sites
        self.assets = assets

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
                    "vendor": device.get("vendor"),
                    "snmp_name": device.get("snmp_name"),
                    "snmp_description": device.get("snmp_description"),
                    "snmp_object_id": device.get("snmp_object_id"),
                    "snmp_contact": device.get("snmp_contact"),
                    "snmp_location": device.get("snmp_location"),
                    "snmp_uptime_seconds": device.get("snmp_uptime_seconds"),
                    "snmp_interface_count": device.get("snmp_interface_count"),
                    "snmp_interfaces": device.get("snmp_interfaces") or [],
                    "device_type": device.get("device_type"),
                    "classification_confidence": device.get(
                        "classification_confidence"
                    ),
                    "status": "queued",
                }
            )
        agent = self.agents.get_public(discovery["agent_id"])
        if agent["status"] == "offline":
            raise InvalidScanSelection("Agent is offline")
        if not all(
            self.sites.approved(agent.get("site_id"), target["ip"], profile)
            for target in targets
        ):
            raise InvalidScanSelection(
                "Selected targets or scan profile are outside the site's approved scope"
            )
        scan_id = str(uuid4())
        command = self.commands.create(
            agent_id=discovery["agent_id"],
            command_type="scan_devices",
            payload={
                "scan_id": scan_id,
                "discovery_id": discovery_id,
                "profile": profile,
                "concurrency": self.settings.scan_concurrency,
                "scope_policy": self.sites.policy(agent.get("site_id")),
                "targets": [
                    {
                        "device_id": target["device_id"],
                        "ip": target["ip"],
                        "hostname": target.get("hostname"),
                        "vendor": target.get("vendor"),
                        "snmp_name": target.get("snmp_name"),
                        "snmp_description": target.get("snmp_description"),
                        "snmp_object_id": target.get("snmp_object_id"),
                        "snmp_contact": target.get("snmp_contact"),
                        "snmp_location": target.get("snmp_location"),
                        "snmp_uptime_seconds": target.get("snmp_uptime_seconds"),
                        "snmp_interface_count": target.get("snmp_interface_count"),
                        "snmp_interfaces": target.get("snmp_interfaces") or [],
                        "device_type": target.get("device_type"),
                        "classification_confidence": target.get(
                            "classification_confidence"
                        ),
                    }
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
        record["summary"] = self._build_summary(record)
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
            record["summary"] = self._build_summary(record)
            self.store.write("scans", scan_id, record)
            self.assets.observe_scan(record, serialized)
            return record

    def request_cancel(self, scan_id: str) -> dict:
        with self.store.locked():
            record = self._record_for_update(scan_id)
            if record["status"] in {"completed", "partial", "failed", "cancelled"}:
                return record
            command = self.commands.get(record["command_id"])
            if command["status"] == "queued":
                self.commands.cancel_pending(
                    record["command_id"], message="Scan cancelled before it started"
                )
                return self._finish_from_command(record, "cancelled", "cancelled")
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
        record = self._reconcile(record)
        return self._with_public_rollups(record, self.store.list("scans"))

    def list(self, agent_id: str | None = None) -> list[dict]:
        records = [self._reconcile(item) for item in self.store.list("scans")]
        if agent_id is not None:
            records = [item for item in records if item["agent_id"] == agent_id]
        records.sort(key=lambda item: item["created_at"], reverse=True)
        return [self._with_public_rollups(item, records) for item in records]

    def observed_cpes(self, scan_id: str, device_id: str) -> set[str]:
        record = self.get(scan_id)
        result = next(
            (item for item in record["results"] if item["device_id"] == device_id),
            None,
        )
        if result is None:
            raise InvalidScanSelection("No completed result exists for this device")
        cpes: set[str] = set()
        for port in result["ports"]:
            cpes.update(_port_cpes(port))
        return cpes

    def observed_cpe_contexts(self, scan_id: str) -> dict[str, list[dict]]:
        record = self.get(scan_id)
        target_by_device = {
            target["device_id"]: target for target in record.get("targets", [])
        }
        contexts: dict[str, list[dict]] = {}
        for result in record.get("results", []):
            device_id = result["device_id"]
            target = target_by_device.get(device_id, {})
            hostname = result.get("hostname") or target.get("hostname")
            for port in result.get("ports") or []:
                for cpe in _port_cpes(port):
                    contexts.setdefault(cpe, []).append(
                        {
                            "device_id": device_id,
                            "ip": result["ip"],
                            "hostname": hostname,
                            "port": port["port"],
                            "protocol": port["protocol"],
                            "service": port.get("service"),
                            "product": port.get("product"),
                            "version": port.get("version"),
                        }
                    )
        return dict(sorted(contexts.items(), key=lambda item: item[0]))

    def _owned(self, scan_id: str, agent_id: str) -> dict:
        record = self._record_for_update(scan_id)
        if record["agent_id"] != agent_id:
            raise ScanOwnershipError
        return record

    def _record_for_update(self, scan_id: str) -> dict:
        record = self.store.read("scans", scan_id)
        if record is None:
            raise ScanNotFound
        return self._with_summary(self._reconcile(record))

    def _reconcile(self, record: dict) -> dict:
        with self.store.locked():
            current = self.store.read("scans", record["scan_id"]) or record
            if current.get("status") not in {"queued", "running", "cancelling"}:
                return current
            try:
                command = self.commands.get(current["command_id"])
            except CommandNotFound:
                return current
            if command["status"] == "cancelled":
                return self._finish_from_command(current, "cancelled", "cancelled")
            if command["status"] in {"expired", "failed"}:
                stage = (
                    "command_expired"
                    if command["status"] == "expired"
                    else "command_failed"
                )
                return self._finish_from_command(current, "failed", stage)
            return current

    def _finish_from_command(self, record: dict, status: str, stage: str) -> dict:
        for target in record["targets"]:
            if target["status"] in {"queued", "running"}:
                target["status"] = status
        completed = sum(item["status"] == "completed" for item in record["targets"])
        cancelled = sum(item["status"] == "cancelled" for item in record["targets"])
        failed = record["total"] - completed - cancelled
        record.update(
            status=status,
            stage=stage,
            queued=0,
            running=0,
            completed=completed,
            failed=failed,
            cancelled=cancelled,
            cancel_requested=record["cancel_requested"] or status == "cancelled",
            completed_at=record["completed_at"] or isoformat(utc_now()),
        )
        record["summary"] = self._build_summary(record)
        self.store.write("scans", record["scan_id"], record)
        record_activity(
            self.store,
            event_type=f"scan.{status}",
            message=f"Scan {stage.replace('_', ' ')}",
            resource_type="scan",
            resource_id=record["scan_id"],
            details={"agent_id": record["agent_id"]},
            severity="error" if status == "failed" else "info",
        )
        return record

    @staticmethod
    def _with_summary(record: dict) -> dict:
        record["summary"] = ScanService._build_summary(record)
        return record

    @staticmethod
    def _with_public_rollups(record: dict, records: list[dict]) -> dict:
        record["summary"] = ScanService._build_summary(record)
        baseline = _previous_comparable_scan(record, records)
        record["change_summary"] = _build_change_summary(record, baseline)
        record["action_summary"] = _build_action_summary(record)
        return record

    @staticmethod
    def _build_summary(record: dict) -> dict:
        targets = record.get("targets") or []
        results = record.get("results") or []
        target_by_device = {target["device_id"]: target for target in targets}

        device_type_counts: Counter[str] = Counter()
        vendor_counts: Counter[str] = Counter()
        service_counts: Counter[str] = Counter()
        severity_counts: Counter[str] = Counter()
        unique_cpes: set[str] = set()
        open_ports = 0
        tcp_ports = 0
        udp_ports = 0
        service_fingerprints = 0
        management_services = 0
        snmp_device_ids: set[str] = set()
        evidence_hosts = 0

        for target in targets:
            device_type = _clean_label(target.get("device_type"))
            if device_type:
                device_type_counts[device_type] += 1
            vendor = _clean_label(target.get("vendor"))
            if vendor:
                vendor_counts[vendor] += 1
            if _target_has_snmp(target):
                snmp_device_ids.add(target["device_id"])

        for result in results:
            target = target_by_device.get(result.get("device_id"), {})
            ports = result.get("ports") or []
            os_matches = result.get("os_matches") or []
            exposure_flags = result.get("exposure_flags") or []
            if ports or os_matches or exposure_flags:
                evidence_hosts += 1

            result_type = _clean_label(result.get("device_type"))
            target_type = _clean_label(target.get("device_type"))
            if result_type and result_type != target_type:
                if target_type and device_type_counts[target_type] > 0:
                    device_type_counts[target_type] -= 1
                device_type_counts[result_type] += 1

            for port in ports:
                protocol = str(port.get("protocol") or "").lower()
                number = port.get("port")
                state = str(port.get("state") or "").lower()
                is_open = state in {"open", "open|filtered"}
                if not is_open:
                    continue
                open_ports += 1
                if protocol == "tcp":
                    tcp_ports += 1
                elif protocol == "udp":
                    udp_ports += 1
                service_counts[_service_label(port)] += 1
                if (protocol, number) in MANAGEMENT_PORTS:
                    management_services += 1
                if protocol == "udp" and number == 161:
                    snmp_device_ids.add(result.get("device_id", ""))
                if _has_fingerprint(port):
                    service_fingerprints += 1
                cpe = port.get("cpe")
                if isinstance(cpe, str) and cpe:
                    unique_cpes.add(cpe)
                for extra_cpe in port.get("cpes") or []:
                    if isinstance(extra_cpe, str) and extra_cpe:
                        unique_cpes.add(extra_cpe)

            for flag in exposure_flags:
                severity = str(flag.get("severity") or "").lower()
                if severity in {"high", "medium", "low", "info"}:
                    severity_counts[severity] += 1

        normalized_type_counts = +device_type_counts
        return {
            "scanned_hosts": len(results),
            "evidence_hosts": evidence_hosts,
            "classified_hosts": sum(normalized_type_counts.values()),
            "network_devices": sum(
                normalized_type_counts.get(device_type, 0)
                for device_type in NETWORK_DEVICE_TYPES
            ),
            "servers": sum(
                normalized_type_counts.get(device_type, 0)
                for device_type in SERVER_DEVICE_TYPES
            ),
            "workstations": sum(
                normalized_type_counts.get(device_type, 0)
                for device_type in WORKSTATION_DEVICE_TYPES
            ),
            "open_ports": open_ports,
            "tcp_ports": tcp_ports,
            "udp_ports": udp_ports,
            "service_fingerprints": service_fingerprints,
            "cpes": len(unique_cpes),
            "exposure_findings": sum(severity_counts.values()),
            "high_exposure_findings": severity_counts["high"],
            "management_services": management_services,
            "snmp_enabled": len(
                {device_id for device_id in snmp_device_ids if device_id}
            ),
            "device_types": _top_counts(normalized_type_counts, limit=12),
            "vendors": _top_counts(vendor_counts, limit=12),
            "services": _top_counts(service_counts, limit=16),
            "severity_counts": {
                "high": severity_counts["high"],
                "medium": severity_counts["medium"],
                "low": severity_counts["low"],
                "info": severity_counts["info"],
            },
        }


def _clean_label(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    label = value.strip()
    return label or None


def _target_has_snmp(target: dict) -> bool:
    return any(
        target.get(key)
        for key in (
            "snmp_name",
            "snmp_description",
            "snmp_object_id",
            "snmp_contact",
            "snmp_location",
            "snmp_interface_count",
        )
    )


def _service_label(port: dict) -> str:
    service = _clean_label(port.get("service")) or str(port.get("port") or "unknown")
    protocol = str(port.get("protocol") or "").lower() or "unknown"
    return f"{service}/{protocol}"


def _has_fingerprint(port: dict) -> bool:
    return any(
        port.get(key)
        for key in (
            "product",
            "version",
            "extrainfo",
            "ostype",
            "devicetype",
            "cpe",
            "cpes",
        )
    )


def _port_cpes(port: dict) -> list[str]:
    if port.get("state") != "open":
        return []
    cpes: list[str] = []
    cpe = port.get("cpe")
    if isinstance(cpe, str) and cpe:
        cpes.append(cpe)
    for extra_cpe in port.get("cpes") or []:
        if isinstance(extra_cpe, str) and extra_cpe not in cpes:
            cpes.append(extra_cpe)
    return cpes


def _top_counts(counter: Counter[str], *, limit: int) -> list[dict]:
    return [
        {"label": label, "count": count}
        for label, count in counter.most_common(limit)
        if count > 0
    ]


def _previous_comparable_scan(record: dict, records: list[dict]) -> dict | None:
    created_at = record.get("created_at")
    if not created_at:
        return None
    candidates = [
        item
        for item in records
        if item.get("scan_id") != record.get("scan_id")
        and item.get("agent_id") == record.get("agent_id")
        and item.get("profile") == record.get("profile")
        and item.get("status") in {"completed", "partial"}
        and item.get("created_at")
        and item.get("created_at") < created_at
        and item.get("results")
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda item: item["created_at"])


def _build_change_summary(record: dict, baseline: dict | None) -> dict:
    if baseline is None:
        return _empty_change_summary()

    current_hosts = _host_map(record)
    baseline_hosts = _host_map(baseline)
    current_ports = _open_port_map(record)
    baseline_ports = _open_port_map(baseline)
    current_findings = _finding_map(record)
    baseline_findings = _finding_map(baseline)

    new_host_ips = sorted(
        set(current_hosts) - set(baseline_hosts),
        key=_ip_sort_key,
    )
    missing_host_ips = sorted(
        set(baseline_hosts) - set(current_hosts),
        key=_ip_sort_key,
    )
    opened_port_keys = sorted(
        set(current_ports) - set(baseline_ports),
        key=lambda item: (_ip_sort_key(item[0]), item[1], item[2]),
    )
    closed_port_keys = sorted(
        set(baseline_ports) - set(current_ports),
        key=lambda item: (_ip_sort_key(item[0]), item[1], item[2]),
    )
    new_finding_keys = sorted(
        set(current_findings) - set(baseline_findings),
        key=lambda item: (_ip_sort_key(item[0]), item[1]),
    )
    resolved_finding_keys = sorted(
        set(baseline_findings) - set(current_findings),
        key=lambda item: (_ip_sort_key(item[0]), item[1]),
    )

    return {
        "baseline_scan_id": baseline.get("scan_id"),
        "baseline_created_at": baseline.get("created_at"),
        "baseline_profile": baseline.get("profile"),
        "new_host_count": len(new_host_ips),
        "missing_host_count": len(missing_host_ips),
        "opened_port_count": len(opened_port_keys),
        "closed_port_count": len(closed_port_keys),
        "new_finding_count": len(new_finding_keys),
        "resolved_finding_count": len(resolved_finding_keys),
        "new_hosts": [current_hosts[ip] for ip in new_host_ips[:MAX_CHANGE_ITEMS]],
        "missing_hosts": [
            baseline_hosts[ip] for ip in missing_host_ips[:MAX_CHANGE_ITEMS]
        ],
        "opened_ports": [
            current_ports[key] for key in opened_port_keys[:MAX_CHANGE_ITEMS]
        ],
        "closed_ports": [
            baseline_ports[key] for key in closed_port_keys[:MAX_CHANGE_ITEMS]
        ],
        "new_findings": [
            current_findings[key] for key in new_finding_keys[:MAX_CHANGE_ITEMS]
        ],
        "resolved_findings": [
            baseline_findings[key] for key in resolved_finding_keys[:MAX_CHANGE_ITEMS]
        ],
    }


def _empty_change_summary() -> dict:
    return {
        "baseline_scan_id": None,
        "baseline_created_at": None,
        "baseline_profile": None,
        "new_host_count": 0,
        "missing_host_count": 0,
        "opened_port_count": 0,
        "closed_port_count": 0,
        "new_finding_count": 0,
        "resolved_finding_count": 0,
        "new_hosts": [],
        "missing_hosts": [],
        "opened_ports": [],
        "closed_ports": [],
        "new_findings": [],
        "resolved_findings": [],
    }


def _build_action_summary(record: dict) -> dict:
    summary = record.get("summary") or {}
    changes = record.get("change_summary") or _empty_change_summary()
    severity = summary.get("severity_counts") or {}
    high_findings = int(summary.get("high_exposure_findings") or 0)
    medium_findings = int(severity.get("medium") or 0)
    low_findings = int(severity.get("low") or 0)
    opened_ports = int(changes.get("opened_port_count") or 0)
    new_findings = int(changes.get("new_finding_count") or 0)
    management_services = int(summary.get("management_services") or 0)
    snmp_enabled = int(summary.get("snmp_enabled") or 0)
    cpes = int(summary.get("cpes") or 0)
    score = min(
        100,
        high_findings * 18
        + medium_findings * 8
        + low_findings * 3
        + new_findings * 12
        + opened_ports * 4
        + min(management_services * 3, 18)
        + min(snmp_enabled * 3, 12)
        + min(cpes * 2, 10),
    )
    actions: list[dict] = []
    if high_findings:
        actions.append(
            {
                "priority": "high",
                "category": "exposure",
                "title": "Review high-severity exposure findings",
                "detail": (
                    "High-severity rule-based observations should be validated "
                    "first and assigned to an owner for remediation."
                ),
                "affected_count": high_findings,
            }
        )
    if new_findings:
        actions.append(
            {
                "priority": "high",
                "category": "change",
                "title": "Investigate new exposure findings",
                "detail": (
                    "New findings appeared compared with the previous same-profile "
                    "scan. Confirm whether these are expected changes."
                ),
                "affected_count": new_findings,
            }
        )
    if opened_ports:
        actions.append(
            {
                "priority": "medium",
                "category": "change",
                "title": "Validate newly opened services",
                "detail": (
                    "Recently opened ports may indicate a new application, changed "
                    "firewall policy, or unexpected service exposure."
                ),
                "affected_count": opened_ports,
            }
        )
    if management_services:
        actions.append(
            {
                "priority": "medium",
                "category": "management",
                "title": "Restrict management service access",
                "detail": (
                    "Confirm SSH, web admin, RDP, WinRM, and SNMP services are "
                    "limited to authorized administration networks."
                ),
                "affected_count": management_services,
            }
        )
    if snmp_enabled:
        actions.append(
            {
                "priority": "medium",
                "category": "inventory",
                "title": "Verify SNMP configuration",
                "detail": (
                    "Review SNMP community strings, versions, source restrictions, "
                    "and device inventory data exposed to the agent network."
                ),
                "affected_count": snmp_enabled,
            }
        )
    if cpes:
        actions.append(
            {
                "priority": "info",
                "category": "vulnerability",
                "title": "Run CVE correlation for fingerprinted services",
                "detail": (
                    "Detected CPE fingerprints can be checked against NVD from "
                    "the report's Vulnerability Triage section."
                ),
                "affected_count": cpes,
            }
        )
    if not actions:
        actions.append(
            {
                "priority": "info",
                "category": "monitoring",
                "title": "Continue periodic baseline scans",
                "detail": (
                    "No immediate action was derived from this scan. Keep a regular "
                    "same-profile scan cadence to catch future drift."
                ),
                "affected_count": int(summary.get("scanned_hosts") or 0),
            }
        )
    return {
        "risk_score": score,
        "risk_level": _risk_level(score),
        "priority_actions": actions[:12],
    }


def _risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _host_map(record: dict) -> dict[str, dict]:
    targets = {target["device_id"]: target for target in record.get("targets", [])}
    hosts: dict[str, dict] = {}
    for result in record.get("results") or []:
        target = targets.get(result.get("device_id"), {})
        ip = result.get("ip")
        if not ip:
            continue
        hosts[ip] = {
            "device_id": result.get("device_id"),
            "ip": ip,
            "hostname": result.get("hostname") or target.get("hostname"),
            "device_type": result.get("device_type") or target.get("device_type"),
        }
    return hosts


def _open_port_map(record: dict) -> dict[tuple[str, str, int], dict]:
    hosts = _host_map(record)
    ports: dict[tuple[str, str, int], dict] = {}
    for result in record.get("results") or []:
        ip = result.get("ip")
        if not ip:
            continue
        for port in result.get("ports") or []:
            state = str(port.get("state") or "").lower()
            protocol = str(port.get("protocol") or "").lower()
            number = port.get("port")
            if state not in {"open", "open|filtered"}:
                continue
            if protocol not in {"tcp", "udp"} or not isinstance(number, int):
                continue
            ports[(ip, protocol, number)] = {
                "ip": ip,
                "hostname": hosts.get(ip, {}).get("hostname"),
                "protocol": protocol,
                "port": number,
                "service": port.get("service"),
            }
    return ports


def _finding_map(record: dict) -> dict[tuple[str, str], dict]:
    hosts = _host_map(record)
    findings: dict[tuple[str, str], dict] = {}
    for result in record.get("results") or []:
        ip = result.get("ip")
        if not ip:
            continue
        for flag in result.get("exposure_flags") or []:
            code = flag.get("code")
            severity = flag.get("severity")
            title = flag.get("title")
            if not code or severity not in {"info", "low", "medium", "high"}:
                continue
            findings[(ip, str(code))] = {
                "ip": ip,
                "hostname": hosts.get(ip, {}).get("hostname"),
                "code": str(code),
                "severity": severity,
                "title": str(title or code),
            }
    return findings


def _ip_sort_key(ip: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in ip.split("."))
    except ValueError:
        return (999, *tuple(ord(char) for char in ip))
