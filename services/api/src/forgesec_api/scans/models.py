"""Selected-device scan API and agent protocol models."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field, field_validator

from forgesec_api.models import StrictModel

ScanProfile = Literal["inventory", "network_services", "standard", "full_tcp"]


class ScanCreateRequest(StrictModel):
    device_ids: list[str] = Field(min_length=1, max_length=4096)
    profile: ScanProfile = "inventory"
    authorization_confirmed: Literal[True]
    full_tcp_confirmed: bool = False


class ScanProfilePlan(StrictModel):
    tcp_top_ports: int | None = Field(default=None, ge=1)
    tcp_all_ports: bool
    tcp_ports: list[int]
    udp_ports: list[int]
    version_detection: Literal["light", "full"]
    os_detection: Literal["when_privileged", "not_requested"]
    host_timeout_seconds: int = Field(ge=1)
    assume_host_up: bool
    open_only_output: bool


class ScanCreateResponse(StrictModel):
    scan_id: UUID
    command_id: UUID
    status: Literal["queued"] = "queued"
    total: int
    created_at: datetime


class SnmpInterface(StrictModel):
    index: int = Field(ge=1, le=65535)
    name: str | None = Field(default=None, max_length=255)
    description: str | None = Field(default=None, max_length=255)
    interface_type: str | None = Field(default=None, max_length=64)
    admin_status: str | None = Field(default=None, max_length=64)
    oper_status: str | None = Field(default=None, max_length=64)
    speed_mbps: float | None = Field(default=None, ge=0)
    alias: str | None = Field(default=None, max_length=255)


class ScanTarget(StrictModel):
    device_id: str
    ip: str
    hostname: str | None
    vendor: str | None = None
    snmp_name: str | None = None
    snmp_description: str | None = None
    snmp_object_id: str | None = None
    snmp_contact: str | None = None
    snmp_location: str | None = None
    snmp_uptime_seconds: int | None = Field(default=None, ge=0)
    snmp_interface_count: int | None = Field(default=None, ge=0)
    snmp_interfaces: list[SnmpInterface] = Field(default_factory=list, max_length=256)
    device_type: str | None = None
    classification_confidence: float | None = Field(default=None, ge=0, le=1)
    status: str


class PortResult(StrictModel):
    protocol: Literal["tcp", "udp"]
    port: int = Field(ge=1, le=65535)
    state: Literal["open", "open|filtered", "filtered"]
    reason: str | None = Field(default=None, max_length=128)
    service: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = Field(default=None, max_length=512)
    ostype: str | None = Field(default=None, max_length=128)
    devicetype: str | None = Field(default=None, max_length=128)
    method: str | None = Field(default=None, max_length=64)
    confidence: int | None = Field(default=None, ge=0, le=10)
    cpe: str | None = None
    cpes: list[str] = Field(default_factory=list, max_length=16)
    evidence_source: Literal["nmap"] | None = None
    recorded_at: datetime | None = None


class OsMatch(StrictModel):
    name: str
    accuracy: int = Field(ge=0, le=100)


class ExposureFlag(StrictModel):
    code: str
    severity: Literal["info", "low", "medium", "high"]
    title: str
    evidence: str


class CountItem(StrictModel):
    label: str = Field(min_length=1, max_length=255)
    count: int = Field(ge=0)


class SeverityCounts(StrictModel):
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    info: int = Field(default=0, ge=0)


class ScanSummary(StrictModel):
    scanned_hosts: int = Field(default=0, ge=0)
    evidence_hosts: int = Field(default=0, ge=0)
    classified_hosts: int = Field(default=0, ge=0)
    network_devices: int = Field(default=0, ge=0)
    servers: int = Field(default=0, ge=0)
    workstations: int = Field(default=0, ge=0)
    timed_out_hosts: int = Field(default=0, ge=0)
    failed_hosts: int = Field(default=0, ge=0)
    open_ports: int = Field(default=0, ge=0)
    open_filtered_ports: int = Field(default=0, ge=0)
    filtered_ports: int = Field(default=0, ge=0)
    tcp_ports: int = Field(default=0, ge=0)
    udp_ports: int = Field(default=0, ge=0)
    service_fingerprints: int = Field(default=0, ge=0)
    cpes: int = Field(default=0, ge=0)
    exposure_findings: int = Field(default=0, ge=0)
    high_exposure_findings: int = Field(default=0, ge=0)
    management_services: int = Field(default=0, ge=0)
    snmp_enabled: int = Field(default=0, ge=0)
    device_types: list[CountItem] = Field(default_factory=list, max_length=32)
    vendors: list[CountItem] = Field(default_factory=list, max_length=32)
    services: list[CountItem] = Field(default_factory=list, max_length=64)
    severity_counts: SeverityCounts = Field(default_factory=SeverityCounts)


class ChangedHost(StrictModel):
    device_id: str | None = None
    ip: str
    hostname: str | None = None
    device_type: str | None = None


class ChangedPort(StrictModel):
    ip: str
    hostname: str | None = None
    protocol: Literal["tcp", "udp"]
    port: int = Field(ge=1, le=65535)
    service: str | None = None


class ChangedFinding(StrictModel):
    ip: str
    hostname: str | None = None
    code: str
    severity: Literal["info", "low", "medium", "high"]
    title: str


class ScanChangeSummary(StrictModel):
    baseline_scan_id: UUID | None = None
    baseline_created_at: datetime | None = None
    baseline_profile: ScanProfile | None = None
    new_host_count: int = Field(default=0, ge=0)
    missing_host_count: int = Field(default=0, ge=0)
    opened_port_count: int = Field(default=0, ge=0)
    closed_port_count: int = Field(default=0, ge=0)
    no_longer_confirmed_port_count: int = Field(default=0, ge=0)
    new_finding_count: int = Field(default=0, ge=0)
    resolved_finding_count: int = Field(default=0, ge=0)
    new_hosts: list[ChangedHost] = Field(default_factory=list, max_length=128)
    missing_hosts: list[ChangedHost] = Field(default_factory=list, max_length=128)
    opened_ports: list[ChangedPort] = Field(default_factory=list, max_length=128)
    closed_ports: list[ChangedPort] = Field(default_factory=list, max_length=128)
    no_longer_confirmed_ports: list[ChangedPort] = Field(
        default_factory=list, max_length=128
    )
    new_findings: list[ChangedFinding] = Field(default_factory=list, max_length=128)
    resolved_findings: list[ChangedFinding] = Field(
        default_factory=list,
        max_length=128,
    )


class RecommendedAction(StrictModel):
    priority: Literal["critical", "high", "medium", "low", "info"]
    category: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=255)
    detail: str = Field(min_length=1, max_length=1024)
    affected_count: int = Field(default=0, ge=0)


class ScanActionSummary(StrictModel):
    risk_score: int = Field(default=0, ge=0, le=100)
    risk_level: Literal["low", "medium", "high", "critical"] = "low"
    priority_actions: list[RecommendedAction] = Field(
        default_factory=list,
        max_length=12,
    )


class HostScanResult(StrictModel):
    schema_version: Literal["1.0"]
    message_type: Literal["host_scan.result"]
    scan_id: UUID
    agent_id: UUID
    device_id: str
    ip: str
    status: Literal["completed", "partial", "failed", "timed_out", "cancelled"]
    started_at: datetime
    completed_at: datetime | None
    hostname: str | None = None
    hostname_source: Literal["nmap", "discovery", "snmp"] | None = None
    device_type: str | None = None
    classification_confidence: float | None = Field(default=None, ge=0, le=1)
    ports: list[PortResult] = Field(max_length=65535)
    os_matches: list[OsMatch] = Field(max_length=32)
    exposure_flags: list[ExposureFlag] = Field(max_length=128)
    raw_xml_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    error: str | None = Field(default=None, max_length=4096)

    @field_validator("ports")
    @classmethod
    def unique_ports(cls, ports: list[PortResult]) -> list[PortResult]:
        seen: set[tuple[str, int]] = set()
        for port in ports:
            key = (port.protocol, port.port)
            if key in seen:
                raise ValueError(f"Duplicate {port.port}/{port.protocol} port evidence")
            seen.add(key)
        return ports


class ScanProgress(StrictModel):
    schema_version: Literal["1.0"]
    message_type: Literal["scan.progress"]
    scan_id: UUID
    agent_id: UUID
    status: Literal["queued", "running", "completed", "partial", "failed", "cancelled"]
    stage: str | None = None
    total: int = Field(ge=1, le=4096)
    queued: int = Field(ge=0, le=4096)
    running: int = Field(ge=0, le=3)
    running_device_ids: list[str] = Field(default_factory=list, max_length=3)
    completed: int = Field(ge=0, le=4096)
    failed: int = Field(ge=0, le=4096)
    cancelled: int = Field(ge=0, le=4096)
    updated_at: datetime


class ScanControlResponse(StrictModel):
    scan_id: UUID
    cancel_requested: bool


class ScanOrigin(StrictModel):
    agent_id: UUID
    label: str
    hostname: str
    local_ip: str | None = None
    subnet: str | None = None
    site_name: str | None = None
    os_name: str
    agent_version: str
    discovery_interface: str | None = None
    last_heartbeat_at: datetime | None = None
    source: Literal["scan_snapshot", "current_heartbeat"]


class ScanPublic(StrictModel):
    scan_id: UUID
    command_id: UUID
    discovery_id: UUID
    agent_id: UUID
    site_id: UUID | None = None
    scan_origin: ScanOrigin | None = None
    profile: ScanProfile
    profile_plan: ScanProfilePlan | None = None
    status: str
    total: int
    queued: int
    running: int
    completed: int
    failed: int
    cancelled: int
    cancel_requested: bool
    stage: str | None
    last_progress_at: datetime | None = None
    targets: list[ScanTarget]
    results: list[HostScanResult]
    summary: ScanSummary = Field(default_factory=ScanSummary)
    change_summary: ScanChangeSummary = Field(default_factory=ScanChangeSummary)
    action_summary: ScanActionSummary = Field(default_factory=ScanActionSummary)
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
