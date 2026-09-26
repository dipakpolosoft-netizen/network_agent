"""Asset inventory API models."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field, field_validator

from forgesec_api.discoveries.models import LldpNeighbor, SnmpInterface
from forgesec_api.models import StrictModel

Criticality = Literal["low", "medium", "high", "critical"]


class AssetPort(StrictModel):
    protocol: Literal["tcp", "udp"]
    port: int = Field(ge=1, le=65535)
    service: str | None = None
    product: str | None = None
    version: str | None = None


class AssetPublic(StrictModel):
    asset_id: UUID
    site_id: UUID
    display_name: str | None
    owner: str | None
    criticality: Criticality
    tags: list[str]
    hostname: str | None
    mac: str | None
    last_ip: str
    ip_history: list[str]
    vendor: str | None
    device_type: str | None
    classification_confidence: float | None
    os_name: str | None
    os_accuracy: int | None
    open_port_count: int
    ports: list[AssetPort]
    first_seen: datetime
    last_seen: datetime
    last_discovery_at: datetime | None
    last_scan_at: datetime | None
    last_discovery_id: UUID | None
    last_scan_id: UUID | None
    last_scan_status: str | None
    observation_count: int
    scan_count: int
    created_at: datetime
    updated_at: datetime


class AssetList(StrictModel):
    items: list[AssetPublic]
    total: int
    limit: int
    offset: int


class TopologyNode(StrictModel):
    id: str
    asset_id: UUID | None
    label: str
    ip: str | None
    device_type: str | None
    observed_only: bool
    last_seen: datetime | None


class TopologyLink(StrictModel):
    id: str
    source: str
    target: str
    reported_by: UUID
    local_port: str
    remote_port: str | None
    remote_system_name: str | None
    discovery_id: UUID
    observed_at: datetime
    stale: bool


class TopologyGraph(StrictModel):
    site_id: UUID
    nodes: list[TopologyNode]
    links: list[TopologyLink]
    observed_assets: int
    unlinked_assets: int
    stale_hidden: int
    total_links: int
    truncated: bool
    latest_observed_at: datetime | None


class AssetObservation(StrictModel):
    observation_id: str
    asset_id: UUID
    site_id: UUID
    source_type: Literal["discovery", "scan"]
    source_id: UUID
    source_device_id: str
    agent_id: UUID
    observed_at: datetime
    ip: str
    mac: str | None
    hostname: str | None
    device_type: str | None
    status: str
    open_port_count: int | None
    vendor: str | None = None
    classification_confidence: float | None = Field(default=None, ge=0, le=1)
    discovery_reason: str | None = None
    latency_ms: float | None = Field(default=None, ge=0)
    snmp_name: str | None = None
    snmp_description: str | None = None
    snmp_object_id: str | None = None
    snmp_uptime_seconds: int | None = Field(default=None, ge=0)
    snmp_interface_count: int | None = Field(default=None, ge=0)
    snmp_interfaces: list[SnmpInterface] = Field(default_factory=list, max_length=64)
    snmp_interfaces_limited: bool = False
    lldp_chassis_subtype: int | None = None
    lldp_chassis_id: str | None = None
    lldp_collected: bool = False
    lldp_neighbors: list[LldpNeighbor] = Field(default_factory=list)


class AssetDiscoveryProfile(StrictModel):
    discovery_id: UUID
    observed_at: datetime
    ip: str
    hostname: str | None
    vendor: str | None
    device_type: str | None
    classification_confidence: float | None = Field(default=None, ge=0, le=1)
    discovery_reason: str | None
    latency_ms: float | None = Field(default=None, ge=0)


class AssetSnmpProfile(StrictModel):
    discovery_id: UUID
    observed_at: datetime
    ip: str
    latest_discovery: bool
    name: str | None
    description: str | None
    object_id: str | None
    uptime_seconds: int | None = Field(default=None, ge=0)
    reported_interface_count: int | None = Field(default=None, ge=0)
    interfaces: list[SnmpInterface] = Field(max_length=64)
    interfaces_limited: bool


class AssetDeviceProfile(StrictModel):
    asset_id: UUID
    discovery: AssetDiscoveryProfile | None
    snmp: AssetSnmpProfile | None


class AssetEvidenceItem(StrictModel):
    source: Literal["host_scan", "nvd", "nuclei", "greenbone"]
    classification: Literal[
        "exposure_signal",
        "potential_cve",
        "configuration_observation",
        "scanner_finding",
    ]
    source_id: UUID
    scan_id: UUID | None = None
    observed_at: datetime
    current: bool
    severity: Literal["critical", "high", "medium", "low", "info", "unknown"]
    title: str
    detail: str
    reference: str | None = None
    target: str | None = None


class AssetEvidenceRun(StrictModel):
    job_id: UUID
    source: Literal["nuclei", "greenbone", "ssh_inventory"]
    status: Literal["queued", "leased", "completed", "failed", "cancelled"]
    created_at: datetime
    completed_at: datetime | None = None
    summary: str | None = None
    current: bool


class AssetInventoryFact(StrictModel):
    job_id: UUID
    observed_at: datetime
    current: bool
    hostname: str
    os_name: str
    os_version: str | None = None
    kernel: str
    package_count: int = Field(ge=0)
    packages_truncated: bool


class AssetEvidence(StrictModel):
    asset_id: UUID
    items: list[AssetEvidenceItem]
    runs: list[AssetEvidenceRun]
    latest_inventory: AssetInventoryFact | None = None
    truncated: bool


class AssetPatch(StrictModel):
    display_name: str | None = Field(default=None, max_length=128)
    owner: str | None = Field(default=None, max_length=128)
    criticality: Criticality | None = None
    tags: list[str] | None = Field(default=None, max_length=32)

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        normalized = [item.strip() for item in value]
        if any(not item or len(item) > 64 for item in normalized):
            raise ValueError("Tags must contain 1 to 64 characters")
        if len({item.casefold() for item in normalized}) != len(normalized):
            raise ValueError("Tags must be unique")
        return normalized
