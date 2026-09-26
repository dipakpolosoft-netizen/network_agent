"""Discovery command and result models."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field

from forgesec_api.models import StrictModel


class DiscoveryCreateRequest(StrictModel):
    authorization_confirmed: Literal[True]
    scope: str | None = None
    mode: Literal["selected", "all"] = "selected"


class DiscoveryCreateResponse(StrictModel):
    discovery_id: UUID
    command_id: UUID
    status: Literal["queued"] = "queued"
    created_at: datetime


class DiscoveryEvent(StrictModel):
    event_id: UUID
    status: str
    stage: str
    message: str = Field(min_length=1, max_length=1024)
    occurred_at: datetime
    progress_percent: float | None = Field(default=None, ge=0, le=100)
    found_count: int = Field(default=0, ge=0, le=4096)


class DiscoveryControlResponse(StrictModel):
    discovery_id: UUID
    cancel_requested: bool


class SnmpInterface(StrictModel):
    index: int = Field(ge=1, le=65535)
    name: str | None = Field(default=None, max_length=255)
    description: str | None = Field(default=None, max_length=255)
    interface_type: str | None = Field(default=None, max_length=64)
    admin_status: str | None = Field(default=None, max_length=64)
    oper_status: str | None = Field(default=None, max_length=64)
    speed_mbps: float | None = Field(default=None, ge=0)
    alias: str | None = Field(default=None, max_length=255)


class LldpNeighbor(StrictModel):
    local_port: str = Field(min_length=1, max_length=255)
    remote_chassis_subtype: int = Field(ge=1, le=7)
    remote_chassis_id: str = Field(pattern=r"^(?:[0-9a-f]{2}){1,255}$")
    remote_port: str | None = Field(default=None, max_length=255)
    remote_system_name: str | None = Field(default=None, max_length=255)


class DiscoveredDevice(StrictModel):
    device_id: str = Field(min_length=8, max_length=128)
    ip: str
    hostname: str | None = Field(default=None, max_length=255)
    mac: str | None = None
    vendor: str | None = Field(default=None, max_length=255)
    snmp_name: str | None = Field(default=None, max_length=255)
    snmp_description: str | None = Field(default=None, max_length=512)
    snmp_object_id: str | None = Field(default=None, max_length=255)
    snmp_contact: str | None = Field(default=None, max_length=255)
    snmp_location: str | None = Field(default=None, max_length=255)
    snmp_uptime_seconds: int | None = Field(default=None, ge=0)
    snmp_interface_count: int | None = Field(default=None, ge=0)
    snmp_interfaces: list[SnmpInterface] = Field(default_factory=list, max_length=256)
    lldp_chassis_subtype: int | None = Field(default=None, ge=1, le=7)
    lldp_chassis_id: str | None = Field(
        default=None, pattern=r"^(?:[0-9a-f]{2}){1,255}$"
    )
    lldp_collected: bool = False
    lldp_neighbors: list[LldpNeighbor] = Field(default_factory=list, max_length=64)
    device_type: str | None = Field(default=None, max_length=64)
    classification_confidence: float | None = Field(default=None, ge=0, le=1)
    status: Literal["up"]
    discovery_reason: str = Field(min_length=1, max_length=128)
    latency_ms: float | None = Field(default=None, ge=0)
    is_agent: bool
    first_seen: datetime
    last_seen: datetime
    discovery_scope: str | None = None


class DiscoveryResult(StrictModel):
    schema_version: Literal["1.0"]
    message_type: Literal["discovery.result"]
    discovery_id: UUID
    agent_id: UUID
    network: str
    interface_name: str | None = Field(default=None, max_length=255)
    status: Literal["completed", "partial", "failed", "cancelled"]
    started_at: datetime
    completed_at: datetime | None
    devices: list[DiscoveredDevice] = Field(max_length=4096)
    error: str | None = Field(default=None, max_length=2048)
    requested_scopes: list[str] = Field(default_factory=list, max_length=256)
    completed_scopes: list[str] = Field(default_factory=list, max_length=256)
    failed_scopes: list[str] = Field(default_factory=list, max_length=256)


class DiscoveryPublic(StrictModel):
    discovery_id: UUID
    command_id: UUID
    agent_id: UUID
    status: str
    stage: str
    network: str | None
    interface_name: str | None
    device_count: int
    found_count: int
    progress_percent: float | None
    cancel_requested: bool
    authorization_confirmed: bool
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    devices: list[DiscoveredDevice]
    error: str | None
    events: list[DiscoveryEvent]
    mode: Literal["selected", "all"] = "selected"
    connected_network: str | None = None
    requested_scopes: list[str] = Field(default_factory=list)
    completed_scopes: list[str] = Field(default_factory=list)
    failed_scopes: list[str] = Field(default_factory=list)
    current_scope: str | None = None
    total_scopes: int = Field(default=1, ge=1, le=256)
    public_scope_authorized: bool = False
