"""Discovery command and result models."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field

from telesec_api.models import StrictModel


class DiscoveryCreateRequest(StrictModel):
    authorization_confirmed: Literal[True]


class DiscoveryCreateResponse(StrictModel):
    discovery_id: UUID
    command_id: UUID
    status: Literal["queued"] = "queued"
    created_at: datetime


class DiscoveredDevice(StrictModel):
    device_id: str = Field(min_length=8, max_length=128)
    ip: str
    hostname: str | None = Field(default=None, max_length=255)
    mac: str | None = None
    vendor: str | None = Field(default=None, max_length=255)
    status: Literal["up"]
    discovery_reason: str = Field(min_length=1, max_length=128)
    latency_ms: float | None = Field(default=None, ge=0)
    is_agent: bool
    first_seen: datetime
    last_seen: datetime


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


class DiscoveryPublic(StrictModel):
    discovery_id: UUID
    command_id: UUID
    agent_id: UUID
    status: str
    network: str | None
    interface_name: str | None
    device_count: int
    authorization_confirmed: bool
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    devices: list[DiscoveredDevice]
    error: str | None
