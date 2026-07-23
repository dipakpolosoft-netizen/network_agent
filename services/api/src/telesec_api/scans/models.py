"""Selected-device scan API and agent protocol models."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field

from telesec_api.models import StrictModel


class ScanCreateRequest(StrictModel):
    device_ids: list[str] = Field(min_length=1, max_length=10)
    profile: Literal["standard", "full_tcp"] = "standard"
    authorization_confirmed: Literal[True]


class ScanCreateResponse(StrictModel):
    scan_id: UUID
    command_id: UUID
    status: Literal["queued"] = "queued"
    total: int
    created_at: datetime


class ScanTarget(StrictModel):
    device_id: str
    ip: str
    hostname: str | None
    status: str


class PortResult(StrictModel):
    protocol: Literal["tcp", "udp"]
    port: int = Field(ge=1, le=65535)
    state: Literal["open", "open|filtered", "filtered"]
    service: str | None = None
    product: str | None = None
    version: str | None = None
    cpe: str | None = None


class OsMatch(StrictModel):
    name: str
    accuracy: int = Field(ge=0, le=100)


class ExposureFlag(StrictModel):
    code: str
    severity: Literal["info", "low", "medium", "high"]
    title: str
    evidence: str


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
    device_type: str | None = None
    classification_confidence: float | None = Field(default=None, ge=0, le=1)
    ports: list[PortResult] = Field(max_length=65535)
    os_matches: list[OsMatch] = Field(max_length=32)
    exposure_flags: list[ExposureFlag] = Field(max_length=128)
    error: str | None = Field(default=None, max_length=4096)


class ScanProgress(StrictModel):
    schema_version: Literal["1.0"]
    message_type: Literal["scan.progress"]
    scan_id: UUID
    agent_id: UUID
    status: Literal["queued", "running", "completed", "partial", "failed", "cancelled"]
    stage: str | None = None
    total: int = Field(ge=1, le=10)
    queued: int = Field(ge=0, le=10)
    running: int = Field(ge=0, le=3)
    completed: int = Field(ge=0, le=10)
    failed: int = Field(ge=0, le=10)
    cancelled: int = Field(ge=0, le=10)
    updated_at: datetime


class ScanControlResponse(StrictModel):
    scan_id: UUID
    cancel_requested: bool


class ScanPublic(StrictModel):
    scan_id: UUID
    command_id: UUID
    discovery_id: UUID
    agent_id: UUID
    profile: Literal["standard", "full_tcp"]
    status: str
    total: int
    queued: int
    running: int
    completed: int
    failed: int
    cancelled: int
    cancel_requested: bool
    stage: str | None
    targets: list[ScanTarget]
    results: list[HostScanResult]
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
