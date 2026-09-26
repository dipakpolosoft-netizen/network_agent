"""Versioned API contracts for centrally hosted scanner workers."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field, field_validator

from forgesec_api.models import StrictModel
from forgesec_api.sites.models import ScanProfile

Capability = Literal[
    "network_inventory",
    "service_fingerprint",
    "vulnerability_assessment",
    "greenbone_assessment",
    "credentialed_inventory",
]


class WorkerCreate(StrictModel):
    site_id: UUID
    label: str = Field(min_length=1, max_length=128)
    capabilities: list[Capability] = Field(min_length=1, max_length=5)

    @field_validator("capabilities")
    @classmethod
    def unique_capabilities(cls, value: list[Capability]) -> list[Capability]:
        if len(value) != len(set(value)):
            raise ValueError("Capabilities must be unique")
        return value


class WorkerPublic(StrictModel):
    worker_id: UUID
    site_id: UUID
    label: str
    capabilities: list[Capability]
    available_capabilities: list[Capability]
    version: str | None
    status: Literal["online", "offline", "revoked"]
    created_at: datetime
    last_heartbeat_at: datetime | None
    revoked_at: datetime | None


class WorkerProvisioned(WorkerPublic):
    credential: str


class WorkerHeartbeat(StrictModel):
    schema_version: Literal["1.0"]
    worker_id: UUID
    version: str = Field(min_length=1, max_length=64)
    available_capabilities: list[Capability] = Field(max_length=5)

    @field_validator("available_capabilities")
    @classmethod
    def unique_available(cls, value: list[Capability]) -> list[Capability]:
        if len(value) != len(set(value)):
            raise ValueError("Capabilities must be unique")
        return value


class WorkerLease(StrictModel):
    lease_id: UUID
    progress: int | None = Field(default=None, ge=0, le=100)
    phase: str | None = Field(default=None, max_length=80)


class WorkerResult(WorkerLease):
    schema_version: Literal["1.0"]
    status: Literal["completed", "failed"]
    summary: str = Field(min_length=1, max_length=2000)
    evidence: dict[str, Any] = Field(default_factory=dict)

    @field_validator("evidence")
    @classmethod
    def bounded_evidence(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            size = len(json.dumps(value, allow_nan=False).encode("utf-8"))
        except (TypeError, ValueError) as exc:
            raise ValueError("Evidence must be JSON data") from exc
        if size > 256 * 1024:
            raise ValueError("Evidence exceeds 256 KiB")
        return value


class WorkerJobPublic(StrictModel):
    job_id: UUID
    site_id: UUID
    capability: Capability
    target_ip: str
    profile: ScanProfile
    status: Literal["queued", "leased", "completed", "failed", "cancelled"]
    attempt: int
    worker_id: UUID | None
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None
    summary: str | None
    target_port: int | None = Field(default=None, ge=1, le=65535)
    target_scheme: Literal["http", "https"] | None = None
    template_profile: Literal["http_baseline"] | None = None
    source_asset_id: UUID | None = None
    source_scan_id: UUID | None = None
    assessment_profile: Literal["greenbone_single_host"] | None = None
    inventory_profile: Literal["linux_ssh_readonly"] | None = None
    progress: int | None = None
    phase: str | None = None


class WorkerJobClaim(WorkerJobPublic):
    schema_version: Literal["1.0"]
    lease_id: UUID
    lease_expires_at: datetime


class NucleiJobCreate(StrictModel):
    asset_id: UUID
    port: int = Field(ge=1, le=65535)
    scheme: Literal["http", "https"]
    authorization_confirmed: Literal[True]


class NucleiFinding(StrictModel):
    template_id: Literal["forgesec-http-missing-x-content-type-options"]
    severity: Literal["low"]
    title: str = Field(min_length=1, max_length=160)
    matched_at: str = Field(min_length=1, max_length=512)


class NucleiEvidence(StrictModel):
    schema_version: Literal["1.0"]
    engine: Literal["nuclei"]
    target_url: str = Field(min_length=1, max_length=128)
    template_profile: Literal["http_baseline"]
    findings: list[NucleiFinding] = Field(max_length=20)


class GreenboneJobCreate(StrictModel):
    asset_id: UUID
    authorization_confirmed: Literal[True]
    maintenance_window_confirmed: Literal[True]


class InventoryJobCreate(StrictModel):
    asset_id: UUID
    authorization_confirmed: Literal[True]


class GreenboneFinding(StrictModel):
    result_id: UUID
    name: str = Field(min_length=1, max_length=200)
    severity: float = Field(ge=0, le=10, allow_inf_nan=False)
    host: str = Field(min_length=7, max_length=45)
    port: str = Field(max_length=48)
    nvt_oid: str | None = Field(default=None, max_length=128)
    cves: list[str] = Field(default_factory=list, max_length=10)


class GreenboneEvidence(StrictModel):
    schema_version: Literal["1.0"]
    engine: Literal["greenbone"]
    target_ip: str = Field(min_length=7, max_length=45)
    assessment_profile: Literal["greenbone_single_host"]
    task_id: UUID
    report_id: UUID
    findings: list[GreenboneFinding] = Field(max_length=50)
    truncated: bool


class InventoryPackage(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    version: str = Field(min_length=1, max_length=160)


class LinuxInventoryEvidence(StrictModel):
    schema_version: Literal["1.0"]
    engine: Literal["ssh_inventory"]
    inventory_profile: Literal["linux_ssh_readonly"]
    target_ip: str = Field(min_length=7, max_length=45)
    hostname: str = Field(min_length=1, max_length=255)
    os_name: str = Field(min_length=1, max_length=160)
    os_version: str | None = Field(default=None, max_length=160)
    kernel: str = Field(min_length=1, max_length=160)
    architecture: str = Field(min_length=1, max_length=80)
    package_manager: Literal["dpkg", "rpm", "none"]
    packages: list[InventoryPackage] = Field(max_length=200)
    packages_truncated: bool


class WorkerJobDetail(WorkerJobPublic):
    evidence: NucleiEvidence | GreenboneEvidence | LinuxInventoryEvidence | None = None
