"""Public vulnerability-correlation response models."""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal
from uuid import UUID

from pydantic import Field

from forgesec_api.models import StrictModel


class VulnerabilityMatch(StrictModel):
    cve_id: str
    severity: Literal["critical", "high", "medium", "low", "unknown"]
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_version: str | None = None
    vector: str | None = None
    description: str
    published_at: datetime | None = None
    last_modified_at: datetime | None = None
    known_exploited: bool = False
    required_action: str | None = None
    action_due: date | None = None
    references: list[str] = Field(max_length=20)


class VulnerabilityLookup(StrictModel):
    source: Literal["NVD"] = "NVD"
    cpe: str
    normalized_cpe: str
    total: int = Field(ge=0)
    returned: int = Field(ge=0)
    retrieved_at: datetime
    cached: bool
    vulnerabilities: list[VulnerabilityMatch] = Field(max_length=500)
    notice: str = (
        "Potential matches based on the detected CPE, not confirmed exploitation. "
        "Verify the product version and vendor advisory before remediation."
    )


class VulnerabilitySeverityCounts(StrictModel):
    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    unknown: int = Field(default=0, ge=0)


class AffectedService(StrictModel):
    device_id: str
    ip: str
    hostname: str | None = None
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"]
    service: str | None = None
    product: str | None = None
    version: str | None = None


class CpeVulnerabilitySummary(StrictModel):
    cpe: str
    normalized_cpe: str | None = None
    affected_services: list[AffectedService] = Field(max_length=128)
    affected_service_count: int = Field(ge=0)
    total: int = Field(default=0, ge=0)
    returned: int = Field(default=0, ge=0)
    severity_counts: VulnerabilitySeverityCounts = Field(
        default_factory=VulnerabilitySeverityCounts
    )
    highest_severity: Literal["critical", "high", "medium", "low", "unknown"] | None
    known_exploited: int = Field(default=0, ge=0)
    top_vulnerabilities: list[VulnerabilityMatch] = Field(max_length=10)
    error: str | None = None


class ScanVulnerabilitySummary(StrictModel):
    source: Literal["NVD"] = "NVD"
    scan_id: UUID
    total_cpes: int = Field(ge=0)
    checked_cpes: int = Field(ge=0)
    skipped_cpes: int = Field(ge=0)
    total_vulnerabilities: int = Field(ge=0)
    returned_vulnerabilities: int = Field(ge=0)
    known_exploited: int = Field(ge=0)
    severity_counts: VulnerabilitySeverityCounts = Field(
        default_factory=VulnerabilitySeverityCounts
    )
    items: list[CpeVulnerabilitySummary] = Field(max_length=50)
    assessed_at: datetime
    evidence_fingerprint: str
    evidence_current: bool
    failed_cpes: int = Field(ge=0)
    cached_lookups: int = Field(ge=0)
    notice: str = (
        "Potential matches based on detected CPEs, not confirmed exploitation. "
        "Verify the product version and vendor advisory before remediation."
    )
