"""Public vulnerability-correlation response models."""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import Field

from telesec_api.models import StrictModel


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
