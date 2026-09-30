"""Site and scope API models."""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal
from uuid import UUID

from pydantic import Field

from forgesec_api.models import StrictModel

ScanProfile = Literal["inventory", "network_services", "standard", "full_tcp"]


class SiteCreate(StrictModel):
    name: str = Field(min_length=1, max_length=128)
    owner: str | None = Field(default=None, max_length=128)
    description: str | None = Field(default=None, max_length=512)


class SitePublic(SiteCreate):
    site_id: UUID
    created_at: datetime


class ScopeCreate(StrictModel):
    cidr: str
    label: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=512)
    exclusions: list[str] = Field(default_factory=list, max_length=256)
    scan_profiles: list[ScanProfile] = Field(
        default_factory=lambda: [
            "inventory",
            "network_services",
            "standard",
            "full_tcp",
        ]
    )
    owner: str = Field(min_length=1, max_length=128)
    approval_reference: str = Field(min_length=1, max_length=256)
    approved_by: str = Field(min_length=1, max_length=128)
    expires_on: date
    authorization_confirmed: Literal[True]
    public_range_authorized: bool = False


class ScopePublic(StrictModel):
    cidr: str
    label: str
    description: str | None = None
    exclusions: list[str]
    scan_profiles: list[ScanProfile]
    owner: str | None = None
    approval_reference: str | None = None
    approved_by: str | None = None
    expires_on: date | None = None
    authorization_confirmed: bool = False
    public_range_authorized: bool = False
    approval_status: Literal["active", "expired", "needs_review"]
    scope_id: UUID
    site_id: UUID
    created_at: datetime
    approved_at: datetime | None = None
