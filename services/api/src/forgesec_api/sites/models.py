"""Site and scope API models."""

from __future__ import annotations

from datetime import datetime
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


class ScopePublic(ScopeCreate):
    scope_id: UUID
    site_id: UUID
    created_at: datetime
