"""Enrollment API models."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field

from forgesec_api.models import StrictModel


class EnrollmentCreateRequest(StrictModel):
    label: str = Field(default="Windows Network Agent", min_length=1, max_length=128)
    site_id: UUID | None = None
    site_name: str | None = Field(default=None, max_length=128)


class EnrollmentCreateResponse(StrictModel):
    enrollment_id: UUID
    enrollment_token: str
    expires_at: datetime


class AgentEnrollRequest(StrictModel):
    schema_version: Literal["1.0"]
    message_type: Literal["agent.enroll.request"]
    enrollment_token: str = Field(min_length=32, max_length=512)
    agent_version: str = Field(min_length=1, max_length=64)
    hostname: str = Field(min_length=1, max_length=255)
    os_name: str = Field(min_length=1, max_length=255)
    architecture: Literal["x86_64", "arm64"]
    requested_at: datetime


class AgentEnrollResponse(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    message_type: Literal["agent.enroll.response"] = "agent.enroll.response"
    agent_id: UUID
    agent_credential: str
    heartbeat_interval_seconds: int
    issued_at: datetime
