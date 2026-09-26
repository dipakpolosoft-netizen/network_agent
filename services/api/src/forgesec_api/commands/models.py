"""Command queue request and response models."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field

from forgesec_api.models import StrictModel


class AgentCommand(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    message_type: Literal["agent.command"] = "agent.command"
    command_id: UUID
    agent_id: UUID
    command_type: Literal[
        "health_check",
        "discover_network",
        "scan_devices",
        "cancel_scan",
        "device_diagnostic",
    ]
    created_at: datetime
    expires_at: datetime
    payload: dict[str, Any]


class CommandEvent(StrictModel):
    schema_version: Literal["1.0"]
    message_type: Literal["command.event"]
    status: Literal["running", "completed", "failed", "cancelled"]
    message: str = Field(min_length=1, max_length=1024)
    details: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime


class CommandEventResponse(StrictModel):
    status: Literal["accepted"] = "accepted"
    command_id: UUID
    command_status: str
