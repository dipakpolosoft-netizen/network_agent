"""Agent API and persistence-facing models."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field

from telesec_api.models import StrictModel


class AgentHeartbeat(StrictModel):
    schema_version: Literal["1.0"]
    message_type: Literal["agent.heartbeat"]
    agent_id: UUID
    agent_version: str = Field(min_length=1, max_length=64)
    hostname: str = Field(min_length=1, max_length=255)
    os_name: str = Field(min_length=1, max_length=255)
    local_ip: str | None = None
    subnet: str | None = None
    nmap_version: str | None = Field(default=None, max_length=64)
    npcap_status: Literal["available", "missing", "degraded", "unknown"]
    service_status: Literal["online", "busy", "degraded", "offline"]
    current_command_id: UUID | None = None
    sent_at: datetime


class AgentPublic(StrictModel):
    agent_id: UUID
    label: str
    site_name: str | None
    hostname: str
    agent_version: str
    os_name: str
    architecture: Literal["x86_64", "arm64"]
    status: Literal["online", "busy", "degraded", "offline"]
    local_ip: str | None
    subnet: str | None
    nmap_version: str | None
    npcap_status: Literal["available", "missing", "degraded", "unknown"]
    current_command_id: UUID | None
    enrolled_at: datetime
    last_heartbeat_at: datetime | None


class HeartbeatResponse(StrictModel):
    status: Literal["accepted"] = "accepted"
    next_heartbeat_seconds: int
    server_time: datetime
