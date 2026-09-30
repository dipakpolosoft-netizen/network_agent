"""Agent API and persistence-facing models."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field, field_validator

from forgesec_api.models import StrictModel


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
    discovery_ready: bool | None = None
    discovery_network: str | None = None
    discovery_interface: str | None = Field(default=None, max_length=255)
    discovery_error: str | None = Field(default=None, max_length=1024)
    discovery_capability: (
        Literal["ready", "selection_required", "authorization_required", "unsupported"]
        | None
    ) = None
    discovery_scope_options: list[str] = Field(default_factory=list, max_length=256)
    discovery_recommended_scope: str | None = None
    discovery_requires_authorization: bool = False
    discovery_all_segments_available: bool = False
    service_status: Literal["online", "busy", "degraded", "offline"]
    current_command_id: UUID | None = None
    sent_at: datetime


class AgentPublic(StrictModel):
    agent_id: UUID
    site_id: UUID | None = None
    approved_scopes: list[str] = Field(default_factory=list)
    approved_discovery_scopes: list[str] = Field(default_factory=list)
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
    discovery_ready: bool | None = None
    discovery_network: str | None = None
    discovery_interface: str | None = None
    discovery_error: str | None = None
    discovery_capability: str | None = None
    discovery_scope_options: list[str] = Field(default_factory=list)
    discovery_recommended_scope: str | None = None
    discovery_requires_authorization: bool = False
    discovery_all_segments_available: bool = False
    current_command_id: UUID | None
    enrolled_at: datetime
    last_heartbeat_at: datetime | None
    credential_rotated_at: datetime | None = None
    revoked_at: datetime | None = None
    revoked_reason: str | None = None


class AgentCredentialRotation(StrictModel):
    agent_id: UUID
    new_credential: str = Field(
        pattern=r"^forgesec_agent_[A-Za-z0-9_-]{64}$", min_length=79, max_length=79
    )


class AgentRevocation(StrictModel):
    reason: str = Field(min_length=3, max_length=500)

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        reason = value.strip()
        if len(reason) < 3:
            raise ValueError("reason must contain at least 3 characters")
        return reason


class HeartbeatResponse(StrictModel):
    status: Literal["accepted"] = "accepted"
    next_heartbeat_seconds: int
    server_time: datetime


DiagnosticKind = Literal[
    "ping",
    "reverse_dns",
    "arp_cache",
    "powershell_test",
    "inventory_nmap",
    "network_services_nmap",
    "standard_nmap",
    "full_tcp_nmap",
]


class AgentDiagnosticRequest(StrictModel):
    target_ip: str
    diagnostic_type: DiagnosticKind
    full_tcp_confirmed: bool = False

    @field_validator("target_ip")
    @classmethod
    def validate_target_ip(cls, value: str) -> str:
        import ipaddress

        try:
            return str(ipaddress.IPv4Address(value))
        except ValueError as exc:
            raise ValueError("target_ip must be an IPv4 address") from exc


class AgentDiagnosticPublic(StrictModel):
    command_id: UUID
    agent_id: UUID
    status: str
    diagnostic_type: DiagnosticKind
    target_ip: str
    message: str | None = None
    command_line: str | None = None
    output: str | None = None
    exit_code: int | None = None
    duration_ms: int | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    details: dict[str, Any] = Field(default_factory=dict)
