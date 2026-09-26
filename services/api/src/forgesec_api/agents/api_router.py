"""Dashboard-facing agent routes."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status

from forgesec_api.agents.models import (
    AgentDiagnosticPublic,
    AgentDiagnosticRequest,
    AgentPublic,
    AgentRevocation,
)
from forgesec_api.agents.service import AgentAlreadyRevoked, AgentNotFound, AgentService
from forgesec_api.commands.service import CommandNotFound, CommandService
from forgesec_api.dependencies import (
    get_agent_service,
    get_command_service,
    get_site_service,
)
from forgesec_api.sites.service import SiteService

router = APIRouter(prefix="/api/agents", tags=["agents"])
AgentServiceDependency = Annotated[AgentService, Depends(get_agent_service)]
CommandServiceDependency = Annotated[CommandService, Depends(get_command_service)]
SiteServiceDependency = Annotated[SiteService, Depends(get_site_service)]


@router.get("", response_model=list[AgentPublic])
def list_agents(
    service: AgentServiceDependency,
) -> list[AgentPublic]:
    return [AgentPublic.model_validate(item) for item in service.list_public()]


@router.get("/{agent_id}", response_model=AgentPublic)
def get_agent(
    agent_id: UUID,
    service: AgentServiceDependency,
) -> AgentPublic:
    try:
        return AgentPublic.model_validate(service.get_public(str(agent_id)))
    except AgentNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        ) from exc


@router.post("/{agent_id}/revoke", response_model=AgentPublic)
def revoke_agent(
    agent_id: UUID,
    payload: AgentRevocation,
    request: Request,
    service: AgentServiceDependency,
    commands: CommandServiceDependency,
) -> AgentPublic:
    try:
        actor = getattr(request.state, "user", None)
        record = service.revoke(
            str(agent_id), payload.reason, actor_id=actor["user_id"] if actor else None
        )
    except AgentNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent not found") from exc
    except AgentAlreadyRevoked as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "Agent already revoked") from exc
    for command in commands.store.list("commands"):
        if command["agent_id"] == str(agent_id) and command["status"] == "queued":
            commands.cancel_pending(
                command["command_id"], message="Agent access revoked"
            )
    return AgentPublic.model_validate(service.public(record))


@router.post(
    "/{agent_id}/diagnostics",
    response_model=AgentDiagnosticPublic,
    status_code=status.HTTP_202_ACCEPTED,
)
def create_agent_diagnostic(
    agent_id: UUID,
    payload: AgentDiagnosticRequest,
    agents: AgentServiceDependency,
    commands: CommandServiceDependency,
    sites: SiteServiceDependency,
) -> AgentDiagnosticPublic:
    try:
        agent = agents.get_public(str(agent_id))
    except AgentNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        ) from exc
    if agent["status"] == "offline":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Agent is offline",
        )
    if not sites.approved(agent.get("site_id"), payload.target_ip):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "Diagnostic target is outside the site's approved scope",
        )
    command = commands.create(
        agent_id=str(agent_id),
        command_type="device_diagnostic",
        payload={
            "target_ip": payload.target_ip,
            "diagnostic_type": payload.diagnostic_type,
            "scope_policy": sites.policy(agent.get("site_id")),
        },
    )
    return _diagnostic_public(command)


@router.get(
    "/{agent_id}/diagnostics/{command_id}",
    response_model=AgentDiagnosticPublic,
)
def get_agent_diagnostic(
    agent_id: UUID,
    command_id: UUID,
    commands: CommandServiceDependency,
) -> AgentDiagnosticPublic:
    try:
        command = commands.get(str(command_id))
    except CommandNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Diagnostic command not found",
        ) from exc
    if (
        command["agent_id"] != str(agent_id)
        or command["command_type"] != "device_diagnostic"
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Diagnostic command not found",
        )
    return _diagnostic_public(command)


def _diagnostic_public(command: dict) -> AgentDiagnosticPublic:
    details = command.get("last_details") or {}
    payload = command["payload"]
    return AgentDiagnosticPublic.model_validate(
        {
            "command_id": command["command_id"],
            "agent_id": command["agent_id"],
            "status": command["status"],
            "diagnostic_type": payload["diagnostic_type"],
            "target_ip": payload["target_ip"],
            "message": command.get("last_message"),
            "command_line": details.get("command_line"),
            "output": details.get("output"),
            "exit_code": details.get("exit_code"),
            "duration_ms": details.get("duration_ms"),
            "started_at": details.get("started_at"),
            "completed_at": details.get("completed_at"),
            "created_at": command["created_at"],
            "updated_at": command["updated_at"],
            "details": details,
        }
    )
