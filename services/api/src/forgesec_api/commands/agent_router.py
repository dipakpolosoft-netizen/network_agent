"""Authenticated command polling and event routes."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status

from forgesec_api.agents.auth import authenticate_agent
from forgesec_api.commands.models import (
    AgentCommand,
    CommandEvent,
    CommandEventResponse,
)
from forgesec_api.commands.service import (
    CommandNotFound,
    CommandOwnershipError,
    CommandService,
    InvalidCommandTransition,
)
from forgesec_api.dependencies import (
    get_command_service,
    get_discovery_service,
    get_site_service,
)
from forgesec_api.discoveries.service import DiscoveryService
from forgesec_api.sites.service import SiteService

router = APIRouter(prefix="/agent/commands", tags=["agent protocol"])
AuthenticatedAgent = Annotated[dict, Depends(authenticate_agent)]
CommandServiceDependency = Annotated[CommandService, Depends(get_command_service)]
DiscoveryServiceDependency = Annotated[DiscoveryService, Depends(get_discovery_service)]
SiteServiceDependency = Annotated[SiteService, Depends(get_site_service)]


@router.get("/next", response_model=AgentCommand | None)
def next_command(
    authenticated: AuthenticatedAgent,
    service: CommandServiceDependency,
    sites: SiteServiceDependency,
) -> AgentCommand | Response:
    command = service.claim_next(
        authenticated["agent_id"],
        allowed=lambda item: sites.command_allowed(authenticated.get("site_id"), item),
    )
    if command is None:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    public_fields = AgentCommand.model_fields.keys()
    return AgentCommand.model_validate({key: command[key] for key in public_fields})


@router.post("/{command_id}/events", response_model=CommandEventResponse)
def command_event(
    command_id: UUID,
    payload: CommandEvent,
    authenticated: AuthenticatedAgent,
    service: CommandServiceDependency,
    discoveries: DiscoveryServiceDependency,
) -> CommandEventResponse:
    try:
        command = service.update_from_agent(
            command_id=str(command_id),
            agent_id=authenticated["agent_id"],
            event=payload,
        )
    except CommandNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Command not found") from exc
    except CommandOwnershipError as exc:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Command belongs to another agent"
        ) from exc
    except InvalidCommandTransition as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Invalid command status transition"
        ) from exc
    discoveries.sync_command_event(command, payload)
    return CommandEventResponse(
        command_id=command_id,
        command_status=command["status"],
    )
