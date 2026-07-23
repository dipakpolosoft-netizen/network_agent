"""Dashboard-facing agent routes."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from telesec_api.agents.models import AgentPublic
from telesec_api.agents.service import AgentNotFound, AgentService
from telesec_api.dependencies import get_agent_service

router = APIRouter(prefix="/api/agents", tags=["agents"])
AgentServiceDependency = Annotated[AgentService, Depends(get_agent_service)]


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
