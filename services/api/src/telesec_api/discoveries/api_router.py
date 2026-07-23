"""Dashboard discovery routes."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from telesec_api.dependencies import get_discovery_service
from telesec_api.discoveries.models import (
    DiscoveryCreateRequest,
    DiscoveryCreateResponse,
    DiscoveryPublic,
)
from telesec_api.discoveries.service import (
    AgentOffline,
    DiscoveryNotFound,
    DiscoveryService,
    ScannerUnavailable,
)

router = APIRouter(tags=["discoveries"])
DiscoveryServiceDependency = Annotated[
    DiscoveryService,
    Depends(get_discovery_service),
]


@router.get("/api/discoveries", response_model=list[DiscoveryPublic])
def list_discoveries(
    service: DiscoveryServiceDependency,
    agent_id: UUID | None = None,
) -> list[DiscoveryPublic]:
    return [
        DiscoveryPublic.model_validate(item)
        for item in service.list(str(agent_id) if agent_id else None)
    ]


@router.post(
    "/api/agents/{agent_id}/discover",
    response_model=DiscoveryCreateResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def create_discovery(
    agent_id: UUID,
    _payload: DiscoveryCreateRequest,
    service: DiscoveryServiceDependency,
) -> DiscoveryCreateResponse:
    try:
        record = service.create(agent_id=str(agent_id))
    except DiscoveryNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent not found") from exc
    except AgentOffline as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, "Agent is offline") from exc
    except ScannerUnavailable as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return DiscoveryCreateResponse(
        discovery_id=record["discovery_id"],
        command_id=record["command_id"],
        created_at=record["created_at"],
    )


@router.get(
    "/api/discoveries/{discovery_id}",
    response_model=DiscoveryPublic,
)
def get_discovery(
    discovery_id: UUID,
    service: DiscoveryServiceDependency,
) -> DiscoveryPublic:
    try:
        return DiscoveryPublic.model_validate(service.get(str(discovery_id)))
    except DiscoveryNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Discovery not found") from exc
