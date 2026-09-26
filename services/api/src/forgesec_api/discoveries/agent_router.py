"""Authenticated discovery-result upload route."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from forgesec_api.agents.auth import authenticate_agent
from forgesec_api.dependencies import get_discovery_service
from forgesec_api.discoveries.models import (
    DiscoveryControlResponse,
    DiscoveryPublic,
    DiscoveryResult,
)
from forgesec_api.discoveries.service import (
    DiscoveryNotFound,
    DiscoveryOwnershipError,
    DiscoveryService,
    InvalidDiscoveryResult,
)

router = APIRouter(prefix="/agent/discoveries", tags=["agent protocol"])
AuthenticatedAgent = Annotated[dict, Depends(authenticate_agent)]
DiscoveryServiceDependency = Annotated[
    DiscoveryService,
    Depends(get_discovery_service),
]


@router.post("/{discovery_id}/devices", response_model=DiscoveryPublic)
def upload_discovery(
    discovery_id: UUID,
    payload: DiscoveryResult,
    authenticated: AuthenticatedAgent,
    service: DiscoveryServiceDependency,
) -> DiscoveryPublic:
    if discovery_id != payload.discovery_id:
        raise HTTPException(status.HTTP_409_CONFLICT, "Discovery ID mismatch")
    try:
        record = service.save_result(authenticated["agent_id"], payload)
    except DiscoveryNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Discovery not found") from exc
    except DiscoveryOwnershipError as exc:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Discovery belongs to another agent"
        ) from exc
    except InvalidDiscoveryResult as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    return DiscoveryPublic.model_validate(record)


@router.get("/{discovery_id}/control", response_model=DiscoveryControlResponse)
def discovery_control(
    discovery_id: UUID,
    authenticated: AuthenticatedAgent,
    service: DiscoveryServiceDependency,
) -> DiscoveryControlResponse:
    try:
        return DiscoveryControlResponse.model_validate(
            service.control(str(discovery_id), authenticated["agent_id"])
        )
    except DiscoveryNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Discovery not found") from exc
    except DiscoveryOwnershipError as exc:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Discovery belongs to another agent"
        ) from exc
