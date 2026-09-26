"""Installed-agent enrollment and heartbeat routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from forgesec_api.agents.auth import BearerCredentials, authenticate_agent
from forgesec_api.agents.models import (
    AgentCredentialRotation,
    AgentHeartbeat,
    HeartbeatResponse,
)
from forgesec_api.agents.service import (
    AgentIdentityMismatch,
    AgentService,
    InvalidAgentCredential,
)
from forgesec_api.dependencies import get_agent_service
from forgesec_api.enrollments.models import AgentEnrollRequest, AgentEnrollResponse
from forgesec_api.enrollments.service import (
    EnrollmentConsumed,
    EnrollmentExpired,
    EnrollmentNotFound,
)
from forgesec_api.time import utc_now

router = APIRouter(prefix="/agent", tags=["agent protocol"])
AgentServiceDependency = Annotated[AgentService, Depends(get_agent_service)]
AuthenticatedAgent = Annotated[dict, Depends(authenticate_agent)]


@router.post(
    "/enroll",
    response_model=AgentEnrollResponse,
    status_code=status.HTTP_201_CREATED,
)
def enroll_agent(
    payload: AgentEnrollRequest,
    service: AgentServiceDependency,
) -> AgentEnrollResponse:
    try:
        agent, credential = service.enroll(payload)
    except EnrollmentNotFound as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Enrollment token not found",
        ) from exc
    except EnrollmentExpired as exc:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="Enrollment token expired",
        ) from exc
    except EnrollmentConsumed as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Enrollment token already used",
        ) from exc
    return AgentEnrollResponse(
        agent_id=agent["agent_id"],
        agent_credential=credential,
        heartbeat_interval_seconds=service.settings.heartbeat_interval_seconds,
        issued_at=utc_now(),
    )


@router.post("/heartbeat", response_model=HeartbeatResponse)
def heartbeat(
    payload: AgentHeartbeat,
    authenticated: AuthenticatedAgent,
    service: AgentServiceDependency,
) -> HeartbeatResponse:
    try:
        service.heartbeat(authenticated, payload)
    except AgentIdentityMismatch as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Credential does not belong to this agent",
        ) from exc
    except InvalidAgentCredential as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid agent credential",
        ) from exc
    return HeartbeatResponse(
        next_heartbeat_seconds=service.settings.heartbeat_interval_seconds,
        server_time=utc_now(),
    )


@router.get("/credentials/status")
def credential_status(authenticated: AuthenticatedAgent) -> dict[str, str]:
    return {"agent_id": authenticated["agent_id"]}


@router.post("/credentials/rotate", status_code=status.HTTP_204_NO_CONTENT)
def rotate_credential(
    payload: AgentCredentialRotation,
    authenticated: AuthenticatedAgent,
    credentials: BearerCredentials,
    service: AgentServiceDependency,
) -> None:
    if authenticated["agent_id"] != str(payload.agent_id):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Credential belongs to another agent"
        )
    try:
        service.rotate_credential(
            authenticated["agent_id"], credentials.credentials, payload.new_credential
        )
    except (InvalidAgentCredential, AgentIdentityMismatch) as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid agent credential"
        ) from exc
