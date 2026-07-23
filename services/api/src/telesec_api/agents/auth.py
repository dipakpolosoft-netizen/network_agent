"""Bearer authentication for installed agents."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from telesec_api.agents.service import AgentService, InvalidAgentCredential
from telesec_api.dependencies import get_agent_service

bearer = HTTPBearer(auto_error=False)
BearerCredentials = Annotated[
    HTTPAuthorizationCredentials | None,
    Depends(bearer),
]
AgentServiceDependency = Annotated[AgentService, Depends(get_agent_service)]


def authenticate_agent(
    credentials: BearerCredentials,
    service: AgentServiceDependency,
) -> dict:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Agent credential required",
        )
    try:
        return service.authenticate(credentials.credentials)
    except InvalidAgentCredential as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid agent credential",
        ) from exc
