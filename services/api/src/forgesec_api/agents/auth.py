"""Bearer authentication for installed agents."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from forgesec_api.agents.service import AgentService, InvalidAgentCredential
from forgesec_api.dependencies import get_agent_service

bearer = HTTPBearer(auto_error=False)
BearerCredentials = Annotated[
    HTTPAuthorizationCredentials | None,
    Depends(bearer),
]
AgentServiceDependency = Annotated[AgentService, Depends(get_agent_service)]


def authenticate_agent(
    credentials: BearerCredentials,
    service: AgentServiceDependency,
    request: Request,
) -> dict:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Agent credential required",
        )
    try:
        agent = service.authenticate(credentials.credentials)
        request.state.agent_id = agent["agent_id"]
        return agent
    except InvalidAgentCredential as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid agent credential",
        ) from exc
