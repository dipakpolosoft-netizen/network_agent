"""Telesec FastAPI application entry point."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from telesec_api import __version__
from telesec_api.agents.agent_router import router as agent_protocol_router
from telesec_api.agents.api_router import router as agents_router
from telesec_api.agents.service import AgentService
from telesec_api.commands.agent_router import router as commands_agent_router
from telesec_api.commands.service import CommandService
from telesec_api.discoveries.agent_router import router as discoveries_agent_router
from telesec_api.discoveries.api_router import router as discoveries_api_router
from telesec_api.discoveries.service import DiscoveryService
from telesec_api.enrollments.router import router as enrollments_router
from telesec_api.enrollments.service import EnrollmentService
from telesec_api.models import HealthResponse
from telesec_api.scans.agent_router import router as scans_agent_router
from telesec_api.scans.api_router import router as scans_api_router
from telesec_api.scans.service import ScanService
from telesec_api.settings import Settings
from telesec_api.storage import JsonStore
from telesec_api.time import utc_now


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved_settings = settings or Settings.from_env()
    store = JsonStore(resolved_settings.runtime_data_dir)
    enrollment_service = EnrollmentService(store, resolved_settings)
    agent_service = AgentService(store, resolved_settings, enrollment_service)
    command_service = CommandService(store, resolved_settings)
    discovery_service = DiscoveryService(
        store,
        resolved_settings,
        agent_service,
        command_service,
    )
    scan_service = ScanService(
        store,
        resolved_settings,
        agent_service,
        discovery_service,
        command_service,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        store.initialize()
        yield

    app = FastAPI(
        title="Telesec API",
        version=__version__,
        lifespan=lifespan,
    )
    app.state.settings = resolved_settings
    app.state.store = store
    app.state.enrollment_service = enrollment_service
    app.state.agent_service = agent_service
    app.state.command_service = command_service
    app.state.discovery_service = discovery_service
    app.state.scan_service = scan_service
    web_origins = [resolved_settings.web_origin]
    if resolved_settings.environment == "development":
        web_origins.extend(["http://localhost:3000", "http://127.0.0.1:3000"])
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(dict.fromkeys(web_origins)),
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )
    app.include_router(enrollments_router)
    app.include_router(agents_router)
    app.include_router(agent_protocol_router)
    app.include_router(commands_agent_router)
    app.include_router(discoveries_api_router)
    app.include_router(discoveries_agent_router)
    app.include_router(scans_api_router)
    app.include_router(scans_agent_router)

    @app.get("/health", response_model=HealthResponse, tags=["system"])
    def health() -> HealthResponse:
        return HealthResponse(
            status="ok",
            service="telesec-api",
            version=__version__,
            environment=resolved_settings.environment,
            server_time=utc_now(),
        )

    return app


app = create_app()


def run() -> None:
    settings = Settings.from_env()
    uvicorn.run(
        "telesec_api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.environment == "development",
        workers=1,
    )


if __name__ == "__main__":
    run()
