"""ForgeSec FastAPI application entry point."""

from __future__ import annotations

import hmac
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from forgesec_api import __version__
from forgesec_api.activity import record_activity
from forgesec_api.agents.agent_router import router as agent_protocol_router
from forgesec_api.agents.api_router import router as agents_router
from forgesec_api.agents.service import AgentService
from forgesec_api.assets.router import router as assets_router
from forgesec_api.assets.service import AssetService
from forgesec_api.auth.router import router as auth_router
from forgesec_api.auth.service import (
    SECURE_SESSION_COOKIE,
    SESSION_COOKIE,
    AuthService,
)
from forgesec_api.commands.agent_router import router as commands_agent_router
from forgesec_api.commands.service import CommandService
from forgesec_api.customer_binding import bind_customer
from forgesec_api.discoveries.agent_router import router as discoveries_agent_router
from forgesec_api.discoveries.api_router import router as discoveries_api_router
from forgesec_api.discoveries.service import DiscoveryService
from forgesec_api.enrollments.router import router as enrollments_router
from forgesec_api.enrollments.service import EnrollmentService
from forgesec_api.models import HealthResponse
from forgesec_api.scans.agent_router import router as scans_agent_router
from forgesec_api.scans.api_router import router as scans_api_router
from forgesec_api.scans.service import ScanService
from forgesec_api.settings import Settings
from forgesec_api.sites.router import router as sites_router
from forgesec_api.sites.service import SiteService
from forgesec_api.storage import JsonStore
from forgesec_api.time import utc_now
from forgesec_api.vulnerabilities.service import VulnerabilityService
from forgesec_api.workers.router import admin_router as workers_admin_router
from forgesec_api.workers.router import jobs_router as worker_jobs_router
from forgesec_api.workers.router import machine_router as workers_machine_router
from forgesec_api.workers.service import WorkerService


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved_settings = settings or Settings.from_env()
    if resolved_settings.database_url:
        from forgesec_api.postgres_storage import PostgresStore

        store = PostgresStore(
            resolved_settings.runtime_data_dir, resolved_settings.database_url
        )
    else:
        store = JsonStore(resolved_settings.runtime_data_dir)
    auth_service = AuthService(store, resolved_settings.session_ttl_seconds)
    site_service = SiteService(store)
    enrollment_service = EnrollmentService(store, resolved_settings, site_service)
    agent_service = AgentService(
        store, resolved_settings, enrollment_service, site_service
    )
    command_service = CommandService(store, resolved_settings)
    asset_service = AssetService(store)
    discovery_service = DiscoveryService(
        store,
        resolved_settings,
        agent_service,
        command_service,
        site_service,
        asset_service,
    )
    scan_service = ScanService(
        store,
        resolved_settings,
        agent_service,
        discovery_service,
        command_service,
        site_service,
        asset_service,
    )
    vulnerability_service = VulnerabilityService(
        resolved_settings.runtime_data_dir / "vulnerability-cache",
        api_key=resolved_settings.nvd_api_key,
        cache_ttl_seconds=resolved_settings.nvd_cache_ttl_seconds,
        timeout_seconds=resolved_settings.nvd_timeout_seconds,
        store=store,
    )
    worker_service = WorkerService(store, site_service)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        store.initialize()
        bind_customer(
            store,
            resolved_settings.customer_id,
            adopt_legacy_data=resolved_settings.adopt_legacy_customer_data,
            required=resolved_settings.environment == "production",
        )
        site_service.migrate_legacy_agents()
        asset_service.backfill()
        try:
            yield
        finally:
            if resolved_settings.database_url:
                store.close()

    app = FastAPI(
        title="ForgeSec API",
        version=__version__,
        lifespan=lifespan,
    )
    app.state.settings = resolved_settings
    app.state.store = store
    app.state.auth_service = auth_service
    app.state.site_service = site_service
    app.state.enrollment_service = enrollment_service
    app.state.agent_service = agent_service
    app.state.command_service = command_service
    app.state.asset_service = asset_service
    app.state.discovery_service = discovery_service
    app.state.scan_service = scan_service
    app.state.vulnerability_service = vulnerability_service
    app.state.worker_service = worker_service
    web_origins = [resolved_settings.web_origin]
    if resolved_settings.environment == "development":
        web_origins.extend(["http://localhost:3000", "http://127.0.0.1:3000"])
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(dict.fromkeys(web_origins)),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
    )

    @app.middleware("http")
    async def protect_operator_api(request: Request, call_next):
        path = request.url.path

        async def no_store_response():
            response = await call_next(request)
            response.headers["Cache-Control"] = "private, no-store"
            return response

        if request.method == "OPTIONS" or not path.startswith("/api/"):
            return await call_next(request)
        if not resolved_settings.auth_required:
            if path.startswith("/api/auth/users"):
                return JSONResponse(
                    {"detail": "Access control is disabled"}, status_code=403
                )
            return await no_store_response()
        if path == "/api/auth/login":
            origin = request.headers.get("origin")
            accepted = {resolved_settings.web_origin.rstrip("/")}
            if resolved_settings.environment == "development":
                accepted.update(
                    {
                        f"http://{host}:{port}"
                        for host in ("localhost", "127.0.0.1")
                        for port in (3000, 3001)
                    }
                )
            if resolved_settings.environment != "test" and origin not in accepted:
                return JSONResponse(
                    {"detail": "Untrusted login origin"}, status_code=403
                )
            return await no_store_response()
        cookie_name = (
            SECURE_SESSION_COOKIE
            if resolved_settings.web_origin.startswith("https://")
            else SESSION_COOKIE
        )
        token = request.cookies.get(cookie_name)
        identity = auth_service.session(token)
        if identity is None:
            return JSONResponse({"detail": "Sign in required"}, status_code=401)
        user, session = identity
        request.state.user = user
        request.state.session = session
        mutation = request.method not in {"GET", "HEAD"}
        if path.startswith("/api/auth/users") and user["role"] != "admin":
            return JSONResponse(
                {"detail": "Administrator access required"}, status_code=403
            )
        if mutation:
            if (
                path in {"/api/worker-jobs/greenbone", "/api/worker-jobs/inventory"}
            ) and user["role"] != "admin":
                return JSONResponse(
                    {"detail": "Administrator access required"}, status_code=403
                )
            if user["role"] == "viewer" and path not in {
                "/api/auth/logout",
                "/api/auth/password",
            }:
                return JSONResponse({"detail": "Read-only access"}, status_code=403)
            if (
                path.startswith("/api/sites")
                or path.startswith("/api/enrollments")
                or path.startswith("/api/workers")
                or (path.startswith("/api/agents/") and path.endswith("/revoke"))
            ) and user["role"] != "admin":
                return JSONResponse(
                    {"detail": "Administrator access required"}, status_code=403
                )
            if not hmac.compare_digest(
                request.headers.get("x-csrf-token", ""), session["csrf_token"]
            ):
                return JSONResponse(
                    {"detail": "Invalid request token"}, status_code=403
                )
        return await no_store_response()

    @app.middleware("http")
    async def audit_policy_denials(request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        if path.startswith(("/api/", "/agent/", "/worker/")):
            response.headers["Cache-Control"] = "private, no-store"
        families = (
            "/api/agents",
            "/api/discoveries",
            "/api/scans",
            "/api/sites",
            "/api/enrollments",
            "/api/auth/users",
            "/api/worker-jobs",
            "/api/workers",
            "/agent",
            "/worker",
        )
        family = next(
            (item for item in families if path == item or path.startswith(item + "/")),
            None,
        )
        if family and response.status_code in {403, 409, 410, 422}:
            route = request.scope.get("route")
            pattern = getattr(route, "path", None) or family
            user = getattr(request.state, "user", None)
            agent_id = getattr(request.state, "agent_id", None)
            worker_id = getattr(request.state, "worker_id", None)
            actor_type = (
                "user"
                if user
                else "agent"
                if agent_id
                else "scanner_worker"
                if worker_id
                else "server"
            )
            record_activity(
                store,
                event_type="security.request_denied",
                message="Security-sensitive request rejected",
                actor_type=actor_type,
                actor_id=(user["user_id"] if user else agent_id or worker_id),
                severity="warning",
                resource_type="api_route",
                details={
                    "method": request.method,
                    "route": pattern,
                    "status": response.status_code,
                },
            )
        return response

    app.include_router(auth_router)
    app.include_router(enrollments_router)
    app.include_router(sites_router)
    app.include_router(agents_router)
    app.include_router(agent_protocol_router)
    app.include_router(commands_agent_router)
    app.include_router(discoveries_api_router)
    app.include_router(discoveries_agent_router)
    app.include_router(scans_api_router)
    app.include_router(scans_agent_router)
    app.include_router(workers_admin_router)
    app.include_router(worker_jobs_router)
    app.include_router(workers_machine_router)
    app.include_router(assets_router)

    @app.get("/health", response_model=HealthResponse, tags=["system"])
    def health() -> HealthResponse:
        return HealthResponse(
            status="ok",
            service="forgesec-api",
            version=__version__,
            environment=resolved_settings.environment,
            server_time=utc_now(),
        )

    @app.get("/ready", include_in_schema=False)
    def ready() -> JSONResponse:
        try:
            binding = store.read("deployment", "customer")
            if resolved_settings.environment == "production" and (
                not binding
                or binding.get("customer_id") != resolved_settings.customer_id
            ):
                return JSONResponse(
                    {"status": "unavailable"},
                    status_code=503,
                    headers={"Cache-Control": "no-store"},
                )
        except Exception:
            return JSONResponse(
                {"status": "unavailable"},
                status_code=503,
                headers={"Cache-Control": "no-store"},
            )
        return JSONResponse({"status": "ready"}, headers={"Cache-Control": "no-store"})

    return app


app = create_app()


def run() -> None:
    settings = Settings.from_env()
    uvicorn.run(
        "forgesec_api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.environment == "development",
        workers=1,
    )


if __name__ == "__main__":
    run()
