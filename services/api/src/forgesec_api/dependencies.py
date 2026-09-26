"""FastAPI state dependencies."""

from __future__ import annotations

from fastapi import Request

from forgesec_api.agents.service import AgentService
from forgesec_api.assets.service import AssetService
from forgesec_api.auth.service import AuthService
from forgesec_api.commands.service import CommandService
from forgesec_api.discoveries.service import DiscoveryService
from forgesec_api.enrollments.service import EnrollmentService
from forgesec_api.scans.service import ScanService
from forgesec_api.settings import Settings
from forgesec_api.sites.service import SiteService
from forgesec_api.storage import JsonStore
from forgesec_api.vulnerabilities.service import VulnerabilityService
from forgesec_api.workers.service import WorkerService


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_store(request: Request) -> JsonStore:
    return request.app.state.store


def get_auth_service(request: Request) -> AuthService:
    return request.app.state.auth_service


def get_site_service(request: Request) -> SiteService:
    return request.app.state.site_service


def get_enrollment_service(request: Request) -> EnrollmentService:
    return request.app.state.enrollment_service


def get_agent_service(request: Request) -> AgentService:
    return request.app.state.agent_service


def get_asset_service(request: Request) -> AssetService:
    return request.app.state.asset_service


def get_command_service(request: Request) -> CommandService:
    return request.app.state.command_service


def get_discovery_service(request: Request) -> DiscoveryService:
    return request.app.state.discovery_service


def get_scan_service(request: Request) -> ScanService:
    return request.app.state.scan_service


def get_vulnerability_service(request: Request) -> VulnerabilityService:
    return request.app.state.vulnerability_service


def get_worker_service(request: Request) -> WorkerService:
    return request.app.state.worker_service
