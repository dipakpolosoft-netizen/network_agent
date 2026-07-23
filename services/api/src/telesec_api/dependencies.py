"""FastAPI state dependencies."""

from __future__ import annotations

from fastapi import Request

from telesec_api.agents.service import AgentService
from telesec_api.commands.service import CommandService
from telesec_api.discoveries.service import DiscoveryService
from telesec_api.enrollments.service import EnrollmentService
from telesec_api.scans.service import ScanService
from telesec_api.settings import Settings
from telesec_api.storage import JsonStore


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_store(request: Request) -> JsonStore:
    return request.app.state.store


def get_enrollment_service(request: Request) -> EnrollmentService:
    return request.app.state.enrollment_service


def get_agent_service(request: Request) -> AgentService:
    return request.app.state.agent_service


def get_command_service(request: Request) -> CommandService:
    return request.app.state.command_service


def get_discovery_service(request: Request) -> DiscoveryService:
    return request.app.state.discovery_service


def get_scan_service(request: Request) -> ScanService:
    return request.app.state.scan_service
