"""Dashboard selected-device scan routes."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from telesec_api.dependencies import get_scan_service, get_vulnerability_service
from telesec_api.scans.models import (
    ScanCreateRequest,
    ScanCreateResponse,
    ScanPublic,
)
from telesec_api.scans.service import (
    InvalidScanSelection,
    ScanNotFound,
    ScanService,
)
from telesec_api.vulnerabilities.models import VulnerabilityLookup
from telesec_api.vulnerabilities.service import (
    InvalidCpe,
    VulnerabilityProviderUnavailable,
    VulnerabilityService,
)

router = APIRouter(tags=["scans"])
ScanServiceDependency = Annotated[ScanService, Depends(get_scan_service)]
VulnerabilityServiceDependency = Annotated[
    VulnerabilityService, Depends(get_vulnerability_service)
]


@router.get("/api/scans", response_model=list[ScanPublic])
def list_scans(
    service: ScanServiceDependency,
    agent_id: UUID | None = None,
) -> list[ScanPublic]:
    return [
        ScanPublic.model_validate(item)
        for item in service.list(str(agent_id) if agent_id else None)
    ]


@router.post(
    "/api/discoveries/{discovery_id}/scan",
    response_model=ScanCreateResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def create_scan(
    discovery_id: UUID,
    payload: ScanCreateRequest,
    service: ScanServiceDependency,
) -> ScanCreateResponse:
    try:
        record = service.create(
            discovery_id=str(discovery_id),
            device_ids=payload.device_ids,
            profile=payload.profile,
        )
    except ScanNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Discovery not found") from exc
    except InvalidScanSelection as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    return ScanCreateResponse(
        scan_id=record["scan_id"],
        command_id=record["command_id"],
        total=record["total"],
        created_at=record["created_at"],
    )


@router.get("/api/scans/{scan_id}", response_model=ScanPublic)
def get_scan(scan_id: UUID, service: ScanServiceDependency) -> ScanPublic:
    try:
        return ScanPublic.model_validate(service.get(str(scan_id)))
    except ScanNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found") from exc


@router.get(
    "/api/scans/{scan_id}/devices/{device_id}/vulnerabilities",
    response_model=VulnerabilityLookup,
)
def get_device_vulnerabilities(
    scan_id: UUID,
    device_id: str,
    scan_service: ScanServiceDependency,
    vulnerability_service: VulnerabilityServiceDependency,
    cpe: Annotated[str, Query(min_length=8, max_length=1024)],
) -> VulnerabilityLookup:
    try:
        if cpe not in scan_service.observed_cpes(str(scan_id), device_id):
            raise InvalidScanSelection("CPE was not observed for this scanned device")
        return VulnerabilityLookup.model_validate(vulnerability_service.lookup(cpe))
    except ScanNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found") from exc
    except (InvalidScanSelection, InvalidCpe) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    except VulnerabilityProviderUnavailable as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from exc


@router.post("/api/scans/{scan_id}/cancel", response_model=ScanPublic)
def cancel_scan(scan_id: UUID, service: ScanServiceDependency) -> ScanPublic:
    try:
        return ScanPublic.model_validate(service.request_cancel(str(scan_id)))
    except ScanNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found") from exc
