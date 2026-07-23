"""Dashboard selected-device scan routes."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from telesec_api.dependencies import get_scan_service
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

router = APIRouter(tags=["scans"])
ScanServiceDependency = Annotated[ScanService, Depends(get_scan_service)]


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


@router.post("/api/scans/{scan_id}/cancel", response_model=ScanPublic)
def cancel_scan(scan_id: UUID, service: ScanServiceDependency) -> ScanPublic:
    try:
        return ScanPublic.model_validate(service.request_cancel(str(scan_id)))
    except ScanNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found") from exc
