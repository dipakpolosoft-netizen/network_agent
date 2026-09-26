"""Authenticated scan progress, result, and cancellation routes."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from forgesec_api.agents.auth import authenticate_agent
from forgesec_api.dependencies import get_scan_service
from forgesec_api.scans.models import (
    HostScanResult,
    ScanControlResponse,
    ScanProgress,
    ScanPublic,
)
from forgesec_api.scans.service import (
    InvalidScanSelection,
    ScanNotFound,
    ScanOwnershipError,
    ScanService,
)

router = APIRouter(prefix="/agent/scans", tags=["agent protocol"])
AuthenticatedAgent = Annotated[dict, Depends(authenticate_agent)]
ScanServiceDependency = Annotated[ScanService, Depends(get_scan_service)]


def translate_scan_error(exc: Exception) -> HTTPException:
    if isinstance(exc, ScanNotFound):
        return HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    if isinstance(exc, ScanOwnershipError):
        return HTTPException(status.HTTP_403_FORBIDDEN, "Scan belongs to another agent")
    return HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc))


@router.post("/{scan_id}/progress", response_model=ScanPublic)
def upload_progress(
    scan_id: UUID,
    payload: ScanProgress,
    authenticated: AuthenticatedAgent,
    service: ScanServiceDependency,
) -> ScanPublic:
    if scan_id != payload.scan_id:
        raise HTTPException(status.HTTP_409_CONFLICT, "Scan ID mismatch")
    try:
        record = service.save_progress(authenticated["agent_id"], payload)
    except (ScanNotFound, ScanOwnershipError, InvalidScanSelection) as exc:
        raise translate_scan_error(exc) from exc
    return ScanPublic.model_validate(record)


@router.post("/{scan_id}/hosts/{device_id}/result", response_model=ScanPublic)
def upload_result(
    scan_id: UUID,
    device_id: str,
    payload: HostScanResult,
    authenticated: AuthenticatedAgent,
    service: ScanServiceDependency,
) -> ScanPublic:
    try:
        record = service.save_result(
            scan_id=str(scan_id),
            device_id=device_id,
            agent_id=authenticated["agent_id"],
            result=payload,
        )
    except (ScanNotFound, ScanOwnershipError, InvalidScanSelection) as exc:
        raise translate_scan_error(exc) from exc
    return ScanPublic.model_validate(record)


@router.get("/{scan_id}/control", response_model=ScanControlResponse)
def scan_control(
    scan_id: UUID,
    authenticated: AuthenticatedAgent,
    service: ScanServiceDependency,
) -> ScanControlResponse:
    try:
        return ScanControlResponse.model_validate(
            service.control(str(scan_id), authenticated["agent_id"])
        )
    except (ScanNotFound, ScanOwnershipError) as exc:
        raise translate_scan_error(exc) from exc
