"""Dashboard enrollment-token routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from forgesec_api.dependencies import get_enrollment_service
from forgesec_api.enrollments.models import (
    EnrollmentCreateRequest,
    EnrollmentCreateResponse,
)
from forgesec_api.enrollments.service import EnrollmentService
from forgesec_api.sites.service import SiteNotFound

router = APIRouter(prefix="/api/enrollments", tags=["enrollments"])
EnrollmentServiceDependency = Annotated[
    EnrollmentService,
    Depends(get_enrollment_service),
]


@router.post(
    "",
    response_model=EnrollmentCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_enrollment(
    payload: EnrollmentCreateRequest,
    service: EnrollmentServiceDependency,
) -> EnrollmentCreateResponse:
    try:
        record, token = service.create(
            label=payload.label,
            site_name=payload.site_name,
            site_id=str(payload.site_id) if payload.site_id else None,
        )
    except SiteNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    return EnrollmentCreateResponse(
        enrollment_id=record["enrollment_id"],
        enrollment_token=token,
        expires_at=record["expires_at"],
    )
