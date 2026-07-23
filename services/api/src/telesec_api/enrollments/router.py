"""Dashboard enrollment-token routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, status

from telesec_api.dependencies import get_enrollment_service
from telesec_api.enrollments.models import (
    EnrollmentCreateRequest,
    EnrollmentCreateResponse,
)
from telesec_api.enrollments.service import EnrollmentService

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
    record, token = service.create(label=payload.label, site_name=payload.site_name)
    return EnrollmentCreateResponse(
        enrollment_id=record["enrollment_id"],
        enrollment_token=token,
        expires_at=record["expires_at"],
    )
