"""Administrative and machine endpoints for central scanner workers."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from forgesec_api.dependencies import get_worker_service
from forgesec_api.workers.models import (
    GreenboneJobCreate,
    InventoryJobCreate,
    NucleiJobCreate,
    WorkerCreate,
    WorkerHeartbeat,
    WorkerJobClaim,
    WorkerJobDetail,
    WorkerJobPublic,
    WorkerLease,
    WorkerProvisioned,
    WorkerPublic,
    WorkerResult,
)
from forgesec_api.workers.service import (
    WorkerConflict,
    WorkerNotFound,
    WorkerScopeError,
    WorkerService,
    WorkerUnauthorized,
)

admin_router = APIRouter(prefix="/api/workers", tags=["scanner workers"])
jobs_router = APIRouter(prefix="/api/worker-jobs", tags=["scanner workers"])
machine_router = APIRouter(prefix="/worker", tags=["scanner worker protocol"])
WorkerServiceDependency = Annotated[WorkerService, Depends(get_worker_service)]
bearer = HTTPBearer(auto_error=False)
BearerCredentials = Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]


def authenticate_worker(
    credentials: BearerCredentials, service: WorkerServiceDependency,
    request: Request,
) -> dict:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Worker credential required")
    try:
        worker = service.authenticate(credentials.credentials)
        request.state.worker_id = worker["worker_id"]
        return worker
    except WorkerUnauthorized as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid worker credential"
        ) from exc


AuthenticatedWorker = Annotated[dict, Depends(authenticate_worker)]


def _public_job(job: dict) -> WorkerJobPublic:
    return WorkerJobPublic.model_validate(
        {key: job.get(key) for key in WorkerJobPublic.model_fields}
    )


def _claimed_job(job: dict) -> WorkerJobClaim:
    return WorkerJobClaim.model_validate(
        {key: job.get(key) for key in WorkerJobClaim.model_fields}
    )


def _worker_error(exc: Exception) -> HTTPException:
    if isinstance(exc, WorkerUnauthorized):
        return HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid worker credential")
    if isinstance(exc, WorkerNotFound):
        return HTTPException(status.HTTP_404_NOT_FOUND, "Worker job not found")
    if isinstance(exc, WorkerScopeError):
        return HTTPException(status.HTTP_409_CONFLICT, str(exc))
    return HTTPException(status.HTTP_409_CONFLICT, str(exc))


@admin_router.post("", response_model=WorkerProvisioned, status_code=201)
def provision_worker(
    payload: WorkerCreate, request: Request, service: WorkerServiceDependency
) -> WorkerProvisioned:
    actor = getattr(request.state, "user", None)
    try:
        worker, credential = service.provision(
            payload, actor_id=actor["user_id"] if actor else None
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Site not found") from exc
    return WorkerProvisioned.model_validate(
        service.public(worker) | {"credential": credential}
    )


@admin_router.get("", response_model=list[WorkerPublic])
def list_workers(service: WorkerServiceDependency) -> list[WorkerPublic]:
    return [WorkerPublic.model_validate(item) for item in service.list_public()]


@admin_router.post("/{worker_id}/revoke", response_model=WorkerPublic)
def revoke_worker(
    worker_id: UUID, request: Request, service: WorkerServiceDependency
) -> WorkerPublic:
    actor = getattr(request.state, "user", None)
    try:
        worker = service.revoke(
            str(worker_id), actor_id=actor["user_id"] if actor else None
        )
    except (WorkerNotFound, WorkerConflict) as exc:
        raise _worker_error(exc) from exc
    return WorkerPublic.model_validate(service.public(worker))


@jobs_router.get("", response_model=list[WorkerJobPublic])
def list_jobs(
    service: WorkerServiceDependency,
    asset_id: UUID | None = None,
    site_id: UUID | None = None,
) -> list[WorkerJobPublic]:
    jobs = service.list_jobs(
        asset_id=str(asset_id) if asset_id else None,
        site_id=str(site_id) if site_id else None,
    )
    jobs.sort(key=lambda job: job["created_at"], reverse=True)
    return [_public_job(job) for job in jobs[:100]]


@jobs_router.post("/nuclei", response_model=WorkerJobPublic, status_code=202)
def enqueue_nuclei_job(
    payload: NucleiJobCreate,
    request: Request,
    service: WorkerServiceDependency,
) -> WorkerJobPublic:
    actor = getattr(request.state, "user", None)
    try:
        job = service.enqueue_nuclei(
            payload, actor_id=actor["user_id"] if actor else None
        )
    except (WorkerScopeError, WorkerConflict) as exc:
        raise _worker_error(exc) from exc
    return _public_job(job)


@jobs_router.post("/greenbone", response_model=WorkerJobPublic, status_code=202)
def enqueue_greenbone_job(
    payload: GreenboneJobCreate,
    request: Request,
    service: WorkerServiceDependency,
) -> WorkerJobPublic:
    actor = getattr(request.state, "user", None)
    try:
        job = service.enqueue_greenbone(
            payload, actor_id=actor["user_id"] if actor else None
        )
    except (WorkerScopeError, WorkerConflict) as exc:
        raise _worker_error(exc) from exc
    return _public_job(job)


@jobs_router.post("/inventory", response_model=WorkerJobPublic, status_code=202)
def enqueue_inventory_job(
    payload: InventoryJobCreate,
    request: Request,
    service: WorkerServiceDependency,
) -> WorkerJobPublic:
    actor = getattr(request.state, "user", None)
    try:
        job = service.enqueue_inventory(
            payload, actor_id=actor["user_id"] if actor else None
        )
    except (WorkerScopeError, WorkerConflict) as exc:
        raise _worker_error(exc) from exc
    return _public_job(job)


@jobs_router.post("/{job_id}/cancel", response_model=WorkerJobPublic)
def cancel_central_job(
    job_id: UUID, request: Request, service: WorkerServiceDependency
) -> WorkerJobPublic:
    actor = getattr(request.state, "user", None)
    try:
        if actor and actor["role"] != "admin":
            try:
                current = service.get_job(str(job_id))
            except WorkerNotFound as exc:
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN, "Administrator access required"
                ) from exc
            if current.get("template_profile") != "http_baseline":
                raise HTTPException(
                    status.HTTP_403_FORBIDDEN, "Administrator access required"
                )
        job = service.cancel_job(
            str(job_id), actor_id=actor["user_id"] if actor else None
        )
    except (WorkerNotFound, WorkerConflict) as exc:
        raise _worker_error(exc) from exc
    return _public_job(job)


@jobs_router.get("/{job_id}", response_model=WorkerJobDetail)
def get_job(job_id: UUID, service: WorkerServiceDependency) -> WorkerJobDetail:
    try:
        job = service.get_job(str(job_id))
    except WorkerNotFound as exc:
        raise _worker_error(exc) from exc
    public = _public_job(job).model_dump(mode="json")
    evidence = (
        job.get("evidence")
        if job.get("template_profile")
        or job.get("assessment_profile")
        or job.get("inventory_profile")
        else None
    )
    return WorkerJobDetail.model_validate({**public, "evidence": evidence or None})


@machine_router.post("/heartbeat", response_model=WorkerPublic)
def worker_heartbeat(
    payload: WorkerHeartbeat,
    authenticated: AuthenticatedWorker,
    service: WorkerServiceDependency,
) -> WorkerPublic:
    try:
        worker = service.heartbeat(authenticated, payload)
    except (WorkerUnauthorized, WorkerConflict) as exc:
        raise _worker_error(exc) from exc
    return WorkerPublic.model_validate(service.public(worker))


@machine_router.get("/jobs/next", response_model=WorkerJobClaim)
def next_job(
    authenticated: AuthenticatedWorker, service: WorkerServiceDependency
) -> WorkerJobClaim | Response:
    try:
        job = service.claim_next(authenticated)
    except WorkerUnauthorized as exc:
        raise _worker_error(exc) from exc
    return _claimed_job(job) if job else Response(status_code=204)


@machine_router.post("/jobs/{job_id}/heartbeat", response_model=WorkerJobClaim)
def renew_job(
    job_id: UUID,
    payload: WorkerLease,
    authenticated: AuthenticatedWorker,
    service: WorkerServiceDependency,
) -> WorkerJobClaim:
    try:
        return _claimed_job(
            service.renew(
                authenticated,
                str(job_id),
                str(payload.lease_id),
                progress=payload.progress,
                phase=payload.phase,
            )
        )
    except (
        WorkerUnauthorized,
        WorkerNotFound,
        WorkerConflict,
        WorkerScopeError,
    ) as exc:
        raise _worker_error(exc) from exc


@machine_router.post("/jobs/{job_id}/result", response_model=WorkerJobPublic)
def complete_job(
    job_id: UUID,
    payload: WorkerResult,
    authenticated: AuthenticatedWorker,
    service: WorkerServiceDependency,
) -> WorkerJobPublic:
    try:
        return _public_job(service.complete(authenticated, str(job_id), payload))
    except (
        WorkerUnauthorized,
        WorkerNotFound,
        WorkerConflict,
        WorkerScopeError,
    ) as exc:
        raise _worker_error(exc) from exc
