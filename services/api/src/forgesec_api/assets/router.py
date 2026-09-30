"""Operator access to durable asset inventory and evidence references."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from forgesec_api.activity import record_activity
from forgesec_api.assets.device_profile import build_device_profile
from forgesec_api.assets.evidence import build_asset_evidence
from forgesec_api.assets.models import (
    AssetDeviceProfile,
    AssetEvidence,
    AssetEvidenceItem,
    AssetEvidenceReviewPatch,
    AssetList,
    AssetObservation,
    AssetPatch,
    AssetPublic,
    TopologyGraph,
)
from forgesec_api.assets.service import AssetNotFound, AssetService
from forgesec_api.assets.topology import build_topology
from forgesec_api.dependencies import get_asset_service, get_scan_service
from forgesec_api.scans.service import ScanService
from forgesec_api.time import isoformat, utc_now

router = APIRouter(prefix="/api/assets", tags=["assets"])
AssetServiceDependency = Annotated[AssetService, Depends(get_asset_service)]
ScanServiceDependency = Annotated[ScanService, Depends(get_scan_service)]


@router.get("", response_model=AssetList)
def list_assets(
    service: AssetServiceDependency,
    site_id: UUID | None = None,
    query: str = Query(default="", max_length=128),
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> AssetList:
    return AssetList.model_validate(
        service.list_assets(
            site_id=str(site_id) if site_id else None,
            query=query.strip(),
            limit=limit,
            offset=offset,
        )
    )


@router.get("/topology", response_model=TopologyGraph)
def site_topology(
    service: AssetServiceDependency,
    site_id: UUID,
    include_stale: bool = False,
) -> TopologyGraph:
    if not service.store.read("sites", str(site_id)):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Site not found")
    return TopologyGraph.model_validate(
        build_topology(service.store, str(site_id), include_stale=include_stale)
    )


@router.get("/{asset_id}", response_model=AssetPublic)
def get_asset(asset_id: UUID, service: AssetServiceDependency) -> AssetPublic:
    try:
        return AssetPublic.model_validate(service.get(str(asset_id)))
    except AssetNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found") from exc


@router.get("/{asset_id}/observations", response_model=list[AssetObservation])
def asset_observations(
    asset_id: UUID,
    service: AssetServiceDependency,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> list[AssetObservation]:
    try:
        items = service.observations(str(asset_id), limit=limit, offset=offset)
    except AssetNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found") from exc
    return [AssetObservation.model_validate(item) for item in items]


@router.get("/{asset_id}/evidence", response_model=AssetEvidence)
def asset_evidence(
    asset_id: UUID,
    service: AssetServiceDependency,
    scans: ScanServiceDependency,
) -> AssetEvidence:
    try:
        asset = service.get(str(asset_id))
    except AssetNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found") from exc
    return AssetEvidence.model_validate(
        build_asset_evidence(service.store, scans, asset)
    )


@router.patch(
    "/{asset_id}/evidence/{review_id}/review", response_model=AssetEvidenceItem
)
def review_asset_evidence(
    asset_id: UUID,
    review_id: str,
    payload: AssetEvidenceReviewPatch,
    request: Request,
    service: AssetServiceDependency,
    scans: ScanServiceDependency,
) -> AssetEvidenceItem:
    if len(review_id) != 64 or any(
        char not in "0123456789abcdef" for char in review_id
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Evidence not found")
    if (
        payload.status in {"false_positive", "accepted_risk"}
        and not payload.note.strip()
    ):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "Review reason required"
        )
    try:
        asset = service.get(str(asset_id))
    except AssetNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found") from exc
    with service.store.locked():
        evidence = build_asset_evidence(service.store, scans, asset)
        item = next(
            (item for item in evidence["items"] if item["review_id"] == review_id), None
        )
        if item is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Evidence not found")
        actor = getattr(request.state, "user", None)
        actor_id = actor["user_id"] if actor else None
        previous = item["review_status"]
        review = {
            "review_id": review_id,
            "asset_id": str(asset_id),
            "site_id": asset["site_id"],
            "source": item["source"],
            "source_id": item["source_id"],
            "status": payload.status,
            "note": payload.note.strip(),
            "actor_id": actor_id,
            "updated_at": isoformat(utc_now()),
        }
        service.store.write("asset-evidence-reviews", review_id, review)
        record_activity(
            service.store,
            event_type="asset_evidence.reviewed",
            message="Asset evidence review updated",
            actor_type="user" if actor_id else "server",
            actor_id=actor_id,
            resource_type="asset",
            resource_id=str(asset_id),
            details={
                "review_id": review_id,
                "source": item["source"],
                "source_id": item["source_id"],
                "previous_status": previous,
                "status": payload.status,
            },
        )
        item.update(
            review_status=review["status"],
            review_note=review["note"] or None,
            reviewed_at=review["updated_at"],
            reviewed_by=actor_id,
        )
        return AssetEvidenceItem.model_validate(item)


@router.get("/{asset_id}/device-profile", response_model=AssetDeviceProfile)
def asset_device_profile(
    asset_id: UUID, service: AssetServiceDependency
) -> AssetDeviceProfile:
    try:
        asset = service.get(str(asset_id))
    except AssetNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found") from exc
    return AssetDeviceProfile.model_validate(build_device_profile(service.store, asset))


@router.patch("/{asset_id}", response_model=AssetPublic)
def update_asset(
    asset_id: UUID,
    payload: AssetPatch,
    request: Request,
    service: AssetServiceDependency,
) -> AssetPublic:
    actor = getattr(request.state, "user", None)
    try:
        return AssetPublic.model_validate(
            service.update(
                str(asset_id),
                payload,
                actor_id=actor["user_id"] if actor else None,
            )
        )
    except AssetNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found") from exc
