"""Dashboard site and scope routes."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status

from forgesec_api.dependencies import get_site_service
from forgesec_api.sites.models import ScopeCreate, ScopePublic, SiteCreate, SitePublic
from forgesec_api.sites.service import InvalidScope, SiteNotFound, SiteService

router = APIRouter(prefix="/api/sites", tags=["sites"])
SiteDependency = Annotated[SiteService, Depends(get_site_service)]


@router.get("", response_model=list[SitePublic])
def list_sites(service: SiteDependency) -> list[SitePublic]:
    return [SitePublic.model_validate(item) for item in service.list()]


@router.post("", response_model=SitePublic, status_code=status.HTTP_201_CREATED)
def create_site(payload: SiteCreate, service: SiteDependency) -> SitePublic:
    try:
        return SitePublic.model_validate(service.create(payload))
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc


@router.get("/{site_id}/scopes", response_model=list[ScopePublic])
def list_scopes(site_id: UUID, service: SiteDependency) -> list[ScopePublic]:
    try:
        return [
            ScopePublic.model_validate(item)
            for item in service.list_scopes(str(site_id))
        ]
    except SiteNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc


@router.post(
    "/{site_id}/scopes", response_model=ScopePublic, status_code=status.HTTP_201_CREATED
)
def add_scope(
    site_id: UUID, payload: ScopeCreate, service: SiteDependency
) -> ScopePublic:
    try:
        return ScopePublic.model_validate(service.add_scope(str(site_id), payload))
    except SiteNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except InvalidScope as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc


@router.delete("/{site_id}/scopes/{scope_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_scope(site_id: UUID, scope_id: UUID, service: SiteDependency) -> None:
    try:
        service.remove_scope(str(site_id), str(scope_id))
    except SiteNotFound as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
