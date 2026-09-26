"""Human sign-in and administrator-managed access."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import Field

from forgesec_api.auth.service import (
    SECURE_SESSION_COOKIE,
    SESSION_COOKIE,
    AuthError,
    AuthService,
)
from forgesec_api.dependencies import get_auth_service, get_settings
from forgesec_api.models import StrictModel
from forgesec_api.settings import Settings

router = APIRouter(prefix="/api/auth", tags=["operator access"])
AuthDependency = Annotated[AuthService, Depends(get_auth_service)]
SettingsDependency = Annotated[Settings, Depends(get_settings)]


class LoginRequest(StrictModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)


class UserPublic(StrictModel):
    user_id: UUID
    email: str
    role: Literal["admin", "operator", "viewer"]
    active: bool
    created_at: datetime


class MeResponse(StrictModel):
    user: UserPublic | None
    csrf_token: str
    auth_required: bool


class UserCreate(StrictModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=256)
    role: Literal["admin", "operator", "viewer"]


class UserActiveUpdate(StrictModel):
    active: bool


class PasswordChange(StrictModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


@router.post("/login", response_model=MeResponse)
def login(
    payload: LoginRequest,
    response: Response,
    auth: AuthDependency,
    settings: SettingsDependency,
) -> MeResponse:
    if not settings.auth_required:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Access control is disabled")
    try:
        user, token, csrf_token = auth.login(payload.email, payload.password)
    except AuthError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    secure = settings.web_origin.startswith("https://")
    response.set_cookie(
        SECURE_SESSION_COOKIE if secure else SESSION_COOKIE,
        token,
        max_age=settings.session_ttl_seconds,
        path="/",
        secure=secure,
        httponly=True,
        samesite="strict",
    )
    return MeResponse(
        user=UserPublic.model_validate(user), csrf_token=csrf_token, auth_required=True
    )


@router.get("/me", response_model=MeResponse)
def me(request: Request, settings: SettingsDependency) -> MeResponse:
    if not settings.auth_required:
        return MeResponse(user=None, csrf_token="", auth_required=False)
    return MeResponse(
        user=UserPublic.model_validate(request.state.user),
        csrf_token=request.state.session["csrf_token"],
        auth_required=True,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    auth: AuthDependency,
    settings: SettingsDependency,
) -> None:
    cookie_name = (
        SECURE_SESSION_COOKIE
        if settings.web_origin.startswith("https://")
        else SESSION_COOKIE
    )
    auth.revoke(request.cookies.get(cookie_name))
    response.delete_cookie(
        SECURE_SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="strict"
    )
    response.delete_cookie(SESSION_COOKIE, path="/")


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    payload: PasswordChange, request: Request, response: Response, auth: AuthDependency
) -> None:
    try:
        auth.change_password(
            request.state.user["user_id"],
            payload.current_password,
            payload.new_password,
        )
    except AuthError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    response.delete_cookie(
        SECURE_SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="strict"
    )
    response.delete_cookie(SESSION_COOKIE, path="/")


@router.get("/users", response_model=list[UserPublic])
def users(auth: AuthDependency) -> list[UserPublic]:
    return [UserPublic.model_validate(auth.public(user)) for user in auth.users()]


@router.post("/users", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreate, auth: AuthDependency) -> UserPublic:
    try:
        return UserPublic.model_validate(
            auth.create_user(payload.email, payload.password, payload.role)
        )
    except AuthError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc


@router.patch("/users/{user_id}", response_model=UserPublic)
def set_user_active(
    user_id: UUID, payload: UserActiveUpdate, auth: AuthDependency
) -> UserPublic:
    try:
        return UserPublic.model_validate(auth.set_active(str(user_id), payload.active))
    except AuthError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
