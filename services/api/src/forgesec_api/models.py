"""Shared API response models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class HealthResponse(StrictModel):
    status: str
    service: str
    version: str
    environment: str
    server_time: datetime


class MessageResponse(StrictModel):
    status: str
    message: str
    server_time: datetime
