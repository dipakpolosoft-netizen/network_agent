"""Append-only activity event creation."""

from __future__ import annotations

from typing import Any, Literal
from uuid import uuid4

from forgesec_api.storage import JsonStore
from forgesec_api.time import isoformat, utc_now


def record_activity(
    store: JsonStore,
    *,
    event_type: str,
    message: str,
    actor_type: Literal["user", "server", "agent", "scanner_worker"] = "server",
    actor_id: str | None = None,
    severity: Literal["info", "warning", "error"] = "info",
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    store.append_activity(
        {
            "schema_version": "1.0",
            "message_type": "activity.event",
            "event_id": str(uuid4()),
            "event_type": event_type,
            "actor_type": actor_type,
            "actor_id": actor_id,
            "severity": severity,
            "message": message,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "details": details or {},
            "occurred_at": isoformat(utc_now()),
        }
    )
