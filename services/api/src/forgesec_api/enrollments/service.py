"""One-time enrollment token lifecycle."""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

from forgesec_api.activity import record_activity
from forgesec_api.security import generate_enrollment_token, hash_secret
from forgesec_api.settings import Settings
from forgesec_api.sites.service import SiteService
from forgesec_api.storage import JsonStore
from forgesec_api.time import isoformat, parse_timestamp, utc_now


class EnrollmentError(RuntimeError):
    pass


class EnrollmentNotFound(EnrollmentError):
    pass


class EnrollmentExpired(EnrollmentError):
    pass


class EnrollmentConsumed(EnrollmentError):
    pass


class EnrollmentService:
    def __init__(self, store: JsonStore, settings: Settings, sites: SiteService):
        self.store = store
        self.settings = settings
        self.sites = sites

    def create(
        self, *, label: str, site_name: str | None, site_id: str | None = None
    ) -> tuple[dict, str]:
        site = (
            self.sites.get(site_id)
            if site_id
            else self.sites.get_or_create(site_name or "Local Site")
        )
        token = generate_enrollment_token()
        token_hash = hash_secret(token)
        now = utc_now()
        record = {
            "enrollment_id": str(uuid4()),
            "token_hash": token_hash,
            "label": label,
            "site_id": site["site_id"],
            "site_name": site["name"],
            "status": "pending",
            "created_at": isoformat(now),
            "expires_at": isoformat(
                now + timedelta(seconds=self.settings.enrollment_ttl_seconds)
            ),
            "consumed_at": None,
            "agent_id": None,
        }
        self.store.write("enrollments", token_hash, record)
        record_activity(
            self.store,
            event_type="enrollment.created",
            message=f"Enrollment token created for {label}",
            actor_type="user",
            resource_type="enrollment",
            resource_id=record["enrollment_id"],
            details={"site_id": site["site_id"]},
        )
        return record, token

    def get_pending(self, token: str) -> tuple[str, dict]:
        token_hash = hash_secret(token)
        record = self.store.read("enrollments", token_hash)
        if record is None:
            raise EnrollmentNotFound
        if record["status"] == "consumed":
            raise EnrollmentConsumed
        if record["status"] == "expired":
            raise EnrollmentExpired
        if utc_now() >= parse_timestamp(record["expires_at"]):
            record["status"] = "expired"
            self.store.write("enrollments", token_hash, record)
            record_activity(
                self.store,
                event_type="enrollment.expired",
                message="Enrollment token expired",
                resource_type="enrollment",
                resource_id=record["enrollment_id"],
                details={"site_id": record["site_id"]},
                severity="warning",
            )
            raise EnrollmentExpired
        return token_hash, record

    def mark_consumed(self, token_hash: str, record: dict, agent_id: str) -> None:
        record.update(
            {
                "status": "consumed",
                "consumed_at": isoformat(utc_now()),
                "agent_id": agent_id,
            }
        )
        self.store.write("enrollments", token_hash, record)
