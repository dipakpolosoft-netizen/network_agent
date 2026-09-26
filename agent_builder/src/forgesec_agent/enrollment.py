"""Initial agent enrollment and protected identity persistence."""

from __future__ import annotations

import base64
import platform
import secrets
import socket
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Protocol

from forgesec_agent import __version__
from forgesec_agent.api_client import ApiClientError, ForgeSecApiClient
from forgesec_agent.config import AgentPaths, BootstrapConfig, validate_server_url
from forgesec_agent.security.dpapi import SecretProtector
from forgesec_agent.storage import AgentStorage


def timestamp() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def architecture() -> str:
    machine = platform.machine().lower()
    return "arm64" if machine in {"arm64", "aarch64"} else "x86_64"


@dataclass(frozen=True, slots=True)
class AgentIdentity:
    agent_id: str
    server_url: str
    credential: str
    heartbeat_interval_seconds: int
    enrolled_at: str
    credential_rotated_at: str | None = None
    pending_credential: str | None = None


class EnrollmentClient(Protocol):
    def enroll(self, payload: dict) -> dict: ...


class IdentityStore:
    def __init__(
        self,
        storage: AgentStorage,
        paths: AgentPaths,
        protector: SecretProtector,
    ):
        self.storage = storage
        self.paths = paths
        self.protector = protector

    def exists(self) -> bool:
        return self.paths.identity.is_file()

    def save(self, identity: AgentIdentity) -> None:
        protected = self.protector.protect(identity.credential.encode("utf-8"))
        pending = (
            self.protector.protect(identity.pending_credential.encode("utf-8"))
            if identity.pending_credential
            else None
        )
        self.storage.write_json(
            self.paths.identity,
            {
                "schema_version": "1.0",
                "agent_id": identity.agent_id,
                "server_url": validate_server_url(identity.server_url),
                "protected_credential": base64.b64encode(protected).decode("ascii"),
                "heartbeat_interval_seconds": identity.heartbeat_interval_seconds,
                "enrolled_at": identity.enrolled_at,
                "credential_rotated_at": identity.credential_rotated_at,
                "protected_pending_credential": (
                    base64.b64encode(pending).decode("ascii") if pending else None
                ),
            },
        )

    def load(self) -> AgentIdentity | None:
        document = self.storage.read_json(self.paths.identity)
        if document is None:
            return None
        protected = base64.b64decode(document["protected_credential"], validate=True)
        credential = self.protector.unprotect(protected).decode("utf-8")
        pending_document = document.get("protected_pending_credential")
        pending = (
            self.protector.unprotect(
                base64.b64decode(pending_document, validate=True)
            ).decode("utf-8")
            if pending_document
            else None
        )
        return AgentIdentity(
            agent_id=document["agent_id"],
            server_url=validate_server_url(document["server_url"]),
            credential=credential,
            heartbeat_interval_seconds=int(document["heartbeat_interval_seconds"]),
            enrolled_at=document["enrolled_at"],
            credential_rotated_at=document.get("credential_rotated_at"),
            pending_credential=pending,
        )


class EnrollmentManager:
    def __init__(
        self,
        storage: AgentStorage,
        paths: AgentPaths,
        identities: IdentityStore,
    ):
        self.storage = storage
        self.paths = paths
        self.identities = identities

    def ensure_enrolled(self) -> AgentIdentity:
        existing = self.identities.load()
        if existing is not None:
            return existing
        bootstrap = BootstrapConfig.load(self.paths.bootstrap)
        client = ForgeSecApiClient(bootstrap.server_url)
        return self.enroll(bootstrap, client)

    def rotate_if_due(
        self, identity: AgentIdentity, client: ForgeSecApiClient
    ) -> AgentIdentity:
        last_rotation = datetime.fromisoformat(
            identity.credential_rotated_at or identity.enrolled_at
        )
        if last_rotation.tzinfo is None:
            last_rotation = last_rotation.replace(tzinfo=UTC)
        if (
            identity.pending_credential is None
            and datetime.now(UTC) - last_rotation < timedelta(days=30)
        ):
            return identity
        if identity.pending_credential is None:
            candidate = f"forgesec_agent_{secrets.token_urlsafe(48)}"
            identity = replace(identity, pending_credential=candidate)
            self.identities.save(identity)
        try:
            client.rotate_credential(
                identity.agent_id,
                credential=identity.credential,
                new_credential=identity.pending_credential,
            )
        except ApiClientError as exc:
            if exc.status_code != 401:
                raise
            status = client.credential_status(credential=identity.pending_credential)
            if status.get("agent_id") != identity.agent_id:
                raise ApiClientError(
                    "Rotated credential belongs to another agent"
                ) from exc
        updated = replace(
            identity,
            credential=identity.pending_credential,
            pending_credential=None,
            credential_rotated_at=timestamp(),
        )
        self.identities.save(updated)
        return updated

    def enroll(
        self,
        bootstrap: BootstrapConfig,
        client: EnrollmentClient,
    ) -> AgentIdentity:
        response = client.enroll(
            {
                "schema_version": "1.0",
                "message_type": "agent.enroll.request",
                "enrollment_token": bootstrap.enrollment_token,
                "agent_version": __version__,
                "hostname": socket.gethostname(),
                "os_name": f"{platform.system()} {platform.release()}",
                "architecture": architecture(),
                "requested_at": timestamp(),
            }
        )
        identity = AgentIdentity(
            agent_id=str(response["agent_id"]),
            server_url=bootstrap.server_url,
            credential=str(response["agent_credential"]),
            heartbeat_interval_seconds=int(response["heartbeat_interval_seconds"]),
            enrolled_at=str(response["issued_at"]),
            credential_rotated_at=str(response["issued_at"]),
        )
        self.identities.save(identity)
        self.storage.remove(self.paths.bootstrap)
        return identity
