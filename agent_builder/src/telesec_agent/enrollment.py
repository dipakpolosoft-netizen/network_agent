"""Initial agent enrollment and protected identity persistence."""

from __future__ import annotations

import base64
import platform
import socket
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from telesec_agent import __version__
from telesec_agent.api_client import TelesecApiClient
from telesec_agent.config import AgentPaths, BootstrapConfig, validate_server_url
from telesec_agent.security.dpapi import SecretProtector
from telesec_agent.storage import AgentStorage


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
        self.storage.write_json(
            self.paths.identity,
            {
                "schema_version": "1.0",
                "agent_id": identity.agent_id,
                "server_url": validate_server_url(identity.server_url),
                "protected_credential": base64.b64encode(protected).decode("ascii"),
                "heartbeat_interval_seconds": identity.heartbeat_interval_seconds,
                "enrolled_at": identity.enrolled_at,
            },
        )

    def load(self) -> AgentIdentity | None:
        document = self.storage.read_json(self.paths.identity)
        if document is None:
            return None
        protected = base64.b64decode(document["protected_credential"], validate=True)
        credential = self.protector.unprotect(protected).decode("utf-8")
        return AgentIdentity(
            agent_id=document["agent_id"],
            server_url=validate_server_url(document["server_url"]),
            credential=credential,
            heartbeat_interval_seconds=int(document["heartbeat_interval_seconds"]),
            enrolled_at=document["enrolled_at"],
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
        client = TelesecApiClient(bootstrap.server_url)
        return self.enroll(bootstrap, client)

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
        )
        self.identities.save(identity)
        self.storage.remove(self.paths.bootstrap)
        return identity
