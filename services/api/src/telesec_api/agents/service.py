"""Agent identity, authentication, and health state."""

from __future__ import annotations

import hmac
from datetime import timedelta
from uuid import uuid4

from telesec_api.activity import record_activity
from telesec_api.agents.models import AgentHeartbeat
from telesec_api.enrollments.models import AgentEnrollRequest
from telesec_api.enrollments.service import EnrollmentService
from telesec_api.security import generate_agent_credential, hash_secret
from telesec_api.settings import Settings
from telesec_api.storage import JsonStore
from telesec_api.time import isoformat, parse_timestamp, utc_now


class AgentError(RuntimeError):
    pass


class AgentNotFound(AgentError):
    pass


class InvalidAgentCredential(AgentError):
    pass


class AgentIdentityMismatch(AgentError):
    pass


class AgentService:
    def __init__(
        self,
        store: JsonStore,
        settings: Settings,
        enrollments: EnrollmentService,
    ):
        self.store = store
        self.settings = settings
        self.enrollments = enrollments

    def enroll(self, payload: AgentEnrollRequest) -> tuple[dict, str]:
        with self.store.locked():
            token_hash, enrollment = self.enrollments.get_pending(
                payload.enrollment_token
            )
            agent_id = str(uuid4())
            credential = generate_agent_credential()
            credential_hash = hash_secret(credential)
            now = utc_now()
            record = {
                "agent_id": agent_id,
                "credential_hash": credential_hash,
                "label": enrollment["label"],
                "site_name": enrollment["site_name"],
                "hostname": payload.hostname,
                "agent_version": payload.agent_version,
                "os_name": payload.os_name,
                "architecture": payload.architecture,
                "status": "offline",
                "local_ip": None,
                "subnet": None,
                "nmap_version": None,
                "npcap_status": "unknown",
                "discovery_ready": None,
                "discovery_network": None,
                "discovery_interface": None,
                "discovery_error": None,
                "discovery_capability": None,
                "discovery_scope_options": [],
                "discovery_recommended_scope": None,
                "discovery_requires_authorization": False,
                "discovery_all_segments_available": False,
                "current_command_id": None,
                "enrolled_at": isoformat(now),
                "last_heartbeat_at": None,
            }
            self.store.write("agents", agent_id, record)
            self.store.write(
                "agent-credentials",
                credential_hash,
                {"agent_id": agent_id, "credential_hash": credential_hash},
            )
            self.enrollments.mark_consumed(token_hash, enrollment, agent_id)
            record_activity(
                self.store,
                event_type="agent.enrolled",
                message=f"Agent {payload.hostname} enrolled",
                actor_type="agent",
                actor_id=agent_id,
                resource_type="agent",
                resource_id=agent_id,
            )
            return record, credential

    def authenticate(self, credential: str) -> dict:
        supplied_hash = hash_secret(credential)
        index = self.store.read("agent-credentials", supplied_hash)
        if index is None or not hmac.compare_digest(
            supplied_hash, index.get("credential_hash", "")
        ):
            raise InvalidAgentCredential
        agent = self.store.read("agents", index["agent_id"])
        if agent is None or not hmac.compare_digest(
            supplied_hash, agent.get("credential_hash", "")
        ):
            raise InvalidAgentCredential
        return agent

    def heartbeat(self, authenticated: dict, payload: AgentHeartbeat) -> dict:
        if authenticated["agent_id"] != str(payload.agent_id):
            raise AgentIdentityMismatch
        previous_status = self.effective_status(authenticated)
        authenticated.update(
            {
                "hostname": payload.hostname,
                "agent_version": payload.agent_version,
                "os_name": payload.os_name,
                "status": payload.service_status,
                "local_ip": payload.local_ip,
                "subnet": payload.subnet,
                "nmap_version": payload.nmap_version,
                "npcap_status": payload.npcap_status,
                "discovery_ready": payload.discovery_ready,
                "discovery_network": payload.discovery_network,
                "discovery_interface": payload.discovery_interface,
                "discovery_error": payload.discovery_error,
                "discovery_capability": payload.discovery_capability,
                "discovery_scope_options": payload.discovery_scope_options,
                "discovery_recommended_scope": payload.discovery_recommended_scope,
                "discovery_requires_authorization": (
                    payload.discovery_requires_authorization
                ),
                "discovery_all_segments_available": (
                    payload.discovery_all_segments_available
                ),
                "current_command_id": (
                    str(payload.current_command_id)
                    if payload.current_command_id
                    else None
                ),
                "last_heartbeat_at": isoformat(utc_now()),
            }
        )
        self.store.write("agents", authenticated["agent_id"], authenticated)
        if previous_status != payload.service_status:
            record_activity(
                self.store,
                event_type="agent.status_changed",
                message=f"Agent status changed to {payload.service_status}",
                actor_type="agent",
                actor_id=authenticated["agent_id"],
                resource_type="agent",
                resource_id=authenticated["agent_id"],
                details={
                    "previous_status": previous_status,
                    "status": payload.service_status,
                },
            )
        return authenticated

    def effective_status(self, record: dict) -> str:
        last_heartbeat = record.get("last_heartbeat_at")
        if not last_heartbeat:
            return "offline"
        offline_at = parse_timestamp(last_heartbeat) + timedelta(
            seconds=self.settings.agent_offline_after_seconds
        )
        return "offline" if utc_now() >= offline_at else record["status"]

    def public(self, record: dict) -> dict:
        return {
            key: value for key, value in record.items() if key != "credential_hash"
        } | {"status": self.effective_status(record)}

    def list_public(self) -> list[dict]:
        records = self.store.list("agents")
        records.sort(key=lambda item: item["enrolled_at"], reverse=True)
        return [self.public(record) for record in records]

    def get_public(self, agent_id: str) -> dict:
        record = self.store.read("agents", agent_id)
        if record is None:
            raise AgentNotFound
        return self.public(record)
