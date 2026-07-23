"""Discovery lifecycle and uploaded-device validation."""

from __future__ import annotations

import ipaddress
from uuid import uuid4

from telesec_api.activity import record_activity
from telesec_api.agents.service import AgentNotFound, AgentService
from telesec_api.commands.service import CommandService
from telesec_api.discoveries.models import DiscoveryResult
from telesec_api.settings import Settings
from telesec_api.storage import JsonStore
from telesec_api.time import isoformat, utc_now


class DiscoveryError(RuntimeError):
    pass


class DiscoveryNotFound(DiscoveryError):
    pass


class DiscoveryOwnershipError(DiscoveryError):
    pass


class InvalidDiscoveryResult(DiscoveryError):
    pass


class AgentOffline(DiscoveryError):
    pass


class ScannerUnavailable(DiscoveryError):
    pass


class DiscoveryService:
    def __init__(
        self,
        store: JsonStore,
        settings: Settings,
        agents: AgentService,
        commands: CommandService,
    ):
        self.store = store
        self.settings = settings
        self.agents = agents
        self.commands = commands

    def create(self, *, agent_id: str) -> dict:
        try:
            agent = self.agents.get_public(agent_id)
        except AgentNotFound as exc:
            raise DiscoveryNotFound from exc
        if agent["status"] == "offline":
            raise AgentOffline
        if not agent.get("nmap_version"):
            raise ScannerUnavailable("Nmap is not installed on this agent")
        if agent.get("npcap_status") != "available":
            raise ScannerUnavailable("Npcap is not available on this agent")
        discovery_id = str(uuid4())
        command = self.commands.create(
            agent_id=agent_id,
            command_type="discover_network",
            payload={"discovery_id": discovery_id},
        )
        now = isoformat(utc_now())
        record = {
            "discovery_id": discovery_id,
            "command_id": command["command_id"],
            "agent_id": agent_id,
            "status": "queued",
            "network": None,
            "interface_name": None,
            "device_count": 0,
            "authorization_confirmed": True,
            "created_at": now,
            "started_at": None,
            "completed_at": None,
            "devices": [],
            "error": None,
        }
        self.store.write("discoveries", discovery_id, record)
        return record

    def save_result(self, authenticated_agent_id: str, result: DiscoveryResult) -> dict:
        discovery_id = str(result.discovery_id)
        with self.store.locked():
            record = self.store.read("discoveries", discovery_id)
            if record is None:
                raise DiscoveryNotFound
            if (
                record["agent_id"] != authenticated_agent_id
                or str(result.agent_id) != authenticated_agent_id
            ):
                raise DiscoveryOwnershipError
            try:
                network = ipaddress.ip_network(result.network, strict=True)
            except ValueError as exc:
                raise InvalidDiscoveryResult("Invalid discovery network") from exc
            if network.version != 4:
                raise InvalidDiscoveryResult("Only IPv4 discovery is supported")
            if not self.settings.allow_public_scopes and not network.is_private:
                raise InvalidDiscoveryResult("Public discovery networks are disabled")
            seen_ips: set[str] = set()
            for device in result.devices:
                try:
                    address = ipaddress.ip_address(device.ip)
                except ValueError as exc:
                    raise InvalidDiscoveryResult("Invalid discovered IP") from exc
                if address not in network:
                    raise InvalidDiscoveryResult(
                        f"Discovered IP {address} is outside {network}"
                    )
                if str(address) in seen_ips:
                    raise InvalidDiscoveryResult(f"Duplicate discovered IP {address}")
                seen_ips.add(str(address))
            record.update(
                {
                    "status": result.status,
                    "network": str(network),
                    "interface_name": result.interface_name,
                    "device_count": len(result.devices),
                    "started_at": isoformat(result.started_at),
                    "completed_at": (
                        isoformat(result.completed_at) if result.completed_at else None
                    ),
                    "devices": [
                        device.model_dump(mode="json") for device in result.devices
                    ],
                    "error": result.error,
                }
            )
            self.store.write("discoveries", discovery_id, record)
            record_activity(
                self.store,
                event_type=f"discovery.{result.status}",
                message=f"Discovery found {len(result.devices)} active devices",
                actor_type="agent",
                actor_id=authenticated_agent_id,
                resource_type="discovery",
                resource_id=discovery_id,
                details={"network": str(network), "device_count": len(result.devices)},
                severity="error" if result.status == "failed" else "info",
            )
            return record

    def get(self, discovery_id: str) -> dict:
        record = self.store.read("discoveries", discovery_id)
        if record is None:
            raise DiscoveryNotFound
        return record

    def list(self, agent_id: str | None = None) -> list[dict]:
        records = self.store.list("discoveries")
        if agent_id is not None:
            records = [item for item in records if item["agent_id"] == agent_id]
        records.sort(key=lambda item: item["created_at"], reverse=True)
        return records
