"""Execute one server-authorized discovery command."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

from telesec_agent.enrollment import AgentIdentity, timestamp
from telesec_agent.scanning.interfaces import InterfaceScope, select_scope
from telesec_agent.scanning.nmap_runner import NmapRunner
from telesec_agent.scanning.parser import parse_discovery_xml


class DiscoveryProtocolClient(Protocol):
    def command_event(
        self,
        command_id: str,
        payload: dict[str, Any],
        *,
        credential: str,
    ) -> dict[str, Any]: ...

    def upload_discovery(
        self,
        discovery_id: str,
        payload: dict[str, Any],
        *,
        credential: str,
    ) -> dict[str, Any]: ...


class DiscoveryCommandHandler:
    def __init__(
        self,
        nmap: NmapRunner,
        scope_selector: Callable[[], InterfaceScope] = select_scope,
    ):
        self.nmap = nmap
        self.scope_selector = scope_selector

    def handle(
        self,
        command: dict[str, Any],
        identity: AgentIdentity,
        client: DiscoveryProtocolClient,
    ) -> None:
        command_id = str(command["command_id"])
        discovery_id = str(command["payload"]["discovery_id"])
        self._event(
            client,
            identity,
            command_id,
            status="running",
            message="Discovering the authorized local network",
        )
        scope: InterfaceScope | None = None
        try:
            scope = self.scope_selector()
            started_at = timestamp()
            xml_output = self.nmap.discover(scope.network)
            completed_at = timestamp()
            devices = parse_discovery_xml(
                xml_output,
                local_ip=scope.local_ip,
                observed_at=completed_at,
            )
            client.upload_discovery(
                discovery_id,
                {
                    "schema_version": "1.0",
                    "message_type": "discovery.result",
                    "discovery_id": discovery_id,
                    "agent_id": identity.agent_id,
                    "network": scope.network,
                    "interface_name": scope.interface_name,
                    "status": "completed",
                    "started_at": started_at,
                    "completed_at": completed_at,
                    "devices": devices,
                    "error": None,
                },
                credential=identity.credential,
            )
            self._event(
                client,
                identity,
                command_id,
                status="completed",
                message=f"Discovery completed with {len(devices)} active devices",
                details={"device_count": len(devices), "network": scope.network},
            )
        except Exception as exc:
            self._event(
                client,
                identity,
                command_id,
                status="failed",
                message=str(exc)[:1024] or "Discovery failed",
                details={"network": scope.network if scope else None},
            )
            raise

    @staticmethod
    def _event(
        client: DiscoveryProtocolClient,
        identity: AgentIdentity,
        command_id: str,
        *,
        status: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        client.command_event(
            command_id,
            {
                "schema_version": "1.0",
                "message_type": "command.event",
                "status": status,
                "message": message,
                "details": details or {},
                "occurred_at": timestamp(),
            },
            credential=identity.credential,
        )
