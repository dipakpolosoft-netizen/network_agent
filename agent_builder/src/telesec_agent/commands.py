"""Dispatch claimed commands to their bounded handlers."""

from __future__ import annotations

from typing import Any

from telesec_agent.api_client import TelesecApiClient
from telesec_agent.enrollment import AgentIdentity, timestamp
from telesec_agent.scanning.discovery import DiscoveryCommandHandler
from telesec_agent.scanning.scan import ScanCommandHandler


class CommandDispatcher:
    def __init__(
        self,
        discovery: DiscoveryCommandHandler,
        scan: ScanCommandHandler,
    ):
        self.discovery = discovery
        self.scan = scan

    def handle(
        self,
        command: dict[str, Any],
        identity: AgentIdentity,
        client: TelesecApiClient,
    ) -> None:
        command_type = command["command_type"]
        if command_type == "discover_network":
            self.discovery.handle(command, identity, client)
            return
        if command_type == "scan_devices":
            self.scan.handle(command, identity, client)
            return
        client.command_event(
            command["command_id"],
            {
                "schema_version": "1.0",
                "message_type": "command.event",
                "status": "failed",
                "message": "Unsupported agent command",
                "details": {"command_type": command_type},
                "occurred_at": timestamp(),
            },
            credential=identity.credential,
        )
