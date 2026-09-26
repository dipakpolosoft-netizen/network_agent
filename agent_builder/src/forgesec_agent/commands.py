"""Dispatch claimed commands to their bounded handlers."""

from __future__ import annotations

from typing import Any

from forgesec_agent.api_client import ForgeSecApiClient
from forgesec_agent.command_diagnostics import DeviceDiagnosticHandler
from forgesec_agent.enrollment import AgentIdentity, timestamp
from forgesec_agent.scanning.discovery import DiscoveryCommandHandler
from forgesec_agent.scanning.scan import ScanCommandHandler


class CommandDispatcher:
    def __init__(
        self,
        discovery: DiscoveryCommandHandler,
        scan: ScanCommandHandler,
        diagnostics: DeviceDiagnosticHandler,
    ):
        self.discovery = discovery
        self.scan = scan
        self.diagnostics = diagnostics

    def handle(
        self,
        command: dict[str, Any],
        identity: AgentIdentity,
        client: ForgeSecApiClient,
    ) -> None:
        command_type = command["command_type"]
        if command_type == "discover_network":
            self.discovery.handle(command, identity, client)
            return
        if command_type == "scan_devices":
            self.scan.handle(command, identity, client)
            return
        if command_type == "device_diagnostic":
            self.diagnostics.handle(command, identity, client)
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
