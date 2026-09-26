"""Agent health collection and authenticated heartbeat delivery."""

from __future__ import annotations

import platform
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from forgesec_agent import __version__
from forgesec_agent.api_client import ForgeSecApiClient
from forgesec_agent.config import dashboard_url_for_server
from forgesec_agent.enrollment import AgentIdentity, timestamp
from forgesec_agent.scanning.interfaces import (
    ScopeError,
    discovery_capability,
    select_connected_scope,
)
from forgesec_agent.scanning.nmap_runner import find_nmap_executable
from forgesec_agent.storage import AgentStorage

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class HeartbeatClient(Protocol):
    def heartbeat(self, payload: dict, *, credential: str) -> dict: ...


@dataclass(frozen=True, slots=True)
class NetworkSnapshot:
    local_ip: str | None
    subnet: str | None


def active_network() -> NetworkSnapshot:
    try:
        scope = select_connected_scope()
    except ScopeError:
        return NetworkSnapshot(None, None)
    return NetworkSnapshot(scope.local_ip, scope.network)


def nmap_version() -> str | None:
    executable = find_nmap_executable()
    if not executable:
        return None
    try:
        result = subprocess.run(
            [executable, "--version"],
            capture_output=True,
            check=False,
            creationflags=NO_WINDOW,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    first_line = result.stdout.splitlines()[0] if result.stdout else ""
    marker = "version "
    return first_line.split(marker, 1)[1].split()[0] if marker in first_line else None


def npcap_status() -> str:
    try:
        result = subprocess.run(
            ["sc.exe", "query", "npcap"],
            capture_output=True,
            check=False,
            creationflags=NO_WINDOW,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    if result.returncode != 0:
        return "missing"
    return "available" if "RUNNING" in result.stdout else "degraded"


def discovery_scope() -> dict:
    try:
        capability = discovery_capability()
    except ScopeError as exc:
        return {
            "ready": False,
            "network": None,
            "local_ip": None,
            "interface": None,
            "error": str(exc),
            "capability": "unsupported",
            "scope_options": [],
            "recommended_scope": None,
            "requires_authorization": False,
            "all_segments_available": False,
        }
    scope = capability.connected_scope
    warning = (
        f"{scope.network} uses public-range addressing and requires authorization"
        if capability.requires_authorization
        else None
    )
    return {
        "ready": True,
        "network": scope.network,
        "local_ip": scope.local_ip,
        "interface": scope.interface_name,
        "error": warning,
        "capability": capability.capability,
        "scope_options": list(capability.scope_options),
        "recommended_scope": capability.recommended_scope,
        "requires_authorization": capability.requires_authorization,
        "all_segments_available": capability.all_segments_available,
    }


class HeartbeatSender:
    def __init__(
        self,
        storage: AgentStorage,
        state_path: Path,
        public_state_path: Path | None = None,
    ):
        self.storage = storage
        self.state_path = state_path
        self.public_state_path = public_state_path

    def send(
        self,
        identity: AgentIdentity,
        *,
        service_status: str = "online",
        current_command_id: str | None = None,
        activity: str | None = None,
        client: HeartbeatClient | None = None,
    ) -> dict:
        network = active_network()
        detected_nmap = nmap_version()
        detected_npcap = npcap_status()
        scope = discovery_scope()
        payload = {
            "schema_version": "1.0",
            "message_type": "agent.heartbeat",
            "agent_id": identity.agent_id,
            "agent_version": __version__,
            "hostname": socket.gethostname(),
            "os_name": f"{platform.system()} {platform.release()}",
            "local_ip": scope["local_ip"] or network.local_ip,
            "subnet": scope["network"] or network.subnet,
            "nmap_version": detected_nmap,
            "npcap_status": detected_npcap,
            "discovery_ready": scope["ready"],
            "discovery_network": scope["network"],
            "discovery_interface": scope["interface"],
            "discovery_error": scope["error"],
            "discovery_capability": scope["capability"],
            "discovery_scope_options": scope["scope_options"],
            "discovery_recommended_scope": scope["recommended_scope"],
            "discovery_requires_authorization": scope["requires_authorization"],
            "discovery_all_segments_available": scope["all_segments_available"],
            "service_status": service_status,
            "current_command_id": current_command_id,
            "sent_at": timestamp(),
        }
        resolved_client = client or ForgeSecApiClient(identity.server_url)
        response = resolved_client.heartbeat(
            payload,
            credential=identity.credential,
        )
        self.storage.write_json(
            self.state_path,
            {
                "agent_id": identity.agent_id,
                "status": service_status,
                "last_heartbeat_at": payload["sent_at"],
                "server_status": response.get("status", "accepted"),
                "current_command_id": current_command_id,
            },
        )
        if self.public_state_path is not None:
            self.storage.write_json(
                self.public_state_path,
                {
                    "status": service_status,
                    "last_heartbeat_at": payload["sent_at"],
                    "heartbeat_interval_seconds": identity.heartbeat_interval_seconds,
                    "dashboard_url": dashboard_url_for_server(identity.server_url),
                    "nmap_version": detected_nmap,
                    "npcap_status": detected_npcap,
                    "discovery_ready": scope["ready"],
                    "discovery_network": scope["network"],
                    "discovery_interface": scope["interface"],
                    "discovery_error": scope["error"],
                    "discovery_capability": scope["capability"],
                    "discovery_scope_options": scope["scope_options"],
                    "discovery_recommended_scope": scope["recommended_scope"],
                    "discovery_requires_authorization": scope["requires_authorization"],
                    "discovery_all_segments_available": scope["all_segments_available"],
                    "current_command_id": current_command_id,
                    "activity": activity,
                },
            )
        return response

    def record_error(
        self,
        error: str,
        *,
        current_command_id: str | None = None,
    ) -> None:
        occurred_at = timestamp()
        message = error[:500]
        self.storage.write_json(
            self.state_path,
            {
                "status": "degraded",
                "last_heartbeat_at": occurred_at,
                "server_status": "error",
                "current_command_id": current_command_id,
                "error": message,
            },
        )
        if self.public_state_path is not None:
            self.storage.write_json(
                self.public_state_path,
                {
                    "status": "degraded",
                    "last_heartbeat_at": occurred_at,
                    "heartbeat_interval_seconds": 30,
                    "nmap_version": nmap_version(),
                    "npcap_status": npcap_status(),
                    "current_command_id": current_command_id,
                    "error": message,
                },
            )
