"""Agent health collection and authenticated heartbeat delivery."""

from __future__ import annotations

import ipaddress
import platform
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import psutil

from telesec_agent import __version__
from telesec_agent.api_client import TelesecApiClient
from telesec_agent.config import dashboard_url_for_server
from telesec_agent.enrollment import AgentIdentity, timestamp
from telesec_agent.scanning.nmap_runner import find_nmap_executable
from telesec_agent.storage import AgentStorage

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class HeartbeatClient(Protocol):
    def heartbeat(self, payload: dict, *, credential: str) -> dict: ...


@dataclass(frozen=True, slots=True)
class NetworkSnapshot:
    local_ip: str | None
    subnet: str | None


def active_network() -> NetworkSnapshot:
    stats = psutil.net_if_stats()
    for name, addresses in psutil.net_if_addrs().items():
        if not stats.get(name) or not stats[name].isup:
            continue
        for address in addresses:
            if address.family != socket.AF_INET or not address.netmask:
                continue
            ip = ipaddress.ip_address(address.address)
            if ip.is_loopback or ip.is_link_local:
                continue
            network = ipaddress.ip_network(
                f"{address.address}/{address.netmask}", strict=False
            )
            return NetworkSnapshot(str(ip), str(network))
    return NetworkSnapshot(None, None)


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
        client: HeartbeatClient | None = None,
    ) -> dict:
        network = active_network()
        detected_nmap = nmap_version()
        detected_npcap = npcap_status()
        payload = {
            "schema_version": "1.0",
            "message_type": "agent.heartbeat",
            "agent_id": identity.agent_id,
            "agent_version": __version__,
            "hostname": socket.gethostname(),
            "os_name": f"{platform.system()} {platform.release()}",
            "local_ip": network.local_ip,
            "subnet": network.subnet,
            "nmap_version": detected_nmap,
            "npcap_status": detected_npcap,
            "service_status": service_status,
            "current_command_id": current_command_id,
            "sent_at": timestamp(),
        }
        resolved_client = client or TelesecApiClient(identity.server_url)
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
                    "current_command_id": current_command_id,
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
