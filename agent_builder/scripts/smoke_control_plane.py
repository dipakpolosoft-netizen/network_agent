"""Run a real API-to-agent enrollment and heartbeat smoke test."""

from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.request import Request, urlopen

import uvicorn
from forgesec_api.main import create_app
from forgesec_api.settings import Settings

from forgesec_agent.api_client import ForgeSecApiClient
from forgesec_agent.config import AgentPaths
from forgesec_agent.enrollment import EnrollmentManager, IdentityStore
from forgesec_agent.heartbeat import HeartbeatSender
from forgesec_agent.job_scheduler import ScanScheduler
from forgesec_agent.scanning.discovery import DiscoveryCommandHandler
from forgesec_agent.scanning.interfaces import InterfaceScope, ResolvedDiscoveryPlan
from forgesec_agent.scanning.nmap_runner import DiscoveryProgress
from forgesec_agent.scanning.scan import ScanCommandHandler
from forgesec_agent.security.dpapi import DpapiProtector
from forgesec_agent.storage import AgentStorage

DISCOVERY_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up" reason="arp-response" />
    <address addr="192.168.1.1" addrtype="ipv4" />
    <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Router Vendor" />
  </host>
  <host>
    <status state="up" reason="localhost-response" />
    <address addr="192.168.1.25" addrtype="ipv4" />
  </host>
</nmaprun>
"""


class FixtureNmap:
    def discover(
        self,
        network: str,
        *,
        cancel_requested,
        progress_callback,
    ) -> str:
        assert network == "192.168.1.0/24"
        assert cancel_requested() is False
        progress_callback(DiscoveryProgress(1, 100.0, 2))
        return DISCOVERY_XML


HOST_SCAN_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up" reason="user-set" />
    <hostnames><hostname name="gateway.local" type="PTR" /></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" />
        <service name="ssh" product="OpenSSH" version="9.0" />
      </port>
    </ports>
    <os><osmatch name="Linux 6.x" accuracy="95" /></os>
  </host>
</nmaprun>
"""


class FixtureHostScanner:
    def scan_host(self, ip, profile, *, cancel_requested):
        assert ip == "192.168.1.1"
        assert profile == "standard"
        assert cancel_requested() is False
        return HOST_SCAN_XML


def available_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def request_json(url: str, payload: dict | None = None) -> dict | list:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"} if body else {},
        method="POST" if body else "GET",
    )
    with urlopen(request, timeout=5) as response:
        return json.loads(response.read())


def main() -> int:
    with TemporaryDirectory(prefix="forgesec-smoke-") as temporary:
        root = Path(temporary)
        settings = Settings(
            environment="test",
            api_host="127.0.0.1",
            api_port=0,
            runtime_data_dir=root / "api",
            web_origin="http://localhost:3000",
            enrollment_ttl_seconds=900,
            heartbeat_interval_seconds=30,
            agent_offline_after_seconds=90,
            command_ttl_seconds=900,
            max_scan_targets=4096,
            scan_concurrency=3,
            allow_public_scopes=False,
        )
        port = available_port()
        server = uvicorn.Server(
            uvicorn.Config(
                create_app(settings),
                host="127.0.0.1",
                port=port,
                log_level="warning",
            )
        )
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        try:
            for _attempt in range(50):
                if server.started:
                    break
                time.sleep(0.1)
            if not server.started:
                raise RuntimeError("ForgeSec API did not start")

            server_url = f"http://127.0.0.1:{port}"
            enrollment = request_json(
                f"{server_url}/api/enrollments",
                {"label": "Integration Agent", "site_name": "Test Site"},
            )
            assert isinstance(enrollment, dict)
            sites = request_json(f"{server_url}/api/sites")
            assert isinstance(sites, list) and len(sites) == 1
            approved_scope = request_json(
                f"{server_url}/api/sites/{sites[0]['site_id']}/scopes",
                {"cidr": "192.168.1.0/24", "label": "Smoke test LAN"},
            )
            assert isinstance(approved_scope, dict)

            paths = AgentPaths(root / "agent")
            storage = AgentStorage(paths)
            storage.initialize()
            storage.write_json(
                paths.bootstrap,
                {
                    "server_url": server_url,
                    "enrollment_token": enrollment["enrollment_token"],
                },
            )
            identities = IdentityStore(storage, paths, DpapiProtector())
            identity = EnrollmentManager(storage, paths, identities).ensure_enrolled()
            with patch(
                "forgesec_agent.heartbeat.discovery_scope",
                return_value={
                    "ready": True,
                    "network": "192.168.1.0/24",
                    "local_ip": "192.168.1.25",
                    "interface": "Ethernet",
                    "error": None,
                    "capability": "ready",
                    "scope_options": ["192.168.1.0/24"],
                    "recommended_scope": "192.168.1.0/24",
                    "requires_authorization": False,
                    "all_segments_available": False,
                },
            ):
                HeartbeatSender(storage, paths.state).send(identity)

            discovery = request_json(
                f"{server_url}/api/agents/{identity.agent_id}/discover",
                {"authorization_confirmed": True},
            )
            assert isinstance(discovery, dict)
            agent_client = ForgeSecApiClient(server_url)
            command = agent_client.next_command(credential=identity.credential)
            assert command is not None
            scope = InterfaceScope(
                interface_name="Ethernet",
                local_ip="192.168.1.25",
                network="192.168.1.0/24",
                is_virtual=False,
            )
            DiscoveryCommandHandler(
                FixtureNmap(),
                lambda: scope,
                lambda *_args, **_kwargs: ResolvedDiscoveryPlan(
                    scope, ("192.168.1.0/24",)
                ),
            ).handle(
                command,
                identity,
                agent_client,
            )

            discovery_result = request_json(
                f"{server_url}/api/discoveries/{discovery['discovery_id']}"
            )
            assert isinstance(discovery_result, dict)
            selected_device = next(
                device
                for device in discovery_result["devices"]
                if not device["is_agent"]
            )
            scan = request_json(
                f"{server_url}/api/discoveries/{discovery['discovery_id']}/scan",
                {
                    "device_ids": [selected_device["device_id"]],
                    "profile": "standard",
                    "authorization_confirmed": True,
                },
            )
            assert isinstance(scan, dict)
            scan_command = agent_client.next_command(credential=identity.credential)
            assert scan_command is not None
            scheduler = ScanScheduler(
                FixtureHostScanner(),
                storage,
                paths.root / "scans",
            )
            ScanCommandHandler(
                scheduler,
                HeartbeatSender(storage, paths.state),
            ).handle(scan_command, identity, agent_client)
            HeartbeatSender(storage, paths.state).send(identity)

            agents = request_json(f"{server_url}/api/agents")
            assert isinstance(agents, list) and len(agents) == 1
            assert agents[0]["agent_id"] == identity.agent_id
            assert agents[0]["status"] == "online"
            result = request_json(f"{server_url}/api/scans/{scan['scan_id']}")
            assert isinstance(result, dict)
            assert result["status"] == "completed"
            assert result["completed"] == 1
            assert len(result["results"]) == 1
            assert result["summary"]["open_ports"] == 1
            assert result["change_summary"]["baseline_scan_id"] is None
            assert 0 <= result["action_summary"]["risk_score"] <= 100
            assert result["action_summary"]["priority_actions"]
            print(
                f"Integrated agent {identity.agent_id}: online, "
                f"{discovery_result['device_count']} devices discovered, "
                f"{result['completed']} selected device scanned"
            )
            return 0
        finally:
            server.should_exit = True
            thread.join(timeout=10)


if __name__ == "__main__":
    raise SystemExit(main())
