"""Run a real API-to-agent enrollment and heartbeat smoke test."""

from __future__ import annotations

import json
import socket
import threading
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.request import Request, urlopen

import uvicorn
from telesec_api.main import create_app
from telesec_api.settings import Settings

from telesec_agent.api_client import TelesecApiClient
from telesec_agent.config import AgentPaths
from telesec_agent.enrollment import EnrollmentManager, IdentityStore
from telesec_agent.heartbeat import HeartbeatSender
from telesec_agent.job_scheduler import ScanScheduler
from telesec_agent.scanning.discovery import DiscoveryCommandHandler
from telesec_agent.scanning.interfaces import InterfaceScope
from telesec_agent.scanning.scan import ScanCommandHandler
from telesec_agent.security.dpapi import DpapiProtector
from telesec_agent.storage import AgentStorage

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
    def discover(self, network: str) -> str:
        assert network == "192.168.1.0/24"
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
    with TemporaryDirectory(prefix="telesec-smoke-") as temporary:
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
            max_scan_targets=10,
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
                raise RuntimeError("Telesec API did not start")

            server_url = f"http://127.0.0.1:{port}"
            enrollment = request_json(
                f"{server_url}/api/enrollments",
                {"label": "Integration Agent", "site_name": "Test Site"},
            )
            assert isinstance(enrollment, dict)

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
            HeartbeatSender(storage, paths.state).send(identity)

            discovery = request_json(
                f"{server_url}/api/agents/{identity.agent_id}/discover",
                {"authorization_confirmed": True},
            )
            assert isinstance(discovery, dict)
            agent_client = TelesecApiClient(server_url)
            command = agent_client.next_command(credential=identity.credential)
            assert command is not None
            scope = InterfaceScope(
                interface_name="Ethernet",
                local_ip="192.168.1.25",
                network="192.168.1.0/24",
                is_virtual=False,
            )
            DiscoveryCommandHandler(FixtureNmap(), lambda: scope).handle(
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
