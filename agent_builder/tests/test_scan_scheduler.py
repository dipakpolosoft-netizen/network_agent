from __future__ import annotations

import threading
import time
from pathlib import Path

from telesec_agent.config import AgentPaths
from telesec_agent.enrollment import AgentIdentity
from telesec_agent.job_scheduler import ScanScheduler
from telesec_agent.storage import AgentStorage

HOST_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up" reason="user-set" />
    <hostnames><hostname name="server.local" type="PTR" /></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" />
        <service name="ssh" product="OpenSSH" version="9.0">
          <cpe>cpe:/a:openbsd:openssh:9.0</cpe>
        </service>
      </port>
    </ports>
    <os><osmatch name="Linux 6.x" accuracy="95" /></os>
  </host>
</nmaprun>
"""


class ConcurrencyScanner:
    def __init__(self):
        self.lock = threading.Lock()
        self.active = 0
        self.maximum = 0

    def scan_host(self, ip, profile, *, cancel_requested):
        assert profile == "standard"
        assert cancel_requested() is False
        with self.lock:
            self.active += 1
            self.maximum = max(self.maximum, self.active)
        time.sleep(0.03)
        with self.lock:
            self.active -= 1
        return HOST_XML


class FakeScanClient:
    def __init__(self):
        self.progress = []
        self.results = []

    def heartbeat(self, payload, *, credential):
        return {"status": "accepted"}

    def command_event(self, command_id, payload, *, credential):
        return {"status": "accepted"}

    def upload_scan_progress(self, scan_id, payload, *, credential):
        self.progress.append(payload)
        return {"status": payload["status"]}

    def upload_host_result(self, scan_id, device_id, payload, *, credential):
        self.results.append(payload)
        return {"status": "accepted"}

    def scan_control(self, scan_id, *, credential):
        return {"scan_id": scan_id, "cancel_requested": False}


def test_scheduler_never_exceeds_three_workers(tmp_path: Path) -> None:
    paths = AgentPaths(tmp_path)
    storage = AgentStorage(paths)
    storage.initialize()
    scanner = ConcurrencyScanner()
    client = FakeScanClient()
    scheduler = ScanScheduler(scanner, storage, paths.root / "scans")
    identity = AgentIdentity(
        agent_id="00000000-0000-0000-0000-000000000123",
        server_url="https://telesec.example.com",
        credential="tes_agent_secret",
        heartbeat_interval_seconds=30,
        enrolled_at="2026-07-23T10:00:00Z",
    )
    targets = [
        {"device_id": f"device-{number}", "ip": f"192.168.1.{number}"}
        for number in range(10, 15)
    ]

    result = scheduler.run(
        scan_id="00000000-0000-0000-0000-000000000456",
        profile="standard",
        targets=targets,
        concurrency=3,
        identity=identity,
        client=client,
        keepalive=lambda: None,
    )

    assert result == "completed"
    assert scanner.maximum == 3
    assert len(client.results) == 5
    assert client.progress[-1]["completed"] == 5
    assert client.progress[-1]["running"] == 0
    assert all(item["ports"][0]["port"] == 22 for item in client.results)
    raw_files = list((paths.root / "scans").rglob("*.xml"))
    assert len(raw_files) == 5
