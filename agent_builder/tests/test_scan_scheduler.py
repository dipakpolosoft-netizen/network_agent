from __future__ import annotations

import hashlib
import threading
import time
from pathlib import Path

from forgesec_agent.config import AgentPaths
from forgesec_agent.enrollment import AgentIdentity
from forgesec_agent.job_scheduler import ScanScheduler
from forgesec_agent.scanning.nmap_runner import ScanCancelled, ScanTimedOut
from forgesec_agent.storage import AgentStorage

HOST_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up" reason="user-set" />
    <address addr="192.168.1.10" addrtype="ipv4" />
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
        return HOST_XML.replace("192.168.1.10", ip)


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
        server_url="https://forgesec.example.com",
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
        concurrency=5,
        identity=identity,
        client=client,
        keepalive=lambda: None,
    )

    assert result == "completed"
    assert 1 <= scanner.maximum <= 3
    assert all(progress["running"] <= 3 for progress in client.progress)
    assert len(client.results) == 5
    assert client.progress[-1]["completed"] == 5
    assert client.progress[-1]["running"] == 0
    assert all(item["ports"][0]["port"] == 22 for item in client.results)
    assert all(item["ports"][0]["evidence_source"] == "nmap" for item in client.results)
    assert all(
        item["ports"][0]["recorded_at"] == item["completed_at"]
        for item in client.results
    )
    raw_files = list((paths.root / "scans").rglob("*.xml"))
    assert len(raw_files) == 5
    for result in client.results:
        raw_path = (
            paths.root / "scans" / result["scan_id"] / "raw"
            / f"{result['device_id']}.xml"
        )
        assert result["raw_xml_sha256"] == hashlib.sha256(
            raw_path.read_bytes()
        ).hexdigest()
        assert result["hostname_source"] == "nmap"


def test_mismatched_nmap_host_fails_without_inventing_port_evidence(
    tmp_path: Path,
) -> None:
    class WrongHostScanner:
        def scan_host(self, ip, profile, *, cancel_requested):
            return HOST_XML

    paths = AgentPaths(tmp_path)
    storage = AgentStorage(paths)
    storage.initialize()
    client = FakeScanClient()
    scan_id = "00000000-0000-0000-0000-000000000456"
    identity = AgentIdentity(
        agent_id="00000000-0000-0000-0000-000000000123",
        server_url="https://forgesec.example.com",
        credential="tes_agent_secret",
        heartbeat_interval_seconds=30,
        enrolled_at="2026-07-23T10:00:00Z",
    )

    outcome = ScanScheduler(
        WrongHostScanner(), storage, paths.root / "scans"
    ).run(
        scan_id=scan_id,
        profile="standard",
        targets=[{"device_id": "device-1", "ip": "192.168.1.11"}],
        concurrency=1,
        identity=identity,
        client=client,
        keepalive=lambda: None,
    )

    result = client.results[0]
    raw_path = paths.root / "scans" / scan_id / "raw" / "device-1.xml"
    assert outcome == "failed"
    assert result["status"] == "failed"
    assert result["ports"] == []
    assert "differs from selected target" in result["error"]
    assert result["raw_xml_sha256"] == hashlib.sha256(raw_path.read_bytes()).hexdigest()


def test_scan_keeps_stronger_discovery_role_when_scan_has_no_role_evidence(
    tmp_path: Path,
) -> None:
    paths = AgentPaths(tmp_path)
    storage = AgentStorage(paths)
    storage.initialize()
    scheduler = ScanScheduler(ConcurrencyScanner(), storage, paths.root / "scans")
    client = FakeScanClient()
    identity = AgentIdentity(
        agent_id="00000000-0000-0000-0000-000000000123",
        server_url="https://forgesec.example.com",
        credential="tes_agent_secret",
        heartbeat_interval_seconds=30,
        enrolled_at="2026-07-23T10:00:00Z",
    )

    scheduler.run(
        scan_id="00000000-0000-0000-0000-000000000456",
        profile="standard",
        targets=[
            {
                "device_id": "device-1",
                "ip": "192.168.1.10",
                "device_type": "switch",
                "classification_confidence": 0.9,
            }
        ],
        concurrency=1,
        identity=identity,
        client=client,
        keepalive=lambda: None,
    )

    assert client.results[0]["device_type"] == "switch"
    assert client.results[0]["classification_confidence"] == 0.9


def test_equal_confidence_scan_role_does_not_replace_discovery_role(
    tmp_path: Path,
) -> None:
    class FirewallScanner(ConcurrencyScanner):
        def scan_host(self, ip, profile, *, cancel_requested):
            return (
                '<nmaprun><host><status state="up"/>'
                '<address addr="192.168.1.10" addrtype="ipv4"/>'
                '<ports><port protocol="tcp" portid="443">'
                '<state state="open"/><service name="https" product="FortiGate"/>'
                '</port></ports></host></nmaprun>'
            )

    paths = AgentPaths(tmp_path)
    storage = AgentStorage(paths)
    storage.initialize()
    scheduler = ScanScheduler(FirewallScanner(), storage, paths.root / "scans")
    client = FakeScanClient()
    identity = AgentIdentity(
        agent_id="00000000-0000-0000-0000-000000000123",
        server_url="https://forgesec.example.com",
        credential="tes_agent_secret",
        heartbeat_interval_seconds=30,
        enrolled_at="2026-07-23T10:00:00Z",
    )
    scheduler.run(
        scan_id="00000000-0000-0000-0000-000000000456",
        profile="standard",
        targets=[{
            "device_id": "device-1",
            "ip": "192.168.1.10",
            "device_type": "switch",
            "classification_confidence": 0.9,
        }],
        concurrency=1,
        identity=identity,
        client=client,
        keepalive=lambda: None,
    )
    assert client.results[0]["device_type"] == "switch"
    assert client.results[0]["classification_confidence"] == 0.9


def test_blocked_host_scan_keeps_heartbeat_and_progress_alive(tmp_path: Path) -> None:
    started = threading.Event()
    release = threading.Event()
    heartbeats: list[float] = []
    heartbeat_attempts = 0

    def keepalive() -> None:
        nonlocal heartbeat_attempts
        heartbeat_attempts += 1
        if heartbeat_attempts == 1:
            raise OSError("Temporary API connection failure")
        heartbeats.append(time.monotonic())

    class BlockingScanner:
        def scan_host(self, ip, profile, *, cancel_requested):
            started.set()
            assert release.wait(2)
            return HOST_XML

    paths = AgentPaths(tmp_path)
    storage = AgentStorage(paths)
    storage.initialize()
    client = FakeScanClient()
    scheduler = ScanScheduler(
        BlockingScanner(),
        storage,
        paths.root / "scans",
        keepalive_interval_seconds=0.02,
    )
    identity = AgentIdentity(
        agent_id="00000000-0000-0000-0000-000000000123",
        server_url="https://forgesec.example.com",
        credential="tes_agent_secret",
        heartbeat_interval_seconds=30,
        enrolled_at="2026-07-23T10:00:00Z",
    )
    outcomes = []
    runner = threading.Thread(
        target=lambda: outcomes.append(
            scheduler.run(
                scan_id="00000000-0000-0000-0000-000000000456",
                profile="standard",
                targets=[{"device_id": "device-1", "ip": "192.168.1.10"}],
                concurrency=1,
                identity=identity,
                client=client,
                keepalive=keepalive,
            )
        )
    )
    runner.start()
    try:
        assert started.wait(1)
        deadline = time.monotonic() + 1
        while len(heartbeats) < 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert len(heartbeats) >= 2
        assert client.progress[-1]["running"] == 1
        assert client.progress[-1]["running_device_ids"] == ["device-1"]
    finally:
        release.set()
        runner.join(2)
    assert not runner.is_alive()
    assert outcomes == ["completed"]
    assert client.progress[-1]["status"] == "completed"


def test_timeout_and_mixed_results_have_distinct_final_outcomes(tmp_path: Path) -> None:
    class TimeoutScanner:
        def scan_host(self, ip, profile, *, cancel_requested):
            if ip.endswith(".10"):
                return HOST_XML
            raise ScanTimedOut("Host scan timed out")

    paths = AgentPaths(tmp_path)
    storage = AgentStorage(paths)
    storage.initialize()
    identity = AgentIdentity(
        agent_id="00000000-0000-0000-0000-000000000123",
        server_url="https://forgesec.example.com",
        credential="tes_agent_secret",
        heartbeat_interval_seconds=30,
        enrolled_at="2026-07-23T10:00:00Z",
    )
    for targets, expected in [
        ([{"device_id": "device-2", "ip": "192.168.1.11"}], "failed"),
        (
            [
                {"device_id": "device-1", "ip": "192.168.1.10"},
                {"device_id": "device-2", "ip": "192.168.1.11"},
            ],
            "partial",
        ),
    ]:
        client = FakeScanClient()
        scheduler = ScanScheduler(TimeoutScanner(), storage, paths.root / "scans")
        outcome = scheduler.run(
            scan_id="00000000-0000-0000-0000-000000000456",
            profile="standard",
            targets=targets,
            concurrency=2,
            identity=identity,
            client=client,
            keepalive=lambda: None,
        )
        assert outcome == expected
        assert client.progress[-1]["status"] == expected
        assert any(result["status"] == "timed_out" for result in client.results)


def test_all_cancelled_targets_finish_cancelled(tmp_path: Path) -> None:
    class CancelledScanner:
        def scan_host(self, ip, profile, *, cancel_requested):
            raise ScanCancelled("Scan cancelled")

    paths = AgentPaths(tmp_path)
    storage = AgentStorage(paths)
    storage.initialize()
    client = FakeScanClient()
    scheduler = ScanScheduler(CancelledScanner(), storage, paths.root / "scans")
    identity = AgentIdentity(
        agent_id="00000000-0000-0000-0000-000000000123",
        server_url="https://forgesec.example.com",
        credential="tes_agent_secret",
        heartbeat_interval_seconds=30,
        enrolled_at="2026-07-23T10:00:00Z",
    )
    outcome = scheduler.run(
        scan_id="00000000-0000-0000-0000-000000000456",
        profile="standard",
        targets=[{"device_id": "device-1", "ip": "192.168.1.10"}],
        concurrency=1,
        identity=identity,
        client=client,
        keepalive=lambda: None,
    )
    assert outcome == "cancelled"
    assert client.results[0]["status"] == "cancelled"
    assert client.progress[-1]["cancelled"] == 1


def test_transient_progress_failure_does_not_replace_host_result(
    tmp_path: Path,
) -> None:
    class FlakyProgressClient(FakeScanClient):
        def __init__(self):
            super().__init__()
            self.attempts = 0

        def upload_scan_progress(self, scan_id, payload, *, credential):
            self.attempts += 1
            if self.attempts in {2, 3}:
                raise OSError("Temporary progress connection failure")
            return super().upload_scan_progress(scan_id, payload, credential=credential)

    paths = AgentPaths(tmp_path)
    storage = AgentStorage(paths)
    storage.initialize()
    client = FlakyProgressClient()
    identity = AgentIdentity(
        agent_id="00000000-0000-0000-0000-000000000123",
        server_url="https://forgesec.example.com",
        credential="tes_agent_secret",
        heartbeat_interval_seconds=30,
        enrolled_at="2026-07-23T10:00:00Z",
    )
    outcome = ScanScheduler(
        ConcurrencyScanner(), storage, paths.root / "scans"
    ).run(
        scan_id="00000000-0000-0000-0000-000000000456",
        profile="standard",
        targets=[{"device_id": "device-1", "ip": "192.168.1.10"}],
        concurrency=1,
        identity=identity,
        client=client,
        keepalive=lambda: None,
    )

    assert outcome == "completed"
    assert len(client.results) == 1
    assert client.results[0]["status"] == "completed"
    assert client.progress[-1]["status"] == "completed"


def test_ambiguous_result_delivery_retries_same_evidence(tmp_path: Path) -> None:
    class LostResponseClient(FakeScanClient):
        def __init__(self):
            super().__init__()
            self.attempts = 0

        def upload_host_result(self, scan_id, device_id, payload, *, credential):
            self.attempts += 1
            response = super().upload_host_result(
                scan_id, device_id, payload, credential=credential
            )
            if self.attempts == 1:
                raise OSError("Response lost after acceptance")
            return response

    paths = AgentPaths(tmp_path)
    storage = AgentStorage(paths)
    storage.initialize()
    client = LostResponseClient()
    identity = AgentIdentity(
        agent_id="00000000-0000-0000-0000-000000000123",
        server_url="https://forgesec.example.com",
        credential="tes_agent_secret",
        heartbeat_interval_seconds=30,
        enrolled_at="2026-07-23T10:00:00Z",
    )
    outcome = ScanScheduler(
        ConcurrencyScanner(), storage, paths.root / "scans"
    ).run(
        scan_id="00000000-0000-0000-0000-000000000456",
        profile="standard",
        targets=[{"device_id": "device-1", "ip": "192.168.1.10"}],
        concurrency=1,
        identity=identity,
        client=client,
        keepalive=lambda: None,
    )

    assert outcome == "completed"
    assert client.attempts == 2
    assert client.results[0] == client.results[1]


def test_exhausted_result_delivery_retains_local_scan_evidence(
    tmp_path: Path,
) -> None:
    class UnreachableClient(FakeScanClient):
        def __init__(self):
            super().__init__()
            self.attempts = 0

        def upload_host_result(self, scan_id, device_id, payload, *, credential):
            self.attempts += 1
            raise OSError("Result endpoint unavailable")

    paths = AgentPaths(tmp_path)
    storage = AgentStorage(paths)
    storage.initialize()
    client = UnreachableClient()
    identity = AgentIdentity(
        agent_id="00000000-0000-0000-0000-000000000123",
        server_url="https://forgesec.example.com",
        credential="tes_agent_secret",
        heartbeat_interval_seconds=30,
        enrolled_at="2026-07-23T10:00:00Z",
    )
    scan_id = "00000000-0000-0000-0000-000000000456"
    outcome = ScanScheduler(
        ConcurrencyScanner(), storage, paths.root / "scans"
    ).run(
        scan_id=scan_id,
        profile="standard",
        targets=[{"device_id": "device-1", "ip": "192.168.1.10"}],
        concurrency=1,
        identity=identity,
        client=client,
        keepalive=lambda: None,
    )

    saved = storage.read_json(
        paths.root / "scans" / scan_id / "hosts" / "device-1.json"
    )
    assert outcome == "failed"
    assert client.attempts == 3
    assert saved is not None and saved["status"] == "completed"
    assert (paths.root / "scans" / scan_id / "raw" / "device-1.xml").is_file()
    assert client.progress[-1]["status"] == "failed"
