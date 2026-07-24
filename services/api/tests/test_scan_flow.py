from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from test_discovery_flow import authenticated_agent


def completed_discovery(
    client: TestClient, device_count: int = 2
) -> tuple[dict, dict]:
    agent = authenticated_agent(client)
    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}
    created = client.post(
        f"/api/agents/{agent['agent_id']}/discover",
        json={"authorization_confirmed": True},
    ).json()
    command = client.get("/agent/commands/next", headers=authorization).json()
    now = datetime.now(UTC).isoformat()
    client.post(
        f"/agent/commands/{command['command_id']}/events",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "command.event",
            "status": "running",
            "message": "Discovery running",
            "details": {},
            "occurred_at": now,
        },
    )
    devices = [
        {
            "device_id": f"selected-device-{number:04d}",
            "ip": f"192.168.1.{number + 9}",
            "hostname": f"server-{number}",
            "mac": f"00:11:22:33:44:{number:02x}",
            "vendor": "Example",
            "status": "up",
            "discovery_reason": "arp-response",
            "latency_ms": 1.0,
            "is_agent": False,
            "first_seen": now,
            "last_seen": now,
        }
        for number in range(1, device_count + 1)
    ]
    uploaded = client.post(
        f"/agent/discoveries/{created['discovery_id']}/devices",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "discovery.result",
            "discovery_id": created["discovery_id"],
            "agent_id": agent["agent_id"],
            "network": "192.168.1.0/24",
            "interface_name": "Ethernet",
            "status": "completed",
            "started_at": now,
            "completed_at": now,
            "devices": devices,
            "error": None,
        },
    )
    assert uploaded.status_code == 200
    completed = client.post(
        f"/agent/commands/{command['command_id']}/events",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "command.event",
            "status": "completed",
            "message": "Discovery completed",
            "details": {"device_count": device_count},
            "occurred_at": now,
        },
    )
    assert completed.status_code == 200
    return agent, created


def test_selected_device_scan_progress_and_results(client: TestClient) -> None:
    agent, discovery = completed_discovery(client)
    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}
    created = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": ["selected-device-0001", "selected-device-0002"],
            "profile": "standard",
            "authorization_confirmed": True,
        },
    )
    assert created.status_code == 202
    scan = created.json()
    assert scan["total"] == 2

    command = client.get("/agent/commands/next", headers=authorization).json()
    assert command["command_type"] == "scan_devices"
    assert len(command["payload"]["targets"]) == 2
    assert command["payload"]["concurrency"] == 3

    now = datetime.now(UTC).isoformat()
    progress = client.post(
        f"/agent/scans/{scan['scan_id']}/progress",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "scan.progress",
            "scan_id": scan["scan_id"],
            "agent_id": agent["agent_id"],
            "status": "running",
            "stage": "service_detection",
            "total": 2,
            "queued": 1,
            "running": 1,
            "completed": 0,
            "failed": 0,
            "cancelled": 0,
            "updated_at": now,
        },
    )
    assert progress.status_code == 200

    result = client.post(
        f"/agent/scans/{scan['scan_id']}/hosts/selected-device-0001/result",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "host_scan.result",
            "scan_id": scan["scan_id"],
            "agent_id": agent["agent_id"],
            "device_id": "selected-device-0001",
            "ip": "192.168.1.10",
            "status": "completed",
            "started_at": now,
            "completed_at": now,
            "hostname": "server-one",
            "device_type": "server",
            "classification_confidence": 0.8,
            "ports": [
                {
                    "protocol": "tcp",
                    "port": 22,
                    "state": "open",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "9.0",
                    "cpe": "cpe:/a:openbsd:openssh:9.0",
                }
            ],
            "os_matches": [{"name": "Linux", "accuracy": 95}],
            "exposure_flags": [],
            "error": None,
        },
    )
    assert result.status_code == 200
    assert len(result.json()["results"]) == 1

    class FakeVulnerabilityService:
        def lookup(self, cpe: str) -> dict:
            assert cpe == "cpe:/a:openbsd:openssh:9.0"
            return {
                "source": "NVD",
                "cpe": cpe,
                "normalized_cpe": "cpe:2.3:a:openbsd:openssh:9.0:*:*:*:*:*:*:*",
                "total": 0,
                "returned": 0,
                "retrieved_at": now,
                "cached": False,
                "vulnerabilities": [],
                "notice": "Potential matches only.",
            }

    client.app.state.vulnerability_service = FakeVulnerabilityService()
    lookup = client.get(
        f"/api/scans/{scan['scan_id']}/devices/selected-device-0001/vulnerabilities",
        params={"cpe": "cpe:/a:openbsd:openssh:9.0"},
    )
    assert lookup.status_code == 200
    assert lookup.json()["normalized_cpe"].startswith("cpe:2.3:a:openbsd")

    unobserved = client.get(
        f"/api/scans/{scan['scan_id']}/devices/selected-device-0001/vulnerabilities",
        params={"cpe": "cpe:/a:example:unobserved:1.0"},
    )
    assert unobserved.status_code == 422

    cancelled = client.post(f"/api/scans/{scan['scan_id']}/cancel")
    assert cancelled.status_code == 200
    control = client.get(
        f"/agent/scans/{scan['scan_id']}/control",
        headers=authorization,
    )
    assert control.json()["cancel_requested"] is True


def test_scan_rejects_unknown_or_excessive_device_selection(
    client: TestClient,
) -> None:
    _agent, discovery = completed_discovery(client)
    unknown = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": ["unknown-device"],
            "profile": "standard",
            "authorization_confirmed": True,
        },
    )
    assert unknown.status_code == 422

    excessive = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": [f"device-{number:02d}" for number in range(11)],
            "profile": "standard",
            "authorization_confirmed": True,
        },
    )
    assert excessive.status_code == 422


def test_scan_accepts_more_than_ten_discovered_devices(client: TestClient) -> None:
    _agent, discovery = completed_discovery(client, device_count=12)
    selected = [f"selected-device-{number:04d}" for number in range(1, 13)]

    response = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": selected,
            "profile": "standard",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 202
    assert response.json()["total"] == 12
