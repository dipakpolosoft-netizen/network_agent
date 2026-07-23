from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from test_enrollment_flow import enroll_agent, enrollment


def authenticated_agent(client: TestClient) -> dict:
    created = enrollment(client)
    enrolled = enroll_agent(client, created["enrollment_token"])
    heartbeat = {
        "schema_version": "1.0",
        "message_type": "agent.heartbeat",
        "agent_id": enrolled["agent_id"],
        "agent_version": "0.1.0",
        "hostname": "WIN-AGENT-01",
        "os_name": "Windows 11",
        "local_ip": "192.168.1.25",
        "subnet": "192.168.1.0/24",
        "nmap_version": "7.99",
        "npcap_status": "available",
        "service_status": "online",
        "current_command_id": None,
        "sent_at": datetime.now(UTC).isoformat(),
    }
    response = client.post(
        "/agent/heartbeat",
        headers={"Authorization": f"Bearer {enrolled['agent_credential']}"},
        json=heartbeat,
    )
    assert response.status_code == 200
    return enrolled


def test_discovery_command_claim_and_result_upload(client: TestClient) -> None:
    agent = authenticated_agent(client)
    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}

    created = client.post(
        f"/api/agents/{agent['agent_id']}/discover",
        json={"authorization_confirmed": True},
    )
    assert created.status_code == 202
    discovery = created.json()

    claimed = client.get("/agent/commands/next", headers=authorization)
    assert claimed.status_code == 200
    command = claimed.json()
    assert command["command_type"] == "discover_network"
    assert command["payload"]["discovery_id"] == discovery["discovery_id"]
    assert client.get("/agent/commands/next", headers=authorization).status_code == 204

    running = client.post(
        f"/agent/commands/{command['command_id']}/events",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "command.event",
            "status": "running",
            "message": "Discovering the authorized local network",
            "details": {},
            "occurred_at": datetime.now(UTC).isoformat(),
        },
    )
    assert running.status_code == 200

    now = datetime.now(UTC).isoformat()
    uploaded = client.post(
        f"/agent/discoveries/{discovery['discovery_id']}/devices",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "discovery.result",
            "discovery_id": discovery["discovery_id"],
            "agent_id": agent["agent_id"],
            "network": "192.168.1.0/24",
            "interface_name": "Ethernet",
            "status": "completed",
            "started_at": now,
            "completed_at": now,
            "devices": [
                {
                    "device_id": "device-192-168-1-1",
                    "ip": "192.168.1.1",
                    "hostname": "gateway",
                    "mac": "00:11:22:33:44:55",
                    "vendor": "Example Vendor",
                    "status": "up",
                    "discovery_reason": "arp-response",
                    "latency_ms": 1.2,
                    "is_agent": False,
                    "first_seen": now,
                    "last_seen": now,
                }
            ],
            "error": None,
        },
    )
    assert uploaded.status_code == 200
    assert uploaded.json()["device_count"] == 1

    completed = client.post(
        f"/agent/commands/{command['command_id']}/events",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "command.event",
            "status": "completed",
            "message": "Discovery completed",
            "details": {"device_count": 1},
            "occurred_at": datetime.now(UTC).isoformat(),
        },
    )
    assert completed.status_code == 200

    fetched = client.get(f"/api/discoveries/{discovery['discovery_id']}")
    assert fetched.status_code == 200
    assert fetched.json()["devices"][0]["ip"] == "192.168.1.1"


def test_discovery_requires_scanner_dependencies(client: TestClient) -> None:
    agent = authenticated_agent(client)
    heartbeat = {
        "schema_version": "1.0",
        "message_type": "agent.heartbeat",
        "agent_id": agent["agent_id"],
        "agent_version": "0.1.0",
        "hostname": "WIN-AGENT-01",
        "os_name": "Windows 11",
        "local_ip": "192.168.1.25",
        "subnet": "192.168.1.0/24",
        "nmap_version": None,
        "npcap_status": "missing",
        "service_status": "online",
        "current_command_id": None,
        "sent_at": datetime.now(UTC).isoformat(),
    }
    updated = client.post(
        "/agent/heartbeat",
        headers={"Authorization": f"Bearer {agent['agent_credential']}"},
        json=heartbeat,
    )
    assert updated.status_code == 200

    response = client.post(
        f"/api/agents/{agent['agent_id']}/discover",
        json={"authorization_confirmed": True},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Nmap is not installed on this agent"
    assert client.get("/api/discoveries").json() == []


def test_discovery_rejects_devices_outside_reported_network(
    client: TestClient,
) -> None:
    agent = authenticated_agent(client)
    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}
    created = client.post(
        f"/api/agents/{agent['agent_id']}/discover",
        json={"authorization_confirmed": True},
    ).json()
    now = datetime.now(UTC).isoformat()
    response = client.post(
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
            "devices": [
                {
                    "device_id": "device-outside-network",
                    "ip": "192.168.2.10",
                    "hostname": None,
                    "mac": None,
                    "vendor": None,
                    "status": "up",
                    "discovery_reason": "icmp-response",
                    "latency_ms": None,
                    "is_agent": False,
                    "first_seen": now,
                    "last_seen": now,
                }
            ],
            "error": None,
        },
    )
    assert response.status_code == 422
