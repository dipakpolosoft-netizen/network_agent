from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from test_enrollment_flow import enroll_agent, enrollment


def online_agent(client: TestClient) -> dict:
    created = enrollment(client)
    agent = enroll_agent(client, created["enrollment_token"])
    response = client.post(
        "/agent/heartbeat",
        headers={"Authorization": f"Bearer {agent['agent_credential']}"},
        json={
            "schema_version": "1.0",
            "message_type": "agent.heartbeat",
            "agent_id": agent["agent_id"],
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
        },
    )
    assert response.status_code == 200
    site_id = client.get("/api/agents").json()[0]["site_id"]
    assert client.post(
        f"/api/sites/{site_id}/scopes",
        json={"cidr": "192.168.1.0/24", "label": "Test LAN"},
    ).status_code == 201
    return agent


def test_device_diagnostic_command_round_trip(client: TestClient) -> None:
    agent = online_agent(client)
    created = client.post(
        f"/api/agents/{agent['agent_id']}/diagnostics",
        json={"target_ip": "192.168.1.2", "diagnostic_type": "ping"},
    )
    assert created.status_code == 202
    diagnostic = created.json()
    assert diagnostic["status"] == "queued"
    assert diagnostic["target_ip"] == "192.168.1.2"

    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}
    command = client.get("/agent/commands/next", headers=authorization).json()
    assert command["command_id"] == diagnostic["command_id"]
    assert command["command_type"] == "device_diagnostic"
    assert command["payload"]["target_ip"] == "192.168.1.2"
    assert command["payload"]["diagnostic_type"] == "ping"
    assert command["payload"]["scope_policy"][0]["cidr"] == "192.168.1.0/24"

    now = datetime.now(UTC).isoformat()
    running = client.post(
        f"/agent/commands/{command['command_id']}/events",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "command.event",
            "status": "running",
            "message": "Ping running",
            "details": {
                "target_ip": "192.168.1.2",
                "diagnostic_type": "ping",
                "command_line": "ping -n 4 192.168.1.2",
                "started_at": now,
            },
            "occurred_at": now,
        },
    )
    assert running.status_code == 200

    completed = client.post(
        f"/agent/commands/{command['command_id']}/events",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "command.event",
            "status": "completed",
            "message": "Ping completed: host responded",
            "details": {
                "target_ip": "192.168.1.2",
                "diagnostic_type": "ping",
                "command_line": "ping -n 4 192.168.1.2",
                "output": "Reply from 192.168.1.2: bytes=32 time=2ms TTL=64",
                "exit_code": 0,
                "duration_ms": 2100,
                "started_at": now,
                "completed_at": now,
                "reachable": True,
            },
            "occurred_at": now,
        },
    )
    assert completed.status_code == 200

    loaded = client.get(
        f"/api/agents/{agent['agent_id']}/diagnostics/{command['command_id']}",
    )
    assert loaded.status_code == 200
    body = loaded.json()
    assert body["status"] == "completed"
    assert body["message"] == "Ping completed: host responded"
    assert body["output"].startswith("Reply from")
    assert body["exit_code"] == 0
    assert body["duration_ms"] == 2100


def test_inventory_nmap_diagnostic_is_accepted(client: TestClient) -> None:
    agent = online_agent(client)
    created = client.post(
        f"/api/agents/{agent['agent_id']}/diagnostics",
        json={"target_ip": "192.168.1.2", "diagnostic_type": "inventory_nmap"},
    )

    assert created.status_code == 202
    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}
    command = client.get("/agent/commands/next", headers=authorization).json()
    assert command["payload"]["target_ip"] == "192.168.1.2"
    assert command["payload"]["diagnostic_type"] == "inventory_nmap"
    assert command["payload"]["scope_policy"][0]["cidr"] == "192.168.1.0/24"


def test_network_services_nmap_diagnostic_is_accepted(client: TestClient) -> None:
    agent = online_agent(client)
    created = client.post(
        f"/api/agents/{agent['agent_id']}/diagnostics",
        json={
            "target_ip": "192.168.1.2",
            "diagnostic_type": "network_services_nmap",
        },
    )

    assert created.status_code == 202
    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}
    command = client.get("/agent/commands/next", headers=authorization).json()
    assert command["payload"]["target_ip"] == "192.168.1.2"
    assert command["payload"]["diagnostic_type"] == "network_services_nmap"
    assert command["payload"]["scope_policy"][0]["cidr"] == "192.168.1.0/24"
