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


def test_failed_command_updates_discovery_terminal_state(client: TestClient) -> None:
    agent = authenticated_agent(client)
    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}
    created = client.post(
        f"/api/agents/{agent['agent_id']}/discover",
        json={"authorization_confirmed": True},
    ).json()
    command = client.get("/agent/commands/next", headers=authorization).json()
    now = datetime.now(UTC).isoformat()

    running = client.post(
        f"/agent/commands/{command['command_id']}/events",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "command.event",
            "status": "running",
            "message": "Validating the authorized network scope",
            "details": {"stage": "validating_scope"},
            "occurred_at": now,
        },
    )
    assert running.status_code == 200
    active = client.get(f"/api/discoveries/{created['discovery_id']}").json()
    assert active["status"] == "running"
    assert active["stage"] == "validating_scope"
    assert active["started_at"] is not None

    failed = client.post(
        f"/agent/commands/{command['command_id']}/events",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "command.event",
            "status": "failed",
            "message": "Ethernet is not a private IPv4 network",
            "details": {
                "stage": "failed",
                "failure_code": "scope_not_private",
            },
            "occurred_at": now,
        },
    )
    assert failed.status_code == 200
    terminal = client.get(f"/api/discoveries/{created['discovery_id']}").json()
    assert terminal["status"] == "failed"
    assert terminal["error"] == "Ethernet is not a private IPv4 network"
    assert terminal["completed_at"] is not None
    assert terminal["events"][-1]["stage"] == "failed"


def test_queued_discovery_can_be_cancelled(client: TestClient) -> None:
    agent = authenticated_agent(client)
    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}
    created = client.post(
        f"/api/agents/{agent['agent_id']}/discover",
        json={"authorization_confirmed": True},
    ).json()

    cancelled = client.post(
        f"/api/discoveries/{created['discovery_id']}/cancel"
    )

    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"
    assert cancelled.json()["cancel_requested"] is True
    assert client.get("/agent/commands/next", headers=authorization).status_code == 204
    control = client.get(
        f"/agent/discoveries/{created['discovery_id']}/control",
        headers=authorization,
    )
    assert control.status_code == 200
    assert control.json()["cancel_requested"] is True


def public_slash_22_heartbeat(client: TestClient, agent: dict) -> None:
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
            "local_ip": "172.168.1.248",
            "subnet": "172.168.0.0/22",
            "nmap_version": "7.99",
            "npcap_status": "available",
            "discovery_ready": True,
            "discovery_network": "172.168.0.0/22",
            "discovery_interface": "Ethernet",
            "discovery_capability": "authorization_required",
            "discovery_scope_options": [
                "172.168.0.0/24",
                "172.168.1.0/24",
                "172.168.2.0/24",
                "172.168.3.0/24",
            ],
            "discovery_recommended_scope": "172.168.1.0/24",
            "discovery_requires_authorization": True,
            "discovery_all_segments_available": True,
            "service_status": "online",
            "current_command_id": None,
            "sent_at": datetime.now(UTC).isoformat(),
        },
    )
    assert response.status_code == 200


def test_public_slash_22_is_dispatched_as_four_authorized_segments(
    client: TestClient,
) -> None:
    agent = authenticated_agent(client)
    public_slash_22_heartbeat(client, agent)
    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}

    created = client.post(
        f"/api/agents/{agent['agent_id']}/discover",
        json={
            "authorization_confirmed": True,
            "scope": None,
            "mode": "all",
        },
    )

    assert created.status_code == 202
    command = client.get("/agent/commands/next", headers=authorization).json()
    assert command["payload"]["connected_network"] == "172.168.0.0/22"
    assert command["payload"]["scopes"] == [
        "172.168.0.0/24",
        "172.168.1.0/24",
        "172.168.2.0/24",
        "172.168.3.0/24",
    ]
    discovery = client.get(
        f"/api/discoveries/{created.json()['discovery_id']}"
    ).json()
    assert discovery["mode"] == "all"
    assert discovery["network"] == "172.168.0.0/22"
    assert discovery["total_scopes"] == 4
    assert discovery["public_scope_authorized"] is True
    now = datetime.now(UTC).isoformat()
    uploaded = client.post(
        f"/agent/discoveries/{created.json()['discovery_id']}/devices",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "discovery.result",
            "discovery_id": created.json()["discovery_id"],
            "agent_id": agent["agent_id"],
            "network": "172.168.0.0/22",
            "interface_name": "Ethernet",
            "status": "completed",
            "started_at": now,
            "completed_at": now,
            "devices": [
                {
                    "device_id": "public-segment-device-0001",
                    "ip": "172.168.0.10",
                    "hostname": None,
                    "mac": None,
                    "vendor": None,
                    "status": "up",
                    "discovery_reason": "arp-response",
                    "latency_ms": 1.0,
                    "is_agent": False,
                    "first_seen": now,
                    "last_seen": now,
                    "discovery_scope": "172.168.0.0/24",
                },
                {
                    "device_id": "public-segment-device-0002",
                    "ip": "172.168.3.10",
                    "hostname": None,
                    "mac": None,
                    "vendor": None,
                    "status": "up",
                    "discovery_reason": "arp-response",
                    "latency_ms": 1.0,
                    "is_agent": False,
                    "first_seen": now,
                    "last_seen": now,
                    "discovery_scope": "172.168.3.0/24",
                },
            ],
            "error": None,
            "requested_scopes": command["payload"]["scopes"],
            "completed_scopes": command["payload"]["scopes"],
            "failed_scopes": [],
        },
    )
    assert uploaded.status_code == 200
    assert uploaded.json()["device_count"] == 2
    assert uploaded.json()["completed_scopes"] == command["payload"]["scopes"]


def test_public_selected_scope_is_limited_to_requested_slash_24(
    client: TestClient,
) -> None:
    agent = authenticated_agent(client)
    public_slash_22_heartbeat(client, agent)
    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}

    created = client.post(
        f"/api/agents/{agent['agent_id']}/discover",
        json={
            "authorization_confirmed": True,
            "scope": "172.168.1.0/24",
            "mode": "selected",
        },
    )

    assert created.status_code == 202
    command = client.get("/agent/commands/next", headers=authorization).json()
    assert command["payload"]["scopes"] == ["172.168.1.0/24"]
    discovery = client.get(
        f"/api/discoveries/{created.json()['discovery_id']}"
    ).json()
    assert discovery["network"] == "172.168.1.0/24"
