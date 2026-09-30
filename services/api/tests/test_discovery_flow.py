from __future__ import annotations

from datetime import UTC, datetime

from approval_payload import approved_scope
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
    site_id = client.get("/api/agents").json()[0]["site_id"]
    scopes = client.get(f"/api/sites/{site_id}/scopes").json()
    if not any(item["cidr"] == "192.168.1.0/24" for item in scopes):
        approved = client.post(
            f"/api/sites/{site_id}/scopes",
            json=approved_scope("192.168.1.0/24", "Test LAN"),
        )
        assert approved.status_code == 201
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
                },
                {
                    "device_id": "device-192-168-1-25",
                    "ip": "192.168.1.25",
                    "hostname": "WIN-AGENT-01",
                    "mac": None,
                    "vendor": None,
                    "status": "up",
                    "discovery_reason": "arp-response",
                    "latency_ms": 0.1,
                    "is_agent": False,
                    "first_seen": now,
                    "last_seen": now,
                },
            ],
            "error": None,
        },
    )
    assert uploaded.status_code == 200
    assert uploaded.json()["device_count"] == 2

    completed = client.post(
        f"/agent/commands/{command['command_id']}/events",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "command.event",
            "status": "completed",
            "message": "Discovery completed",
            "details": {"device_count": 2},
            "occurred_at": datetime.now(UTC).isoformat(),
        },
    )
    assert completed.status_code == 200

    fetched = client.get(f"/api/discoveries/{discovery['discovery_id']}")
    assert fetched.status_code == 200
    assert fetched.json()["devices"][0]["ip"] == "192.168.1.1"
    assert fetched.json()["devices"][1]["is_agent"] is True
    assert client.get("/api/assets").json()["total"] == 1


def test_known_host_checks_are_bounded_and_preserve_no_response(
    client: TestClient,
) -> None:
    agent = authenticated_agent(client)
    endpoint = f"/api/agents/{agent['agent_id']}/discover"
    request = {
        "authorization_confirmed": True,
        "scope": "192.168.1.0/24",
        "mode": "selected",
    }
    for targets in (
        ["192.168.2.2"],
        ["192.168.1.25"],
        ["192.168.1.0"],
        ["192.168.1.255"],
        ["192.168.1.2", "192.168.1.2"],
        ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4"],
    ):
        assert client.post(
            endpoint, json={**request, "known_targets": targets}
        ).status_code == 422

    created = client.post(
        endpoint,
        json={**request, "known_targets": ["192.168.1.1", "192.168.1.2"]},
    )
    assert created.status_code == 202
    discovery_id = created.json()["discovery_id"]
    command = client.app.state.store.read("commands", created.json()["command_id"])
    assert command["payload"]["known_targets"] == ["192.168.1.1", "192.168.1.2"]
    now = datetime.now(UTC).isoformat()
    payload = {
        "schema_version": "1.0",
        "message_type": "discovery.result",
        "discovery_id": discovery_id,
        "agent_id": agent["agent_id"],
        "network": "192.168.1.0/24",
        "interface_name": "Ethernet",
        "status": "completed",
        "started_at": now,
        "completed_at": now,
        "devices": [{
            "device_id": "device-192-168-1-1",
            "ip": "192.168.1.1",
            "status": "up",
            "discovery_reason": "arp-response",
            "is_agent": False,
            "first_seen": now,
            "last_seen": now,
        }],
        "follow_up_checks": [
            {
                "ip": "192.168.1.1",
                "status": "already_discovered",
                "method": "initial_discovery",
                "checked_at": now,
                "reason": "arp-response",
            },
            {
                "ip": "192.168.1.2",
                "status": "no_response",
                "method": "targeted_tcp_icmp",
                "checked_at": now,
                "reason": "no-response",
            },
        ],
        "error": None,
    }
    upload_path = f"/agent/discoveries/{discovery_id}/devices"
    headers = {"Authorization": f"Bearer {agent['agent_credential']}"}
    invalid = {**payload, "follow_up_checks": [
        {**payload["follow_up_checks"][1], "ip": "192.168.1.1"}
    ]}
    assert client.post(upload_path, headers=headers, json=invalid).status_code == 422
    uploaded = client.post(upload_path, headers=headers, json=payload)
    assert uploaded.status_code == 200, uploaded.text
    saved = client.get(f"/api/discoveries/{discovery_id}").json()
    assert saved["known_targets"] == ["192.168.1.1", "192.168.1.2"]
    assert [item["status"] for item in saved["follow_up_checks"]] == [
        "already_discovered", "no_response"
    ]
    assert saved["device_count"] == 1
    assert client.get("/api/assets").json()["total"] == 1

    older_probe = client.post(
        endpoint,
        json={**request, "known_targets": ["192.168.1.2"]},
    )
    assert older_probe.status_code == 202
    missing_checks = {
        **payload,
        "discovery_id": older_probe.json()["discovery_id"],
        "devices": [],
        "follow_up_checks": [],
    }
    incomplete = client.post(
        f"/agent/discoveries/{older_probe.json()['discovery_id']}/devices",
        headers=headers,
        json=missing_checks,
    )
    assert incomplete.status_code == 200
    assert incomplete.json()["status"] == "partial"
    assert "not reported" in incomplete.json()["error"]


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


def test_timed_out_segment_keeps_partial_host_evidence(client: TestClient) -> None:
    agent = authenticated_agent(client)
    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}
    created = client.post(
        f"/api/agents/{agent['agent_id']}/discover",
        json={"authorization_confirmed": True, "scope": "192.168.1.0/24"},
    ).json()
    now = datetime.now(UTC).isoformat()
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
            "status": "partial",
            "started_at": now,
            "completed_at": now,
            "devices": [{
                "device_id": "device-partial-host",
                "ip": "192.168.1.20",
                "status": "up",
                "discovery_reason": "arp-response",
                "is_agent": False,
                "first_seen": now,
                "last_seen": now,
            }],
            "requested_scopes": ["192.168.1.0/24"],
            "completed_scopes": [],
            "failed_scopes": ["192.168.1.0/24"],
            "error": "1 segment(s) failed",
        },
    )
    assert uploaded.status_code == 200, uploaded.text
    saved = client.get(f"/api/discoveries/{created['discovery_id']}").json()
    assert saved["status"] == "partial"
    assert saved["completed_scopes"] == []
    assert saved["failed_scopes"] == ["192.168.1.0/24"]
    assert saved["devices"][0]["discovery_reason"] == "arp-response"
    assert saved["devices"][0]["last_seen"] == now.replace("+00:00", "Z")
    assert client.get("/api/assets").json()["total"] == 1


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


def test_queued_discovery_expires_without_probe_polling(client: TestClient) -> None:
    agent = authenticated_agent(client)
    created = client.post(
        f"/api/agents/{agent['agent_id']}/discover",
        json={"authorization_confirmed": True},
    ).json()
    store = client.app.state.store
    command = store.read("commands", created["command_id"])
    command["expires_at"] = "2020-01-01T00:00:00Z"
    store.write("commands", created["command_id"], command)

    discovery = client.get(f"/api/discoveries/{created['discovery_id']}").json()
    assert discovery["status"] == "failed"
    assert discovery["error"] == "Command expired before the agent claimed it"
    assert discovery["completed_at"] is not None
    assert store.read("commands", created["command_id"])["status"] == "expired"


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
    site_id = client.get("/api/agents").json()[0]["site_id"]
    approved = client.post(
        f"/api/sites/{site_id}/scopes",
        json=approved_scope("172.168.0.0/22", "Authorized test range"),
    )
    assert approved.status_code == 201
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
