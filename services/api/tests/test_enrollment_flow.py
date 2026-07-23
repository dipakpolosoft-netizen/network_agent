from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from telesec_api.settings import Settings


def enrollment(client: TestClient) -> dict:
    response = client.post(
        "/api/enrollments",
        json={"label": "Head Office Agent", "site_name": "Head Office"},
    )
    assert response.status_code == 201
    return response.json()


def enroll_agent(client: TestClient, token: str) -> dict:
    response = client.post(
        "/agent/enroll",
        json={
            "schema_version": "1.0",
            "message_type": "agent.enroll.request",
            "enrollment_token": token,
            "agent_version": "0.1.0",
            "hostname": "WIN-AGENT-01",
            "os_name": "Windows 11",
            "architecture": "x86_64",
            "requested_at": datetime.now(UTC).isoformat(),
        },
    )
    assert response.status_code == 201
    return response.json()


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_enrollment_token_is_not_stored_in_plaintext(
    client: TestClient, settings: Settings
) -> None:
    created = enrollment(client)
    persisted = list((settings.runtime_data_dir / "enrollments").glob("*.json"))
    assert len(persisted) == 1
    assert created["enrollment_token"] not in persisted[0].read_text(encoding="utf-8")


def test_agent_can_enroll_once_and_send_authenticated_heartbeat(
    client: TestClient,
) -> None:
    created = enrollment(client)
    enrolled = enroll_agent(client, created["enrollment_token"])

    reused = client.post(
        "/agent/enroll",
        json={
            "schema_version": "1.0",
            "message_type": "agent.enroll.request",
            "enrollment_token": created["enrollment_token"],
            "agent_version": "0.1.0",
            "hostname": "WIN-AGENT-02",
            "os_name": "Windows 11",
            "architecture": "x86_64",
            "requested_at": datetime.now(UTC).isoformat(),
        },
    )
    assert reused.status_code == 409

    heartbeat = client.post(
        "/agent/heartbeat",
        headers={"Authorization": f"Bearer {enrolled['agent_credential']}"},
        json={
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
        },
    )
    assert heartbeat.status_code == 200
    assert heartbeat.json()["status"] == "accepted"

    agents = client.get("/api/agents")
    assert agents.status_code == 200
    body = agents.json()
    assert len(body) == 1
    assert body[0]["status"] == "online"
    assert body[0]["local_ip"] == "192.168.1.25"
    assert "credential_hash" not in body[0]


def test_heartbeat_rejects_missing_or_mismatched_credentials(
    client: TestClient,
) -> None:
    created = enrollment(client)
    enrolled = enroll_agent(client, created["enrollment_token"])
    payload = {
        "schema_version": "1.0",
        "message_type": "agent.heartbeat",
        "agent_id": enrolled["agent_id"],
        "agent_version": "0.1.0",
        "hostname": "WIN-AGENT-01",
        "os_name": "Windows 11",
        "local_ip": None,
        "subnet": None,
        "nmap_version": None,
        "npcap_status": "unknown",
        "service_status": "online",
        "current_command_id": None,
        "sent_at": datetime.now(UTC).isoformat(),
    }
    assert client.post("/agent/heartbeat", json=payload).status_code == 401

    wrong_id = dict(payload, agent_id="00000000-0000-0000-0000-000000000001")
    response = client.post(
        "/agent/heartbeat",
        headers={"Authorization": f"Bearer {enrolled['agent_credential']}"},
        json=wrong_id,
    )
    assert response.status_code == 403


def test_final_heartbeat_marks_agent_offline_immediately(client: TestClient) -> None:
    created = enrollment(client)
    enrolled = enroll_agent(client, created["enrollment_token"])
    payload = {
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
        "service_status": "offline",
        "current_command_id": None,
        "sent_at": datetime.now(UTC).isoformat(),
    }

    response = client.post(
        "/agent/heartbeat",
        headers={"Authorization": f"Bearer {enrolled['agent_credential']}"},
        json=payload,
    )

    assert response.status_code == 200
    agents = client.get("/api/agents").json()
    assert agents[0]["status"] == "offline"
