from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from test_enrollment_flow import enroll_agent, enrollment

from forgesec_api.agents.models import AgentHeartbeat
from forgesec_api.agents.service import InvalidAgentCredential
from forgesec_api.main import create_app
from forgesec_api.security import generate_agent_credential
from forgesec_api.settings import Settings


def test_probe_credential_rotation_and_revocation(client: TestClient) -> None:
    issued = enroll_agent(client, enrollment(client)["enrollment_token"])
    agent_id = issued["agent_id"]
    old = issued["agent_credential"]
    new = generate_agent_credential()
    assert client.get("/agent/credentials/status").status_code == 401
    assert client.get(
        "/agent/credentials/status", headers={"Authorization": f"Bearer {old}"}
    ).json() == {"agent_id": agent_id}

    wrong_id = "00000000-0000-0000-0000-000000000001"
    assert client.post(
        "/agent/credentials/rotate",
        headers={"Authorization": f"Bearer {old}"},
        json={"agent_id": wrong_id, "new_credential": new},
    ).status_code == 403
    assert client.post(
        "/agent/credentials/rotate",
        headers={"Authorization": f"Bearer {old}"},
        json={"agent_id": agent_id, "new_credential": new},
    ).status_code == 204
    assert client.get(
        "/agent/credentials/status", headers={"Authorization": f"Bearer {old}"}
    ).status_code == 401
    assert client.get(
        "/agent/credentials/status", headers={"Authorization": f"Bearer {new}"}
    ).status_code == 200
    public = client.get(f"/api/agents/{agent_id}").json()
    assert public["credential_rotated_at"]
    assert new not in str(public)

    commands = client.app.state.command_service
    queued = commands.create(agent_id=agent_id, command_type="test", payload={})

    revoked = client.post(
        f"/api/agents/{agent_id}/revoke", json={"reason": "Probe decommissioned"}
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "offline"
    assert revoked.json()["revoked_at"]
    assert commands.get(queued["command_id"])["status"] == "cancelled"
    assert commands.claim_next(agent_id) is None
    assert client.get(
        "/agent/commands/next", headers={"Authorization": f"Bearer {new}"}
    ).status_code == 401
    assert client.post(
        f"/api/agents/{agent_id}/revoke", json={"reason": "Again"}
    ).status_code == 409


def test_only_admin_can_revoke_probe(settings: Settings) -> None:
    app = create_app(replace(settings, auth_required=True))
    with TestClient(app) as client:
        auth = app.state.auth_service
        auth.create_user("admin@example.test", "correct horse battery", "admin")
        auth.create_user("operator@example.test", "operator password here", "operator")
        _, token = app.state.enrollment_service.create(
            label="QA Probe", site_name="QA Site"
        )
        agent_id = enroll_agent(client, token)["agent_id"]
        path = f"/api/agents/{agent_id}/revoke"
        assert client.post(path, json={"reason": "Decommissioned"}).status_code == 401
        operator = client.post(
            "/api/auth/login",
            json={
                "email": "operator@example.test",
                "password": "operator password here",
            },
        )
        assert client.post(
            path,
            headers={"X-CSRF-Token": operator.json()["csrf_token"]},
            json={"reason": "Decommissioned"},
        ).status_code == 403
        admin = client.post(
            "/api/auth/login",
            json={"email": "admin@example.test", "password": "correct horse battery"},
        )
        assert client.post(
            path,
            headers={"X-CSRF-Token": admin.json()["csrf_token"]},
            json={"reason": "Decommissioned"},
        ).status_code == 200


def test_stale_heartbeat_cannot_undo_rotation_or_revocation(client: TestClient) -> None:
    issued = enroll_agent(client, enrollment(client)["enrollment_token"])
    service = client.app.state.agent_service
    old = issued["agent_credential"]
    stale = service.authenticate(old)
    payload = AgentHeartbeat.model_validate(
        {
            "schema_version": "1.0",
            "message_type": "agent.heartbeat",
            "agent_id": issued["agent_id"],
            "agent_version": "0.1.0",
            "hostname": "WIN-AGENT-01",
            "os_name": "Windows 11",
            "npcap_status": "unknown",
            "service_status": "online",
            "sent_at": datetime.now(UTC).isoformat(),
        }
    )
    new = generate_agent_credential()
    service.rotate_credential(issued["agent_id"], old, new)
    with pytest.raises(InvalidAgentCredential):
        service.heartbeat(stale, payload)
    assert service.authenticate(new)["credential_rotated_at"]
    fresh = service.authenticate(new)
    service.revoke(issued["agent_id"], "Decommissioned")
    with pytest.raises(InvalidAgentCredential):
        service.heartbeat(fresh, payload)
    assert service.get_public(issued["agent_id"])["revoked_at"]
