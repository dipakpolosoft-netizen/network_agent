from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from approval_payload import approved_scope
from fastapi.testclient import TestClient
from test_discovery_flow import authenticated_agent
from test_enrollment_flow import enroll_agent
from test_scan_flow import completed_discovery

from forgesec_api.settings import Settings
from forgesec_api.storage import JsonStore


def test_probe_enrollment_binds_to_selected_site(client: TestClient) -> None:
    site = client.post(
        "/api/sites",
        json={"name": "Branch Office", "owner": "Network team"},
    )
    assert site.status_code == 201
    site_id = site.json()["site_id"]
    token = client.post(
        "/api/enrollments",
        json={"label": "Branch Probe", "site_id": site_id},
    )
    assert token.status_code == 201
    enrolled = enroll_agent(client, token.json()["enrollment_token"])
    probe = client.get(f"/api/agents/{enrolled['agent_id']}").json()
    assert probe["site_id"] == site_id
    assert probe["site_name"] == "Branch Office"
    assert probe["approved_scopes"] == []


def test_scope_requires_real_approval_and_public_range_acknowledgment(
    client: TestClient,
) -> None:
    site_id = client.post("/api/sites", json={"name": "Test Approval"}).json()[
        "site_id"
    ]
    endpoint = f"/api/sites/{site_id}/scopes"
    assert (
        client.post(
            endpoint, json={"cidr": "192.168.1.0/24", "label": "LAN"}
        ).status_code
        == 422
    )
    assert (
        client.post(
            endpoint,
            json=approved_scope(
                "192.168.1.0/24", "LAN", approval_reference="ACTUAL_REFERENCE"
            ),
        ).status_code
        == 422
    )
    assert (
        client.post(
            endpoint,
            json=approved_scope("192.168.1.0/24", "LAN", authorization_confirmed=False),
        ).status_code
        == 422
    )
    assert (
        client.post(
            endpoint,
            json=approved_scope("192.168.1.0/24", "LAN", expires_on="2000-01-01"),
        ).status_code
        == 422
    )
    assert (
        client.post(
            endpoint,
            json=approved_scope(
                "172.168.1.0/24", "Public test LAN", public_range_authorized=False
            ),
        ).status_code
        == 422
    )
    assert client.get(endpoint).json() == []


def test_expiry_blocks_queued_discovery_and_diagnostics(
    client: TestClient, settings: Settings
) -> None:
    agent = authenticated_agent(client)
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    queued = client.post(
        f"/api/agents/{agent['agent_id']}/discover",
        json={"authorization_confirmed": True},
    )
    assert queued.status_code == 202
    scope = client.get(f"/api/sites/{site_id}/scopes").json()[0]
    store = JsonStore(settings.runtime_data_dir)
    saved = store.read("approved-scopes", scope["scope_id"])
    assert saved is not None
    saved["expires_on"] = (datetime.now(UTC).date() - timedelta(days=1)).isoformat()
    store.write("approved-scopes", scope["scope_id"], saved)

    assert (
        client.get(f"/api/sites/{site_id}/scopes").json()[0]["approval_status"]
        == "expired"
    )
    assert (
        client.get(f"/api/agents/{agent['agent_id']}").json()["approved_scopes"] == []
    )
    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}
    assert client.get("/agent/commands/next", headers=authorization).status_code == 204
    assert (
        client.post(
            f"/api/agents/{agent['agent_id']}/diagnostics",
            json={"target_ip": "192.168.1.2", "diagnostic_type": "ping"},
        ).status_code
        == 422
    )

    renewed = client.post(
        f"/api/sites/{site_id}/scopes",
        json=approved_scope("192.168.1.0/24", "Renewed LAN"),
    )
    assert renewed.status_code == 201, renewed.text
    assert renewed.json()["scope_id"] == scope["scope_id"]
    assert renewed.json()["approval_status"] == "active"
    assert len(client.get(f"/api/sites/{site_id}/scopes").json()) == 1


def test_legacy_scope_is_visible_but_inactive_until_renewed(
    client: TestClient, settings: Settings
) -> None:
    agent = authenticated_agent(client)
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    scope = client.get(f"/api/sites/{site_id}/scopes").json()[0]
    store = JsonStore(settings.runtime_data_dir)
    saved = store.read("approved-scopes", scope["scope_id"])
    assert saved is not None
    for key in (
        "owner",
        "approval_reference",
        "approved_by",
        "expires_on",
        "authorization_confirmed",
    ):
        saved.pop(key, None)
    store.write("approved-scopes", scope["scope_id"], saved)
    assert (
        client.get(f"/api/sites/{site_id}/scopes").json()[0]["approval_status"]
        == "needs_review"
    )
    assert (
        client.get(f"/api/agents/{agent['agent_id']}").json()[
            "approved_discovery_scopes"
        ]
        == []
    )
    assert (
        client.post(
            f"/api/agents/{agent['agent_id']}/discover",
            json={"authorization_confirmed": True},
        ).status_code
        == 422
    )
    renewed = client.post(
        f"/api/sites/{site_id}/scopes",
        json=approved_scope("192.168.1.0/24", "Reviewed LAN"),
    )
    assert renewed.status_code == 201, renewed.text
    assert renewed.json()["scope_id"] == scope["scope_id"]


def test_removed_approval_blocks_discovery_diagnostic_and_queued_job(
    client: TestClient,
) -> None:
    agent = authenticated_agent(client)
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    queued = client.post(
        f"/api/agents/{agent['agent_id']}/discover",
        json={"authorization_confirmed": True},
    )
    assert queued.status_code == 202
    scope_id = client.get(f"/api/sites/{site_id}/scopes").json()[0]["scope_id"]
    assert client.delete(f"/api/sites/{site_id}/scopes/{scope_id}").status_code == 204
    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}
    assert client.get("/agent/commands/next", headers=authorization).status_code == 204
    assert (
        client.get(f"/api/discoveries/{queued.json()['discovery_id']}").json()["status"]
        == "cancelled"
    )
    assert (
        client.post(
            f"/api/agents/{agent['agent_id']}/discover",
            json={"authorization_confirmed": True},
        ).status_code
        == 422
    )
    assert (
        client.post(
            f"/api/agents/{agent['agent_id']}/diagnostics",
            json={"target_ip": "192.168.1.2", "diagnostic_type": "ping"},
        ).status_code
        == 422
    )


def test_approval_is_bound_to_probe_site(client: TestClient) -> None:
    agent = authenticated_agent(client)
    own_site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    own_scope_id = client.get(f"/api/sites/{own_site_id}/scopes").json()[0]["scope_id"]
    assert (
        client.delete(f"/api/sites/{own_site_id}/scopes/{own_scope_id}").status_code
        == 204
    )
    other_site = client.post("/api/sites", json={"name": "Other Branch"}).json()
    assert (
        client.post(
            f"/api/sites/{other_site['site_id']}/scopes",
            json=approved_scope("192.168.1.0/24", "Other LAN"),
        ).status_code
        == 201
    )

    probe = client.get(f"/api/agents/{agent['agent_id']}").json()
    assert probe["approved_discovery_scopes"] == []
    assert (
        client.post(
            f"/api/agents/{agent['agent_id']}/discover",
            json={"authorization_confirmed": True},
        ).status_code
        == 422
    )
    assert (
        client.post(
            f"/api/agents/{agent['agent_id']}/diagnostics",
            json={"target_ip": "192.168.1.2", "diagnostic_type": "ping"},
        ).status_code
        == 422
    )


def test_exclusion_and_profile_apply_to_selected_scans(client: TestClient) -> None:
    agent, discovery = completed_discovery(client)
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    scope_id = client.get(f"/api/sites/{site_id}/scopes").json()[0]["scope_id"]
    assert client.delete(f"/api/sites/{site_id}/scopes/{scope_id}").status_code == 204
    approved = client.post(
        f"/api/sites/{site_id}/scopes",
        json=approved_scope(
            "192.168.1.0/24",
            "Limited LAN",
            exclusions=["192.168.1.11/32"],
            scan_profiles=["inventory"],
        ),
    )
    assert approved.status_code == 201
    endpoint = f"/api/discoveries/{discovery['discovery_id']}/scan"
    selected = ["selected-device-0001"]
    assert (
        client.post(
            endpoint,
            json={
                "device_ids": selected,
                "profile": "standard",
                "authorization_confirmed": True,
            },
        ).status_code
        == 422
    )
    assert (
        client.post(
            endpoint,
            json={
                "device_ids": selected,
                "profile": "inventory",
                "authorization_confirmed": True,
            },
        ).status_code
        == 202
    )
    assert (
        client.post(
            endpoint,
            json={
                "device_ids": ["selected-device-0002"],
                "profile": "inventory",
                "authorization_confirmed": True,
            },
        ).status_code
        == 422
    )


def test_excluded_host_is_not_accepted_in_discovery_result(
    client: TestClient, settings: Settings
) -> None:
    agent = authenticated_agent(client)
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    scope_id = client.get(f"/api/sites/{site_id}/scopes").json()[0]["scope_id"]
    assert client.delete(f"/api/sites/{site_id}/scopes/{scope_id}").status_code == 204
    assert (
        client.post(
            f"/api/sites/{site_id}/scopes",
            json=approved_scope(
                "192.168.1.0/24",
                "LAN with exception",
                exclusions=["192.168.1.11/32"],
                scan_profiles=["inventory"],
            ),
        ).status_code
        == 201
    )
    endpoint = f"/api/agents/{agent['agent_id']}/discover"
    created = client.post(endpoint, json={"authorization_confirmed": True})
    assert created.status_code == 202, created.text
    discovery_id = created.json()["discovery_id"]
    credential = {"Authorization": f"Bearer {agent['agent_credential']}"}
    claimed = client.get("/agent/commands/next", headers=credential)
    assert claimed.status_code == 200, claimed.text
    assert claimed.json()["payload"]["scope_policy"][0]["exclusions"] == [
        "192.168.1.11/32"
    ]
    now = datetime.now(UTC).isoformat()
    payload = {
        "schema_version": "1.0",
        "message_type": "discovery.result",
        "discovery_id": discovery_id,
        "agent_id": agent["agent_id"],
        "network": "192.168.1.0/24",
        "status": "completed",
        "started_at": now,
        "completed_at": now,
        "devices": [
            {
                "device_id": "excluded-device-0001",
                "ip": "192.168.1.11",
                "hostname": None,
                "status": "up",
                "discovery_reason": "arp-response",
                "is_agent": False,
                "first_seen": now,
                "last_seen": now,
            }
        ],
    }
    upload = f"/agent/discoveries/{discovery_id}/devices"
    rejected = client.post(upload, headers=credential, json=payload)
    assert rejected.status_code == 422, rejected.text
    assert client.get(f"/api/discoveries/{discovery_id}").json()["devices"] == []
    assert client.get("/api/assets").json()["total"] == 0
    events = [
        json.loads(line)
        for line in (settings.runtime_data_dir / "activity" / "activity.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    denial = [
        event for event in events if event["event_type"] == "security.request_denied"
    ][-1]
    assert denial["actor_type"] == "agent"
    assert denial["actor_id"] == agent["agent_id"]
    assert denial["details"]["status"] == 422
    assert agent["agent_credential"] not in json.dumps(denial)
    assert "192.168.1.11" not in json.dumps(denial)

    payload["devices"][0]["ip"] = "192.168.1.12"
    accepted = client.post(upload, headers=credential, json=payload)
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["devices"][0]["ip"] == "192.168.1.12"


def test_claimed_discovery_cannot_upload_after_scope_revocation(
    client: TestClient,
) -> None:
    agent = authenticated_agent(client)
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    created = client.post(
        f"/api/agents/{agent['agent_id']}/discover",
        json={"authorization_confirmed": True},
    )
    assert created.status_code == 202
    credential = {"Authorization": f"Bearer {agent['agent_credential']}"}
    assert client.get("/agent/commands/next", headers=credential).status_code == 200
    scope_id = client.get(f"/api/sites/{site_id}/scopes").json()[0]["scope_id"]
    assert client.delete(f"/api/sites/{site_id}/scopes/{scope_id}").status_code == 204
    now = datetime.now(UTC).isoformat()
    discovery_id = created.json()["discovery_id"]
    control = client.get(
        f"/agent/discoveries/{discovery_id}/control", headers=credential
    )
    assert control.status_code == 200
    assert control.json()["cancel_requested"] is True
    rejected = client.post(
        f"/agent/discoveries/{discovery_id}/devices",
        headers=credential,
        json={
            "schema_version": "1.0",
            "message_type": "discovery.result",
            "discovery_id": discovery_id,
            "agent_id": agent["agent_id"],
            "network": "192.168.1.0/24",
            "status": "completed",
            "started_at": now,
            "completed_at": now,
            "devices": [],
        },
    )
    assert rejected.status_code == 422, rejected.text
    assert client.get(f"/api/discoveries/{discovery_id}").json()["devices"] == []
