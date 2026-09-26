from __future__ import annotations

from fastapi.testclient import TestClient
from test_discovery_flow import authenticated_agent
from test_enrollment_flow import enroll_agent
from test_scan_flow import completed_discovery


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
            json={"cidr": "192.168.1.0/24", "label": "Other LAN"},
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
        json={
            "cidr": "192.168.1.0/24",
            "label": "Limited LAN",
            "exclusions": ["192.168.1.11/32"],
            "scan_profiles": ["inventory"],
        },
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
