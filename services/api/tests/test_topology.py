from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient
from test_discovery_flow import authenticated_agent


def _device(
    number: int,
    chassis: str,
    *,
    neighbors: list[dict] | None = None,
    observed_at: str,
) -> dict:
    return {
        "device_id": f"topology-device-{number:04d}",
        "ip": f"192.168.1.{number + 9}",
        "hostname": f"switch-{number}",
        "mac": f"00:11:22:33:44:{number:02x}",
        "status": "up",
        "discovery_reason": "arp-response",
        "is_agent": False,
        "first_seen": observed_at,
        "last_seen": observed_at,
        "lldp_chassis_subtype": 4,
        "lldp_chassis_id": chassis,
        "lldp_collected": True,
        "lldp_neighbors": neighbors or [],
    }


def _neighbor(chassis: str, *, local_port: str = "Gi1/0/1") -> dict:
    return {
        "local_port": local_port,
        "remote_chassis_subtype": 4,
        "remote_chassis_id": chassis,
        "remote_port": "Gi0/1",
        "remote_system_name": "edge-switch",
    }


def _observe(client: TestClient, agent_id: str, devices: list[dict], at: str) -> None:
    client.app.state.asset_service.observe_discovery(
        {
            "discovery_id": str(uuid4()),
            "agent_id": agent_id,
            "created_at": at,
            "completed_at": at,
            "devices": devices,
        }
    )


def test_uploaded_lldp_builds_site_graph_with_unresolved_neighbor(
    client: TestClient,
) -> None:
    agent = authenticated_agent(client)
    created = client.post(
        f"/api/agents/{agent['agent_id']}/discover",
        json={"authorization_confirmed": True},
    ).json()
    now = datetime.now(UTC).isoformat()
    first = _device(
        1,
        "001122334401",
        neighbors=[
            _neighbor("001122334402"),
            _neighbor("aabbccddeeff", local_port="Gi1/0/2"),
        ],
        observed_at=now,
    )
    second = _device(2, "001122334402", observed_at=now)
    response = client.post(
        f"/agent/discoveries/{created['discovery_id']}/devices",
        headers={"Authorization": f"Bearer {agent['agent_credential']}"},
        json={
            "schema_version": "1.0",
            "message_type": "discovery.result",
            "discovery_id": created["discovery_id"],
            "agent_id": agent["agent_id"],
            "network": "192.168.1.0/24",
            "status": "completed",
            "started_at": now,
            "completed_at": now,
            "devices": [first, second],
            "error": None,
        },
    )
    assert response.status_code == 200, response.text
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    graph_response = client.get("/api/assets/topology", params={"site_id": site_id})
    assert graph_response.status_code == 200, graph_response.text
    graph = graph_response.json()
    assert graph["observed_assets"] == 2
    assert graph["total_links"] == 2
    assert len(graph["nodes"]) == 3
    assert sum(node["observed_only"] for node in graph["nodes"]) == 1
    assert any(link["target"].startswith("asset:") for link in graph["links"])
    assert all(
        link["discovery_id"] == created["discovery_id"] for link in graph["links"]
    )
    assert (
        client.get("/api/assets/topology", params={"site_id": uuid4()}).status_code
        == 404
    )


def test_graph_never_resolves_chassis_across_sites_or_ambiguous_ids(
    client: TestClient,
) -> None:
    agent = authenticated_agent(client)
    now = datetime.now(UTC).isoformat()
    _observe(
        client,
        agent["agent_id"],
        [
            _device(
                1,
                "001122334401",
                neighbors=[_neighbor("aabbccddeeff")],
                observed_at=now,
            )
        ],
        now,
    )
    other_site = client.post("/api/sites", json={"name": "Other site"}).json()
    other_agent = str(uuid4())
    client.app.state.store.write(
        "agents",
        other_agent,
        {"agent_id": other_agent, "site_id": other_site["site_id"]},
    )
    _observe(client, other_agent, [_device(2, "aabbccddeeff", observed_at=now)], now)
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    graph = client.get("/api/assets/topology", params={"site_id": site_id}).json()
    assert graph["links"][0]["target"].startswith("neighbor:")
    assert all(node["ip"] != "192.168.1.11" for node in graph["nodes"])

    _observe(
        client,
        agent["agent_id"],
        [
            _device(2, "aabbccddeeff", observed_at=now),
            _device(3, "aabbccddeeff", observed_at=now),
        ],
        now,
    )
    graph = client.get("/api/assets/topology", params={"site_id": site_id}).json()
    assert graph["links"][0]["target"].startswith("neighbor:")


def test_old_snapshot_is_stale_and_new_empty_snapshot_clears_link(
    client: TestClient,
) -> None:
    agent = authenticated_agent(client)
    old = (datetime.now(UTC) - timedelta(days=8)).isoformat()
    now = datetime.now(UTC).isoformat()
    _observe(
        client,
        agent["agent_id"],
        [
            _device(
                1,
                "001122334401",
                neighbors=[_neighbor("aabbccddeeff")],
                observed_at=old,
            )
        ],
        old,
    )
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    hidden = client.get("/api/assets/topology", params={"site_id": site_id}).json()
    assert hidden["links"] == []
    assert hidden["stale_hidden"] == 1
    stale = client.get(
        "/api/assets/topology", params={"site_id": site_id, "include_stale": True}
    ).json()
    assert stale["links"][0]["stale"] is True
    _observe(
        client, agent["agent_id"], [_device(1, "001122334401", observed_at=now)], now
    )
    current = client.get(
        "/api/assets/topology", params={"site_id": site_id, "include_stale": True}
    ).json()
    assert current["links"] == []
    assert current["observed_assets"] == 1
