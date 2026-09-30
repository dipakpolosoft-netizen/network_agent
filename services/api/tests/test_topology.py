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
            "site_id": client.app.state.store.read("agents", agent_id)["site_id"],
            "created_at": at,
            "completed_at": at,
            "devices": devices,
        }
    )


def test_site_topology_lists_probe_without_inventing_lldp_link(
    client: TestClient,
) -> None:
    agent = authenticated_agent(client)
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    graph = client.get("/api/assets/topology", params={"site_id": site_id}).json()
    assert graph["nodes"] == []
    assert graph["links"] == []
    assert graph["total_links"] == 0
    assert len(graph["probes"]) == 1
    assert graph["probes"][0]["ip"] == "192.168.1.25"
    assert graph["probes"][0]["subnet"] == "192.168.1.0/24"

    other_site = client.post("/api/sites", json={"name": "Other site"}).json()
    other = client.get(
        "/api/assets/topology", params={"site_id": other_site["site_id"]}
    ).json()
    assert other["probes"] == []


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
    assert {link["match_method"] for link in graph["links"]} == {
        "chassis_id", "unresolved"
    }
    assert all(
        link["discovery_id"] == created["discovery_id"] for link in graph["links"]
    )
    assert all(link["probe_id"] == agent["agent_id"] for link in graph["links"])
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
            {
                **_device(3, "aabbccddeeff", observed_at=now),
                "mac": "aa:bb:cc:dd:ee:ff",
            },
        ],
        now,
    )
    graph = client.get("/api/assets/topology", params={"site_id": site_id}).json()
    assert graph["links"][0]["target"].startswith("neighbor:")
    assert graph["links"][0]["match_method"] == "unresolved"


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


def test_failed_lldp_read_keeps_last_success_and_mac_match_is_explicit(
    client: TestClient,
) -> None:
    agent = authenticated_agent(client)
    now = datetime.now(UTC)
    target = {
        **_device(2, "001122334402", observed_at=now.isoformat()),
        "mac": "aa:bb:cc:dd:ee:ff",
    }
    source = _device(
        1,
        "001122334401",
        neighbors=[_neighbor("aabbccddeeff")],
        observed_at=now.isoformat(),
    )
    _observe(client, agent["agent_id"], [source, target], now.isoformat())
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    graph = client.get("/api/assets/topology", params={"site_id": site_id}).json()
    assert graph["links"][0]["match_method"] == "mac"

    later = (now + timedelta(seconds=2)).isoformat()
    failed_read = {
        **_device(1, "001122334401", observed_at=later),
        "lldp_collected": False,
    }
    _observe(client, agent["agent_id"], [failed_read], later)
    graph = client.get("/api/assets/topology", params={"site_id": site_id}).json()
    assert graph["total_links"] == 1
    assert graph["links"][0]["match_method"] == "mac"


def test_current_lldp_neighbor_does_not_resolve_to_stale_identity(
    client: TestClient,
) -> None:
    agent = authenticated_agent(client)
    old = (datetime.now(UTC) - timedelta(days=8)).isoformat()
    now = datetime.now(UTC).isoformat()
    _observe(
        client, agent["agent_id"], [_device(2, "aabbccddeeff", observed_at=old)], old
    )
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
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    graph = client.get("/api/assets/topology", params={"site_id": site_id}).json()
    assert graph["total_links"] == 1
    assert graph["links"][0]["target"].startswith("neighbor:")
    assert graph["links"][0]["match_method"] == "unresolved"


def test_unresolved_chassis_reports_do_not_invent_a_shared_device(
    client: TestClient,
) -> None:
    agent = authenticated_agent(client)
    now = datetime.now(UTC)
    first = _device(
        1,
        "001122334401",
        neighbors=[
            _neighbor("aabbccddeeff"),
            _neighbor("aabbccddeeff", local_port="Gi1/0/2"),
        ],
        observed_at=now.isoformat(),
    )
    second = _device(
        2,
        "001122334402",
        neighbors=[_neighbor("aabbccddeeff")],
        observed_at=now.isoformat(),
    )
    _observe(client, agent["agent_id"], [first, second], now.isoformat())
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    graph = client.get("/api/assets/topology", params={"site_id": site_id}).json()
    unresolved = [
        link for link in graph["links"] if link["match_method"] == "unresolved"
    ]
    assert len(unresolved) == 3
    assert len({link["target"] for link in unresolved}) == 3
    assert sum(node["observed_only"] for node in graph["nodes"]) == 3
    assert all(link["target"].startswith("neighbor:") for link in unresolved)

    later = (now + timedelta(seconds=1)).isoformat()
    _observe(
        client,
        agent["agent_id"],
        [{**first, "first_seen": later, "last_seen": later}],
        later,
    )
    refreshed = client.get(
        "/api/assets/topology", params={"site_id": site_id}
    ).json()
    assert {link["target"] for link in refreshed["links"]} == {
        link["target"] for link in unresolved
    }


def test_self_matching_chassis_keeps_report_without_inventing_self_link(
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
                neighbors=[_neighbor("001122334401")],
                observed_at=now,
            )
        ],
        now,
    )
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    graph = client.get("/api/assets/topology", params={"site_id": site_id}).json()

    assert graph["total_links"] == 1
    assert graph["links"][0]["match_method"] == "unresolved"
    assert graph["links"][0]["source"].startswith("asset:")
    assert graph["links"][0]["target"].startswith("neighbor:")
    assert graph["links"][0]["source"] != graph["links"][0]["target"]


def test_legacy_invalid_asset_mac_cannot_resolve_lldp_neighbor(
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
                neighbors=[_neighbor("000000000000")],
                observed_at=now,
            ),
            _device(2, "001122334402", observed_at=now),
        ],
        now,
    )
    store = client.app.state.store
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    legacy = next(
        asset for asset in store.list("assets")
        if asset["last_ip"] == "192.168.1.11"
    )
    legacy["mac"] = "00:00:00:00:00:00"
    store.write("assets", legacy["asset_id"], legacy)

    graph = client.get("/api/assets/topology", params={"site_id": site_id}).json()
    assert graph["total_links"] == 1
    assert graph["links"][0]["match_method"] == "unresolved"
    assert graph["links"][0]["target"].startswith("neighbor:")


def test_reciprocal_lldp_reports_keep_both_sources(
    client: TestClient,
) -> None:
    agent = authenticated_agent(client)
    now = datetime.now(UTC).isoformat()
    _observe(
        client,
        agent["agent_id"],
        [
            _device(
                1, "001122334401",
                neighbors=[_neighbor("001122334402")],
                observed_at=now,
            ),
            _device(
                2, "001122334402",
                neighbors=[_neighbor("001122334401")],
                observed_at=now,
            ),
        ],
        now,
    )
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    graph = client.get("/api/assets/topology", params={"site_id": site_id}).json()
    assert graph["total_links"] == 2
    assert {link["match_method"] for link in graph["links"]} == {"chassis_id"}
    assert len({link["reported_by"] for link in graph["links"]}) == 2
    assert len(
        {
            frozenset((link["source"], link["target"]))
            for link in graph["links"]
        }
    ) == 1


def test_latest_discovery_breaks_equal_timestamp_snapshot_tie(
    client: TestClient,
) -> None:
    agent = authenticated_agent(client)
    now = datetime.now(UTC).isoformat()
    first = _device(
        1,
        "001122334401",
        neighbors=[_neighbor("aabbccddeeff")],
        observed_at=now,
    )
    _observe(client, agent["agent_id"], [first], now)
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    before = client.get("/api/assets/topology", params={"site_id": site_id}).json()
    assert before["total_links"] == 1

    same_instant = now.replace("+00:00", "Z")
    _observe(
        client,
        agent["agent_id"],
        [{**first, "lldp_neighbors": []}],
        same_instant,
    )
    after = client.get("/api/assets/topology", params={"site_id": site_id}).json()
    assert after["total_links"] == 0
    assert after["observed_assets"] == 1
