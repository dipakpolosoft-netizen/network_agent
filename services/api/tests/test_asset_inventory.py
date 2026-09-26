from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from test_scan_flow import completed_discovery

from forgesec_api.main import create_app
from forgesec_api.settings import Settings


def test_discovery_and_scan_build_durable_asset_history(client: TestClient) -> None:
    agent, discovery = completed_discovery(client)
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    listed = client.get("/api/assets", params={"site_id": site_id}).json()
    assert listed["total"] == 2
    first = next(item for item in listed["items"] if item["last_ip"] == "192.168.1.10")
    assert first["mac"] == "00:11:22:33:44:01"
    assert first["observation_count"] == 1
    assert first["last_scan_id"] is None

    annotation = client.patch(
        f"/api/assets/{first['asset_id']}",
        json={
            "display_name": "Core switch",
            "owner": "Network team",
            "criticality": "high",
            "tags": ["production", "core"],
        },
    )
    assert annotation.status_code == 200
    scan = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": ["selected-device-0001"],
            "profile": "standard",
            "authorization_confirmed": True,
        },
    ).json()
    now = datetime.now(UTC).isoformat()
    payload = {
        "schema_version": "1.0",
        "message_type": "host_scan.result",
        "scan_id": scan["scan_id"],
        "agent_id": agent["agent_id"],
        "device_id": "selected-device-0001",
        "ip": "192.168.1.10",
        "status": "completed",
        "started_at": now,
        "completed_at": now,
        "hostname": "switch-core.example.test",
        "device_type": "switch",
        "classification_confidence": 0.95,
        "ports": [
            {
                "protocol": "tcp",
                "port": 22,
                "state": "open",
                "service": "ssh",
                "product": "OpenSSH",
                "version": "9.0",
            }
        ],
        "os_matches": [{"name": "Linux", "accuracy": 88}],
        "exposure_flags": [],
        "error": None,
    }
    headers = {"Authorization": f"Bearer {agent['agent_credential']}"}
    path = f"/agent/scans/{scan['scan_id']}/hosts/selected-device-0001/result"
    assert client.post(path, headers=headers, json=payload).status_code == 200
    assert client.post(path, headers=headers, json=payload).status_code == 200
    updated = client.get(f"/api/assets/{first['asset_id']}").json()
    assert updated["display_name"] == "Core switch"
    assert updated["owner"] == "Network team"
    assert updated["criticality"] == "high"
    assert updated["tags"] == ["production", "core"]
    assert updated["hostname"] == "switch-core.example.test"
    assert updated["open_port_count"] == 1
    assert updated["ports"][0]["service"] == "ssh"
    assert updated["os_name"] == "Linux"
    assert updated["scan_count"] == 1
    assert updated["observation_count"] == 2
    observations = client.get(f"/api/assets/{first['asset_id']}/observations").json()
    assert {item["source_type"] for item in observations} == {"discovery", "scan"}
    searched = client.get("/api/assets", params={"query": "Core switch"}).json()
    assert searched["total"] == 1
    assert client.get("/api/assets", params={"limit": 1}).json()["total"] == 2
    assert len(client.get("/api/assets", params={"limit": 1}).json()["items"]) == 1


def test_asset_port_sample_keeps_observed_ssh_for_inventory(
    client: TestClient,
) -> None:
    agent, discovery = completed_discovery(client, device_count=1)
    scan = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": ["selected-device-0001"],
            "profile": "standard",
            "authorization_confirmed": True,
        },
    ).json()
    now = datetime.now(UTC).isoformat()
    ports = [
        {"protocol": "tcp", "port": 10000 + index, "state": "open"}
        for index in range(32)
    ] + [{"protocol": "tcp", "port": 22, "state": "open", "service": "ssh"}]
    response = client.post(
        f"/agent/scans/{scan['scan_id']}/hosts/selected-device-0001/result",
        headers={"Authorization": f"Bearer {agent['agent_credential']}"},
        json={
            "schema_version": "1.0",
            "message_type": "host_scan.result",
            "scan_id": scan["scan_id"],
            "agent_id": agent["agent_id"],
            "device_id": "selected-device-0001",
            "ip": "192.168.1.10",
            "status": "completed",
            "started_at": now,
            "completed_at": now,
            "ports": ports,
            "os_matches": [],
            "exposure_flags": [],
            "error": None,
        },
    )
    assert response.status_code == 200
    asset = client.get("/api/assets").json()["items"][0]
    assert asset["open_port_count"] == 33
    assert len(asset["ports"]) == 32
    assert asset["ports"][-1]["port"] == 22


def test_mac_identity_is_site_scoped_and_ip_reuse_does_not_overwrite(
    client: TestClient,
) -> None:
    agent, discovery = completed_discovery(client, device_count=1)
    service = client.app.state.asset_service
    first = client.get("/api/assets").json()["items"][0]
    record = client.app.state.store.read("discoveries", discovery["discovery_id"])
    moved = dict(record)
    moved["discovery_id"] = "00000000-0000-0000-0000-000000000111"
    moved["devices"] = [dict(record["devices"][0], ip="192.168.1.20")]
    service.observe_discovery(moved)
    asset = client.get(f"/api/assets/{first['asset_id']}").json()
    assert asset["last_ip"] == "192.168.1.20"
    assert asset["ip_history"] == ["192.168.1.10", "192.168.1.20"]

    reused = dict(record)
    reused["discovery_id"] = "00000000-0000-0000-0000-000000000222"
    reused["devices"] = [
        dict(record["devices"][0], ip="192.168.1.20", mac="AA:BB:CC:DD:EE:FF")
    ]
    service.observe_discovery(reused)
    assets = client.get("/api/assets").json()["items"]
    assert len(assets) == 2
    assert {item["mac"] for item in assets} == {
        "00:11:22:33:44:01",
        "aa:bb:cc:dd:ee:ff",
    }
    other_site = client.post("/api/sites", json={"name": "Remote office"}).json()
    other_agent_id = "00000000-0000-0000-0000-000000000333"
    client.app.state.store.write(
        "agents",
        other_agent_id,
        {"agent_id": other_agent_id, "site_id": other_site["site_id"]},
    )
    remote = dict(record)
    remote["agent_id"] = other_agent_id
    remote["discovery_id"] = "00000000-0000-0000-0000-000000000444"
    service.observe_discovery(remote)
    assert (
        client.get("/api/assets", params={"site_id": other_site["site_id"]}).json()[
            "total"
        ]
        == 1
    )
    assert client.get("/api/assets").json()["total"] == 3


def test_backfill_rebuilds_legacy_inventory_once(
    client: TestClient, settings: Settings
) -> None:
    _, discovery = completed_discovery(client, device_count=1)
    store = client.app.state.store
    for collection in (
        "assets",
        "asset-observations",
        "asset-mac-index",
        "asset-ip-index",
        "asset-migrations",
    ):
        for path in (store.root / collection).glob("*.json"):
            store.delete(collection, path.stem)
    with TestClient(create_app(settings)) as restarted:
        asset = restarted.get("/api/assets").json()["items"][0]
        assert asset["last_discovery_id"] == discovery["discovery_id"]
        assert asset["observation_count"] == 1
    with TestClient(create_app(settings)) as restarted_again:
        assert restarted_again.get("/api/assets").json()["total"] == 1
        assert (
            restarted_again.get("/api/assets").json()["items"][0]["observation_count"]
            == 1
        )


def test_viewer_cannot_change_asset_annotations(settings: Settings) -> None:
    app = create_app(replace(settings, auth_required=True))
    with TestClient(app) as client:
        admin = app.state.auth_service.create_user(
            "admin@example.test", "correct horse battery", "admin"
        )
        assert admin["role"] == "admin"
        app.state.auth_service.create_user(
            "viewer@example.test", "another correct password", "viewer"
        )
        admin_session = client.post(
            "/api/auth/login",
            json={"email": "admin@example.test", "password": "correct horse battery"},
        ).json()
        site = client.post(
            "/api/sites",
            headers={"X-CSRF-Token": admin_session["csrf_token"]},
            json={"name": "QA"},
        ).json()
        agent_id = "00000000-0000-0000-0000-000000000001"
        app.state.store.write(
            "agents", agent_id, {"agent_id": agent_id, "site_id": site["site_id"]}
        )
        app.state.asset_service._observe(
            site_id=site["site_id"],
            agent_id=agent_id,
            source_type="discovery",
            source_id="00000000-0000-0000-0000-000000000002",
            device={"device_id": "device-001", "ip": "10.1.1.1", "status": "up"},
            observed_at=datetime.now(UTC).isoformat(),
        )
        asset_id = client.get("/api/assets").json()["items"][0]["asset_id"]
        viewer = client.post(
            "/api/auth/login",
            json={
                "email": "viewer@example.test",
                "password": "another correct password",
            },
        ).json()
        assert (
            client.patch(
                f"/api/assets/{asset_id}",
                headers={"X-CSRF-Token": viewer["csrf_token"]},
                json={"owner": "Not permitted"},
            ).status_code
            == 403
        )
