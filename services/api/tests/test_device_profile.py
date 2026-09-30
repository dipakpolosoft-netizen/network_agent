from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient
from test_scan_flow import completed_discovery


def _first_asset(client: TestClient) -> dict:
    return next(
        item
        for item in client.get("/api/assets").json()["items"]
        if item["last_ip"] == "192.168.1.10"
    )


def test_device_profile_preserves_provenance_without_contact_fields(
    client: TestClient,
) -> None:
    _agent, discovery = completed_discovery(client)
    asset = _first_asset(client)
    response = client.get(f"/api/assets/{asset['asset_id']}/device-profile")
    assert response.status_code == 200
    profile = response.json()
    assert profile["discovery"]["discovery_id"] == discovery["discovery_id"]
    assert profile["discovery"]["device_type"] == "switch"
    assert profile["discovery"]["classification_confidence"] == 0.9
    assert profile["discovery"]["discovery_reason"] == "arp-response"
    assert profile["snmp"]["name"] == "switch-1"
    assert profile["snmp"]["reported_interface_count"] == 48
    assert profile["snmp"]["interfaces"][0]["name"] == "Gi1/0/1"
    assert profile["snmp"]["latest_discovery"] is True
    assert "contact" not in profile["snmp"]
    assert "location" not in profile["snmp"]
    assert client.get(f"/api/assets/{uuid4()}/device-profile").status_code == 404


def test_old_observation_recovers_from_exact_source_and_stale_snmp_is_labeled(
    client: TestClient,
) -> None:
    agent, _discovery = completed_discovery(client)
    asset = _first_asset(client)
    store = client.app.state.store
    observation = next(
        item
        for item in store.list("asset-observations")
        if item["asset_id"] == asset["asset_id"]
    )
    for key in (
        "vendor",
        "classification_confidence",
        "discovery_reason",
        "latency_ms",
        "snmp_name",
        "snmp_description",
        "snmp_object_id",
        "snmp_uptime_seconds",
        "snmp_interface_count",
        "snmp_interfaces",
        "snmp_interfaces_limited",
    ):
        observation.pop(key, None)
    store.write("asset-observations", observation["observation_id"], observation)
    recovered = client.get(f"/api/assets/{asset['asset_id']}/device-profile").json()
    assert recovered["snmp"]["name"] == "switch-1"
    assert recovered["discovery"]["discovery_reason"] == "arp-response"

    now = (datetime.now(UTC) + timedelta(seconds=1)).isoformat()
    client.app.state.asset_service.observe_discovery(
        {
            "discovery_id": str(uuid4()),
            "agent_id": agent["agent_id"],
            "site_id": asset["site_id"],
            "created_at": now,
            "completed_at": now,
            "devices": [
                {
                    "device_id": "selected-device-0001",
                    "ip": "192.168.1.10",
                    "mac": "00:11:22:33:44:01",
                    "hostname": "new-name",
                    "status": "up",
                    "discovery_reason": "icmp-response",
                    "is_agent": False,
                }
            ],
        }
    )
    updated = client.get(f"/api/assets/{asset['asset_id']}/device-profile").json()
    assert updated["discovery"]["hostname"] == "new-name"
    assert updated["snmp"]["name"] == "switch-1"
    assert updated["snmp"]["latest_discovery"] is False

    client.app.state.asset_service.observe_discovery(
        {
            "discovery_id": str(uuid4()),
            "agent_id": agent["agent_id"],
            "site_id": asset["site_id"],
            "created_at": now,
            "completed_at": now,
            "devices": [
                {
                    "device_id": "replacement-device",
                    "ip": "192.168.1.10",
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "hostname": "replacement",
                    "status": "up",
                    "is_agent": False,
                }
            ],
        }
    )
    replacement = next(
        item
        for item in client.get("/api/assets").json()["items"]
        if item["mac"] == "aa:bb:cc:dd:ee:ff"
    )
    assert replacement["asset_id"] != asset["asset_id"]
    assert (
        client.get(f"/api/assets/{replacement['asset_id']}/device-profile").json()[
            "snmp"
        ]
        is None
    )


def test_interface_snapshot_is_bounded(client: TestClient) -> None:
    agent, _discovery = completed_discovery(client)
    asset = _first_asset(client)
    now = (datetime.now(UTC) + timedelta(seconds=1)).isoformat()
    client.app.state.asset_service.observe_discovery(
        {
            "discovery_id": str(uuid4()),
            "agent_id": agent["agent_id"],
            "site_id": asset["site_id"],
            "created_at": now,
            "completed_at": now,
            "devices": [
                {
                    "device_id": "selected-device-0001",
                    "ip": "192.168.1.10",
                    "mac": "00:11:22:33:44:01",
                    "status": "up",
                    "snmp_interface_count": 70,
                    "snmp_interfaces": [
                        {"index": index, "name": f"Gi{index}"} for index in range(1, 71)
                    ],
                }
            ],
        }
    )
    profile = client.get(f"/api/assets/{asset['asset_id']}/device-profile").json()
    assert profile["snmp"]["reported_interface_count"] == 70
    assert len(profile["snmp"]["interfaces"]) == 64
    assert profile["snmp"]["interfaces_limited"] is True
