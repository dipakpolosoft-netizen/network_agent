from __future__ import annotations

from fastapi.testclient import TestClient

from forgesec_api.assets.service import normalize_mac


def test_non_unicast_or_empty_mac_cannot_be_an_asset_identity(
    client: TestClient,
) -> None:
    assert normalize_mac("00:00:00:00:00:00") is None
    assert normalize_mac("ff:ff:ff:ff:ff:ff") is None
    assert normalize_mac("01:00:5e:00:00:01") is None
    assert normalize_mac("02-11-22-33-44-55") == "02:11:22:33:44:55"

    service = client.app.state.asset_service
    site_id = "00000000-0000-0000-0000-000000000001"
    agent_id = "00000000-0000-0000-0000-000000000002"
    first = service._observe(
        site_id=site_id,
        agent_id=agent_id,
        source_type="discovery",
        source_id="00000000-0000-0000-0000-000000000011",
        device={
            "device_id": "host-1",
            "ip": "192.0.2.10",
            "mac": "00:00:00:00:00:00",
        },
        observed_at="2026-09-29T10:00:00Z",
    )
    second = service._observe(
        site_id=site_id,
        agent_id=agent_id,
        source_type="discovery",
        source_id="00000000-0000-0000-0000-000000000012",
        device={
            "device_id": "host-2",
            "ip": "192.0.2.11",
            "mac": "00:00:00:00:00:00",
        },
        observed_at="2026-09-29T10:01:00Z",
    )
    repeated = service._observe(
        site_id=site_id,
        agent_id=agent_id,
        source_type="discovery",
        source_id="00000000-0000-0000-0000-000000000013",
        device={
            "device_id": "host-1",
            "ip": "192.0.2.10",
            "mac": "00:00:00:00:00:00",
        },
        observed_at="2026-09-29T10:02:00Z",
    )

    assert first != second
    assert repeated == first
    assert client.get(f"/api/assets/{first}").json()["observation_count"] == 2
    assert client.get(f"/api/assets/{first}").json()["mac"] is None


def test_asset_keeps_stronger_identity_until_better_evidence_arrives(
    client: TestClient,
) -> None:
    service = client.app.state.asset_service
    site_id = "00000000-0000-0000-0000-000000000001"
    agent_id = "00000000-0000-0000-0000-000000000002"
    device = {
        "device_id": "host-1",
        "ip": "192.0.2.10",
        "mac": "00:11:22:33:44:55",
        "hostname": "core-switch",
        "vendor": "Cisco",
        "device_type": "switch",
        "classification_confidence": 0.9,
    }
    first = service._observe(
        site_id=site_id,
        agent_id=agent_id,
        source_type="discovery",
        source_id="00000000-0000-0000-0000-000000000011",
        device=device,
        observed_at="2026-09-28T10:00:00Z",
    )
    service._observe(
        site_id=site_id,
        agent_id=agent_id,
        source_type="scan",
        source_id="00000000-0000-0000-0000-000000000012",
        device=device,
        observed_at="2026-09-28T10:01:00Z",
        result={
            "status": "completed",
            "hostname": "core-switch.example.test",
            "device_type": "unknown",
            "classification_confidence": 0.0,
            "ports": [],
            "os_matches": [],
        },
    )
    asset = client.get(f"/api/assets/{first}").json()
    assert asset["hostname"] == "core-switch.example.test"
    assert asset["vendor"] == "Cisco"
    assert asset["device_type"] == "switch"
    assert asset["classification_confidence"] == 0.9

    service._observe(
        site_id=site_id,
        agent_id=agent_id,
        source_type="discovery",
        source_id="00000000-0000-0000-0000-000000000013",
        device={
            **device,
            "hostname": None,
            "vendor": None,
            "device_type": "router",
            "classification_confidence": 0.65,
        },
        observed_at="2026-09-28T10:02:00Z",
    )
    asset = client.get(f"/api/assets/{first}").json()
    assert asset["device_type"] == "switch"
    assert asset["hostname"] == "core-switch.example.test"
    assert asset["vendor"] == "Cisco"

    service._observe(
        site_id=site_id,
        agent_id=agent_id,
        source_type="discovery",
        source_id="00000000-0000-0000-0000-000000000016",
        device={**device, "device_type": "router", "classification_confidence": 0.9},
        observed_at="2026-09-28T10:02:30Z",
    )
    asset = client.get(f"/api/assets/{first}").json()
    assert asset["device_type"] == "switch"
    assert asset["classification_confidence"] == 0.9

    service._observe(
        site_id=site_id,
        agent_id=agent_id,
        source_type="discovery",
        source_id="00000000-0000-0000-0000-000000000014",
        device={**device, "device_type": "router", "classification_confidence": 0.95},
        observed_at="2026-09-28T10:03:00Z",
    )
    asset = client.get(f"/api/assets/{first}").json()
    assert asset["device_type"] == "router"
    assert asset["classification_confidence"] == 0.95
    assert asset["first_seen"] == "2026-09-28T10:00:00Z"
    assert asset["last_seen"] == "2026-09-28T10:03:00Z"

    service._observe(
        site_id=site_id,
        agent_id=agent_id,
        source_type="discovery",
        source_id="00000000-0000-0000-0000-000000000015",
        device={**device, "device_type": "firewall", "classification_confidence": 1.0},
        observed_at="2026-09-28T09:59:00Z",
    )
    asset = client.get(f"/api/assets/{first}").json()
    assert asset["device_type"] == "router"
    assert asset["last_seen"] == "2026-09-28T10:03:00Z"
