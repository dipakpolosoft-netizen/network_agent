from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient


def test_asset_history_compares_only_matching_complete_host_evidence(
    client: TestClient,
) -> None:
    site_id = client.post("/api/sites", json={"name": "History pilot"}).json()[
        "site_id"
    ]
    agent_id = str(uuid4())
    service = client.app.state.asset_service
    store = client.app.state.store
    device_id = "stable-mac-device"
    ids: dict[str, str] = {}
    asset_id: str | None = None
    minute = 0

    def observe(
        label: str,
        ip: str,
        ports: list[int],
        *,
        status: str = "completed",
        profile: str = "standard",
        plan: dict | None = None,
        missing_plan: bool = False,
        probe_id: str = agent_id,
    ) -> None:
        nonlocal asset_id, minute
        minute += 1
        scan_id = ids[label] = str(uuid4())
        observed_at = f"2026-09-29T10:{minute:02d}:00+00:00"
        result = {
            "device_id": device_id,
            "ip": ip,
            "status": status,
            "hostname": "switch.example.test",
            "device_type": "switch",
            "classification_confidence": 0.9,
            "ports": [
                {"protocol": "tcp", "port": port, "state": "open"}
                for port in ports
            ],
            "os_matches": [],
        }
        store.write(
            "scans",
            scan_id,
            {
                "scan_id": scan_id,
                "site_id": site_id,
                "agent_id": probe_id,
                "profile": profile,
                "profile_plan": (
                    None if missing_plan else
                    {"tcp_top_ports": 1000} if plan is None else plan
                ),
                "results": [result],
            },
        )
        asset_id = service._observe(
            site_id=site_id,
            agent_id=probe_id,
            source_type="scan",
            source_id=scan_id,
            device={
                "device_id": device_id,
                "ip": ip,
                "mac": "00:11:22:33:44:55",
            },
            observed_at=observed_at,
            result=result,
        )

    observe("first", "192.0.2.10", [22])
    assert asset_id is not None
    annotation = client.patch(
        f"/api/assets/{asset_id}",
        json={"display_name": "Core switch", "owner": "Network team"},
    )
    assert annotation.status_code == 200
    observe("partial", "192.0.2.10", [80], status="partial")
    observe("second", "192.0.2.10", [22, 443])
    observe("moved", "192.0.2.20", [80])
    observe("same_ip", "192.0.2.20", [80, 443])
    observe("other_profile", "192.0.2.20", [53], profile="inventory")
    observe("other_probe", "192.0.2.20", [53], probe_id=str(uuid4()))
    observe("different_plan", "192.0.2.20", [22], plan={"tcp_top_ports": 200})
    observe("unknown_plan", "192.0.2.20", [22], missing_plan=True)
    observe("latest", "192.0.2.20", [80, 443, 445])
    observe("port_absent", "192.0.2.20", [80, 445])

    assert asset_id is not None
    asset = client.get(f"/api/assets/{asset_id}").json()
    assert asset["ip_history"] == ["192.0.2.10", "192.0.2.20"]
    assert asset["last_ip"] == "192.0.2.20"
    assert asset["port_snapshot_scan_id"] == ids["port_absent"]
    assert asset["open_port_count"] == 2
    assert asset["observation_count"] == 11
    assert asset["display_name"] == "Core switch"
    assert asset["owner"] == "Network team"

    response = client.get(
        f"/api/assets/{asset_id}/observations", params={"limit": 20}
    )
    assert response.status_code == 200, response.text
    history = {item["source_id"]: item for item in response.json()}
    assert history[ids["first"]]["port_delta"] is None
    assert history[ids["partial"]]["port_delta"] is None
    assert history[ids["moved"]]["port_delta"] is None
    assert history[ids["other_profile"]]["port_delta"] is None
    assert history[ids["other_probe"]]["port_delta"] is None
    assert history[ids["different_plan"]]["port_delta"] is None
    assert history[ids["unknown_plan"]]["port_delta"] is None
    second = history[ids["second"]]["port_delta"]
    assert second["baseline_scan_id"] == ids["first"]
    assert second["opened_ports"] == [
        {"protocol": "tcp", "port": 443, "service": None}
    ]
    same_ip = history[ids["same_ip"]]["port_delta"]
    assert same_ip["baseline_scan_id"] == ids["moved"]
    assert same_ip["opened_count"] == 1
    latest = history[ids["latest"]]["port_delta"]
    assert latest["baseline_scan_id"] == ids["same_ip"]
    assert latest["opened_ports"][0]["port"] == 445
    assert latest["no_longer_confirmed_count"] == 0
    port_absent = history[ids["port_absent"]]["port_delta"]
    assert port_absent["baseline_scan_id"] == ids["latest"]
    assert port_absent["opened_count"] == 0
    assert port_absent["no_longer_confirmed_ports"] == [
        {"protocol": "tcp", "port": 443, "service": None}
    ]

    page = client.get(
        f"/api/assets/{asset_id}/observations", params={"limit": 1, "offset": 0}
    ).json()
    assert [item["source_id"] for item in page] == [ids["port_absent"]]
    assert page[0]["port_delta"] == port_absent
