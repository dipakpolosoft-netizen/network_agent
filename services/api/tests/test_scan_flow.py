from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from test_discovery_flow import authenticated_agent

from forgesec_api.scans.service import ScanService, _previous_comparable_scan


def completed_discovery(
    client: TestClient,
    device_count: int = 2,
    *,
    agent: dict | None = None,
    device_numbers: list[int] | None = None,
) -> tuple[dict, dict]:
    agent = agent or authenticated_agent(client)
    numbers = device_numbers or list(range(1, device_count + 1))
    device_count = len(numbers)
    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}
    created = client.post(
        f"/api/agents/{agent['agent_id']}/discover",
        json={"authorization_confirmed": True},
    ).json()
    command = client.get("/agent/commands/next", headers=authorization).json()
    now = datetime.now(UTC).isoformat()
    client.post(
        f"/agent/commands/{command['command_id']}/events",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "command.event",
            "status": "running",
            "message": "Discovery running",
            "details": {},
            "occurred_at": now,
        },
    )
    devices = [
        {
            "device_id": f"selected-device-{number:04d}",
            "ip": f"192.168.1.{number + 9}",
            "hostname": f"server-{number}",
            "mac": f"00:11:22:33:44:{number:02x}",
            "vendor": "Example",
            "snmp_name": f"switch-{number}" if number == 1 else None,
            "snmp_description": "Cisco Catalyst managed switch"
            if number == 1
            else None,
            "snmp_object_id": "1.3.6.1.4.1.9.1.123" if number == 1 else None,
            "snmp_contact": "netops@example.com" if number == 1 else None,
            "snmp_location": "MDF rack" if number == 1 else None,
            "snmp_uptime_seconds": 86400 if number == 1 else None,
            "snmp_interface_count": 48 if number == 1 else None,
            "snmp_interfaces": [
                {
                    "index": 1,
                    "name": "Gi1/0/1",
                    "description": "GigabitEthernet1/0/1",
                    "interface_type": "ethernet",
                    "admin_status": "up",
                    "oper_status": "up",
                    "speed_mbps": 1000,
                    "alias": "uplink",
                }
            ]
            if number == 1
            else [],
            "device_type": "switch" if number == 1 else "server",
            "classification_confidence": 0.9 if number == 1 else 0.7,
            "status": "up",
            "discovery_reason": "arp-response",
            "latency_ms": 1.0,
            "is_agent": False,
            "first_seen": now,
            "last_seen": now,
        }
        for number in numbers
    ]
    uploaded = client.post(
        f"/agent/discoveries/{created['discovery_id']}/devices",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "discovery.result",
            "discovery_id": created["discovery_id"],
            "agent_id": agent["agent_id"],
            "network": "192.168.1.0/24",
            "interface_name": "Ethernet",
            "status": "completed",
            "started_at": now,
            "completed_at": now,
            "devices": devices,
            "error": None,
        },
    )
    assert uploaded.status_code == 200
    completed = client.post(
        f"/agent/commands/{command['command_id']}/events",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "command.event",
            "status": "completed",
            "message": "Discovery completed",
            "details": {"device_count": device_count},
            "occurred_at": now,
        },
    )
    assert completed.status_code == 200
    return agent, created


def test_scan_origin_is_snapshotted_and_legacy_report_is_labeled(
    client: TestClient,
) -> None:
    agent, discovery = completed_discovery(client, device_count=1)
    created = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": ["selected-device-0001"],
            "profile": "inventory",
            "authorization_confirmed": True,
        },
    )
    assert created.status_code == 202, created.text
    scan_id = created.json()["scan_id"]
    first = client.get(f"/api/scans/{scan_id}").json()
    assert first["scan_origin"]["source"] == "scan_snapshot"
    assert first["scan_origin"]["hostname"] == "WIN-AGENT-01"
    assert first["scan_origin"]["local_ip"] == "192.168.1.25"
    assert first["total"] == 1
    assert len(first["targets"]) == 1

    store = client.app.state.store
    probe = store.read("agents", agent["agent_id"])
    probe["local_ip"] = "192.168.1.99"
    store.write("agents", agent["agent_id"], probe)
    saved = client.get(f"/api/scans/{scan_id}").json()
    assert saved["scan_origin"]["local_ip"] == "192.168.1.25"
    listed = client.get("/api/scans").json()
    assert listed[0]["scan_origin"] == saved["scan_origin"]

    old_scan = store.read("scans", scan_id)
    old_scan.pop("scan_origin")
    old_scan.pop("profile_plan")
    store.write("scans", scan_id, old_scan)
    legacy = client.get(f"/api/scans/{scan_id}").json()
    assert legacy["scan_origin"]["source"] == "current_heartbeat"
    assert legacy["scan_origin"]["local_ip"] == "192.168.1.99"
    assert legacy["profile_plan"] is None
    assert client.get("/api/scans").json()[0]["scan_origin"] == legacy["scan_origin"]
    assert legacy["total"] == 1

    reassigned = store.read("agents", agent["agent_id"])
    reassigned["site_id"] = "another-site"
    reassigned["site_name"] = "Another customer"
    store.write("agents", agent["agent_id"], reassigned)
    moved = client.get(f"/api/scans/{scan_id}").json()
    assert moved["scan_origin"] is None
    assert client.get("/api/scans").json()[0]["scan_origin"] is None


def test_probe_revocation_keeps_saved_scan_evidence(client: TestClient) -> None:
    agent, discovery = completed_discovery(client, device_count=1)
    created = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": ["selected-device-0001"],
            "profile": "inventory",
            "authorization_confirmed": True,
        },
    )
    assert created.status_code == 202, created.text
    scan_id = created.json()["scan_id"]
    saved_target = client.get(f"/api/scans/{scan_id}").json()["targets"][0]

    revoked = client.post(
        f"/api/agents/{agent['agent_id']}/revoke",
        json={"reason": "Pilot probe removed"},
    )
    assert revoked.status_code == 200, revoked.text
    report = client.get(f"/api/scans/{scan_id}")
    assert report.status_code == 200, report.text
    assert report.json()["targets"][0]["device_id"] == saved_target["device_id"]
    assert report.json()["targets"][0]["ip"] == saved_target["ip"]
    assert report.json()["targets"][0]["status"] == "cancelled"
    assert report.json()["scan_origin"]["agent_id"] == agent["agent_id"]
    assert any(item["scan_id"] == scan_id for item in client.get("/api/scans").json())


def test_scan_upload_rejects_spoofed_identity_and_revoked_site_scope(
    client: TestClient,
) -> None:
    agent, discovery = completed_discovery(client, device_count=1)
    created = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": ["selected-device-0001"],
            "profile": "inventory",
            "authorization_confirmed": True,
        },
    )
    assert created.status_code == 202, created.text
    scan_id = created.json()["scan_id"]
    credential = {"Authorization": f"Bearer {agent['agent_credential']}"}
    assert client.get("/agent/commands/next", headers=credential).status_code == 200
    control_path = f"/agent/scans/{scan_id}/control"

    def cancellation_requested() -> bool:
        return client.get(control_path, headers=credential).json()["cancel_requested"]

    assert cancellation_requested() is False
    now = datetime.now(UTC).isoformat()
    wrong_agent_id = "00000000-0000-0000-0000-000000000001"
    progress = {
        "schema_version": "1.0",
        "message_type": "scan.progress",
        "scan_id": scan_id,
        "agent_id": wrong_agent_id,
        "status": "running",
        "total": 1,
        "queued": 0,
        "running": 1,
        "completed": 0,
        "failed": 0,
        "cancelled": 0,
        "updated_at": now,
    }
    assert client.post(
        f"/agent/scans/{scan_id}/progress", headers=credential, json=progress
    ).status_code == 422
    result = {
        "schema_version": "1.0",
        "message_type": "host_scan.result",
        "scan_id": scan_id,
        "agent_id": wrong_agent_id,
        "device_id": "selected-device-0001",
        "ip": "192.168.1.10",
        "status": "completed",
        "started_at": now,
        "completed_at": now,
        "ports": [],
        "os_matches": [],
        "exposure_flags": [],
    }
    upload = f"/agent/scans/{scan_id}/hosts/selected-device-0001/result"
    assert client.post(upload, headers=credential, json=result).status_code == 422

    result["agent_id"] = agent["agent_id"]
    store = client.app.state.store
    original = store.read("agents", agent["agent_id"])
    other_site = client.post("/api/sites", json={"name": "Other site"}).json()
    store.write(
        "agents", agent["agent_id"],
        {**original, "site_id": other_site["site_id"]},
    )
    assert cancellation_requested() is True
    assert client.post(upload, headers=credential, json=result).status_code == 422
    store.write("agents", agent["agent_id"], original)
    assert cancellation_requested() is False

    site_id = original["site_id"]
    scope_id = client.get(f"/api/sites/{site_id}/scopes").json()[0]["scope_id"]
    assert client.delete(f"/api/sites/{site_id}/scopes/{scope_id}").status_code == 204
    assert cancellation_requested() is True
    assert client.post(upload, headers=credential, json=result).status_code == 422
    assert client.get(f"/api/scans/{scan_id}").json()["results"] == []


def test_probe_cannot_be_selected_as_its_own_scan_target(client: TestClient) -> None:
    agent, discovery = completed_discovery(client, device_count=1)
    store = client.app.state.store
    saved = store.read("discoveries", discovery["discovery_id"])
    saved["devices"].append(
        {
            **saved["devices"][0],
            "device_id": "probe-device",
            "ip": "192.168.1.25",
            "is_agent": True,
        }
    )
    store.write("discoveries", discovery["discovery_id"], saved)
    response = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": ["probe-device"],
            "profile": "inventory",
            "authorization_confirmed": True,
        },
    )
    assert response.status_code == 422
    assert "cannot target itself" in response.text


def test_selected_device_scan_progress_and_results(client: TestClient) -> None:
    agent, discovery = completed_discovery(client)
    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}
    created = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": ["selected-device-0001", "selected-device-0002"],
            "profile": "standard",
            "authorization_confirmed": True,
        },
    )
    assert created.status_code == 202
    scan = created.json()
    assert scan["total"] == 2

    command = client.get("/agent/commands/next", headers=authorization).json()
    assert command["command_type"] == "scan_devices"
    assert len(command["payload"]["targets"]) == 2
    assert command["payload"]["concurrency"] == 3
    assert command["payload"]["targets"][0]["device_type"] == "switch"
    assert command["payload"]["targets"][0]["snmp_name"] == "switch-1"
    assert command["payload"]["targets"][0]["snmp_interface_count"] == 48
    assert command["payload"]["targets"][0]["snmp_interfaces"][0]["name"] == "Gi1/0/1"

    now = datetime.now(UTC).isoformat()
    progress = client.post(
        f"/agent/scans/{scan['scan_id']}/progress",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "scan.progress",
            "scan_id": scan["scan_id"],
            "agent_id": agent["agent_id"],
            "status": "running",
            "stage": "service_detection",
            "total": 2,
            "queued": 1,
            "running": 1,
            "completed": 0,
            "failed": 0,
            "cancelled": 0,
            "updated_at": now,
        },
    )
    assert progress.status_code == 200

    result = client.post(
        f"/agent/scans/{scan['scan_id']}/hosts/selected-device-0001/result",
        headers=authorization,
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
            "hostname": "server-one",
            "device_type": "server",
            "classification_confidence": 0.8,
            "ports": [
                {
                    "protocol": "tcp",
                    "port": 22,
                    "state": "open",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "9.0",
                    "evidence_source": "nmap",
                    "recorded_at": now,
                    "cpe": "cpe:/a:openbsd:openssh:9.0",
                    "cpes": [
                        "cpe:/a:openbsd:openssh:9.0",
                        "cpe:/o:linux:linux_kernel:6.0",
                    ],
                },
                {
                    "protocol": "udp",
                    "port": 161,
                    "state": "open|filtered",
                    "service": "snmp",
                    "product": "Unverified",
                    "cpe": "cpe:/a:example:unverified:1.0",
                },
                {
                    "protocol": "tcp",
                    "port": 445,
                    "state": "filtered",
                    "service": "microsoft-ds",
                },
            ],
            "os_matches": [{"name": "Linux", "accuracy": 95}],
            "exposure_flags": [],
            "error": None,
        },
    )
    assert result.status_code == 200
    result_body = result.json()
    assert len(result_body["results"]) == 1
    assert result_body["summary"]["open_ports"] == 1
    assert result_body["summary"]["open_filtered_ports"] == 1
    assert result_body["summary"]["filtered_ports"] == 1
    assert result_body["summary"]["tcp_ports"] == 1
    assert result_body["summary"]["udp_ports"] == 0
    assert result_body["summary"]["service_fingerprints"] == 1
    assert result_body["summary"]["cpes"] == 2
    assert result_body["summary"]["servers"] == 2
    assert result_body["summary"]["network_devices"] == 0
    assert result_body["summary"]["snmp_enabled"] == 1
    assert result_body["summary"]["services"] == [{"label": "ssh/tcp", "count": 1}]
    assert result_body["summary"]["vendors"] == [{"label": "Example", "count": 2}]
    assert [port["state"] for port in result_body["results"][0]["ports"]] == [
        "open", "open|filtered", "filtered"
    ]
    saved_report = client.get(f"/api/scans/{scan['scan_id']}").json()
    saved_ports = saved_report["results"][0]["ports"]
    assert saved_ports[0]["evidence_source"] == "nmap"
    assert datetime.fromisoformat(
        saved_ports[0]["recorded_at"]
    ) == datetime.fromisoformat(now)
    assert saved_ports[1]["evidence_source"] is None
    assert saved_ports[1]["recorded_at"] is None


    class FakeVulnerabilityService:
        calls = 0

        def lookup(self, cpe: str) -> dict:
            self.calls += 1
            assert cpe in {
                "cpe:/a:openbsd:openssh:9.0",
                "cpe:/o:linux:linux_kernel:6.0",
            }
            vulnerabilities = []
            if cpe == "cpe:/a:openbsd:openssh:9.0":
                vulnerabilities = [
                    {
                        "cve_id": "CVE-2026-10000",
                        "severity": "critical",
                        "cvss_score": 9.8,
                        "cvss_version": "3.1",
                        "vector": "CVSS:3.1/AV:N/AC:L",
                        "description": "Example OpenSSH vulnerability.",
                        "published_at": None,
                        "last_modified_at": None,
                        "known_exploited": True,
                        "required_action": "Apply the vendor update.",
                        "action_due": None,
                        "references": ["https://example.com/advisory"],
                    }
                ]
            return {
                "source": "NVD",
                "cpe": cpe,
                "normalized_cpe": "cpe:2.3:a:openbsd:openssh:9.0:*:*:*:*:*:*:*",
                "total": len(vulnerabilities),
                "returned": len(vulnerabilities),
                "retrieved_at": now,
                "cached": False,
                "vulnerabilities": vulnerabilities,
                "notice": "Potential matches only.",
            }

    fake_vulnerabilities = FakeVulnerabilityService()
    client.app.state.vulnerability_service = fake_vulnerabilities
    lookup = client.post(
        f"/api/scans/{scan['scan_id']}/devices/selected-device-0001/vulnerabilities",
        params={"cpe": "cpe:/a:openbsd:openssh:9.0"},
    )
    assert lookup.status_code == 200
    assert lookup.json()["normalized_cpe"].startswith("cpe:2.3:a:openbsd")

    extra_lookup = client.post(
        f"/api/scans/{scan['scan_id']}/devices/selected-device-0001/vulnerabilities",
        params={"cpe": "cpe:/o:linux:linux_kernel:6.0"},
    )
    assert extra_lookup.status_code == 200

    assessment_path = f"/api/scans/{scan['scan_id']}/vulnerabilities"
    assert client.get(assessment_path).json() is None
    scan_vulnerabilities = client.post(f"{assessment_path}/refresh")
    assert scan_vulnerabilities.status_code == 200
    vulnerability_summary = scan_vulnerabilities.json()
    assert vulnerability_summary["total_cpes"] == 2
    assert vulnerability_summary["checked_cpes"] == 2
    assert vulnerability_summary["total_vulnerabilities"] == 1
    assert vulnerability_summary["known_exploited"] == 1
    assert vulnerability_summary["severity_counts"]["critical"] == 1
    assert vulnerability_summary["items"][0]["cpe"] == "cpe:/a:openbsd:openssh:9.0"
    assert vulnerability_summary["items"][0]["affected_services"][0]["ip"] == (
        "192.168.1.10"
    )
    assert vulnerability_summary["evidence_current"] is True
    assert vulnerability_summary["failed_cpes"] == 0
    assert vulnerability_summary["cached_lookups"] == 0
    assert client.get(assessment_path).json() == vulnerability_summary
    assert fake_vulnerabilities.calls == 4

    unobserved = client.post(
        f"/api/scans/{scan['scan_id']}/devices/selected-device-0001/vulnerabilities",
        params={"cpe": "cpe:/a:example:unobserved:1.0"},
    )
    assert unobserved.status_code == 422

    cancelled = client.post(f"/api/scans/{scan['scan_id']}/cancel")
    assert cancelled.status_code == 200
    control = client.get(
        f"/agent/scans/{scan['scan_id']}/control",
        headers=authorization,
    )
    assert control.json()["cancel_requested"] is True


def test_port_state_summary_does_not_call_timeout_or_ambiguity_open() -> None:
    summary = ScanService._build_summary(
        {
            "targets": [],
            "results": [
                {
                    "device_id": "ambiguous",
                    "status": "completed",
                    "ports": [
                        {
                            "protocol": "udp",
                            "port": 161,
                            "state": "open|filtered",
                            "service": "snmp",
                        },
                        {
                            "protocol": "tcp",
                            "port": 443,
                            "state": "filtered",
                            "service": "https",
                        },
                    ],
                },
                {
                    "device_id": "timeout",
                    "status": "timed_out",
                    "ports": [],
                    "error": "Host scan timed out",
                },
                {
                    "device_id": "error",
                    "status": "failed",
                    "ports": [],
                    "error": "Nmap failed",
                },
            ],
        }
    )
    assert summary["open_ports"] == 0
    assert summary["open_filtered_ports"] == 1
    assert summary["filtered_ports"] == 1
    assert summary["tcp_ports"] == 0
    assert summary["udp_ports"] == 0
    assert summary["management_services"] == 0
    assert summary["snmp_enabled"] == 0
    assert summary["timed_out_hosts"] == 1
    assert summary["failed_hosts"] == 1


def test_duplicate_host_port_upload_is_rejected_without_saving(
    client: TestClient,
) -> None:
    agent, discovery = completed_discovery(client, device_count=1)
    created = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": ["selected-device-0001"],
            "profile": "inventory",
            "authorization_confirmed": True,
        },
    )
    assert created.status_code == 202
    scan_id = created.json()["scan_id"]
    headers = {"Authorization": f"Bearer {agent['agent_credential']}"}
    assert client.get("/agent/commands/next", headers=headers).status_code == 200
    now = datetime.now(UTC).isoformat()
    port = {"protocol": "tcp", "port": 443, "state": "open"}
    uploaded = client.post(
        f"/agent/scans/{scan_id}/hosts/selected-device-0001/result",
        headers=headers,
        json={
            "schema_version": "1.0",
            "message_type": "host_scan.result",
            "scan_id": scan_id,
            "agent_id": agent["agent_id"],
            "device_id": "selected-device-0001",
            "ip": "192.168.1.10",
            "status": "completed",
            "started_at": now,
            "completed_at": now,
            "ports": [port, {**port, "state": "filtered"}],
            "os_matches": [],
            "exposure_flags": [],
        },
    )
    assert uploaded.status_code == 422
    assert "Duplicate 443/tcp" in uploaded.text
    report = client.get(f"/api/scans/{scan_id}").json()
    assert report["results"] == []
    assert report["summary"]["open_ports"] == 0


def test_scan_accepts_inventory_profile(client: TestClient) -> None:
    agent, discovery = completed_discovery(client)
    response = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": ["selected-device-0001"],
            "profile": "inventory",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 202
    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}
    command = client.get("/agent/commands/next", headers=authorization).json()
    assert command["payload"]["profile"] == "inventory"
    saved = client.get(f"/api/scans/{response.json()['scan_id']}").json()
    assert command["payload"]["profile_plan"] == saved["profile_plan"]
    assert saved["profile_plan"]["tcp_top_ports"] == 200
    assert saved["profile_plan"]["udp_ports"] == []
    assert saved["profile_plan"]["host_timeout_seconds"] == 480


@pytest.mark.parametrize(
    ("profile", "next_profile"),
    [
        ("inventory", "network_services"),
        ("network_services", "standard"),
        ("standard", "full_tcp"),
        ("full_tcp", "inventory"),
    ],
)
@pytest.mark.parametrize("initial_status", ["queued", "running"])
def test_active_scan_blocks_another_profile_until_cancelled(
    client: TestClient, profile: str, next_profile: str, initial_status: str
) -> None:
    agent, discovery = completed_discovery(client)
    path = f"/api/discoveries/{discovery['discovery_id']}/scan"
    payload = {
        "device_ids": ["selected-device-0001"],
        "profile": profile,
        "authorization_confirmed": True,
        "full_tcp_confirmed": profile == "full_tcp",
    }
    created = client.post(path, json=payload)
    assert created.status_code == 202
    scan = created.json()
    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}
    if initial_status == "running":
        client.get("/agent/commands/next", headers=authorization)
        progress = client.post(
            f"/agent/scans/{scan['scan_id']}/progress",
            headers=authorization,
            json={
                "schema_version": "1.0",
                "message_type": "scan.progress",
                "scan_id": scan["scan_id"],
                "agent_id": agent["agent_id"],
                "status": "running",
                "stage": "service_detection",
                "total": 1,
                "queued": 0,
                "running": 1,
                "completed": 0,
                "failed": 0,
                "cancelled": 0,
                "updated_at": datetime.now(UTC).isoformat(),
            },
        )
        assert progress.status_code == 200

    assert client.post(path, json=payload).status_code == 422
    next_payload = {
        **payload,
        "profile": next_profile,
        "full_tcp_confirmed": next_profile == "full_tcp",
    }
    rejected = client.post(path, json=next_payload)
    assert rejected.status_code == 422
    assert "already active" in rejected.json()["detail"]
    assert len(client.app.state.store.list("scans")) == 1
    assert len(
        [
            command
            for command in client.app.state.store.list("commands")
            if command["command_type"] == "scan_devices"
        ]
    ) == 1

    cancelled = client.post(f"/api/scans/{scan['scan_id']}/cancel")
    assert cancelled.status_code == 200
    if initial_status == "running":
        assert cancelled.json()["cancel_requested"] is True
        assert client.post(path, json=next_payload).status_code == 422
        finished = client.post(
            f"/agent/scans/{scan['scan_id']}/progress",
            headers=authorization,
            json={
                "schema_version": "1.0",
                "message_type": "scan.progress",
                "scan_id": scan["scan_id"],
                "agent_id": agent["agent_id"],
                "status": "cancelled",
                "stage": "cancelled",
                "total": 1,
                "queued": 0,
                "running": 0,
                "completed": 0,
                "failed": 0,
                "cancelled": 1,
                "updated_at": datetime.now(UTC).isoformat(),
            },
        )
        assert finished.status_code == 200
    assert client.post(path, json=next_payload).status_code == 202


@pytest.mark.parametrize("terminal_status", ["completed", "partial", "failed"])
def test_scan_can_restart_after_terminal_progress(
    client: TestClient, terminal_status: str
) -> None:
    agent, discovery = completed_discovery(client)
    path = f"/api/discoveries/{discovery['discovery_id']}/scan"
    payload = {
        "device_ids": ["selected-device-0001", "selected-device-0002"],
        "profile": "standard",
        "authorization_confirmed": True,
    }
    scan = client.post(path, json=payload).json()
    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}
    client.get("/agent/commands/next", headers=authorization)
    completed_count = {"completed": 2, "partial": 1, "failed": 0}[terminal_status]
    now = datetime.now(UTC).isoformat()
    for number in range(1, completed_count + 1):
        device_id = f"selected-device-{number:04d}"
        result = client.post(
            f"/agent/scans/{scan['scan_id']}/hosts/{device_id}/result",
            headers=authorization,
            json={
                "schema_version": "1.0",
                "message_type": "host_scan.result",
                "scan_id": scan["scan_id"],
                "agent_id": agent["agent_id"],
                "device_id": device_id,
                "ip": f"192.168.1.{number + 9}",
                "status": "completed",
                "started_at": now,
                "completed_at": now,
                "ports": [],
                "os_matches": [],
                "exposure_flags": [],
            },
        )
        assert result.status_code == 200
    finished = client.post(
        f"/agent/scans/{scan['scan_id']}/progress",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "scan.progress",
            "scan_id": scan["scan_id"],
            "agent_id": agent["agent_id"],
            "status": terminal_status,
            "stage": terminal_status,
            "total": 2,
            "queued": 0,
            "running": 0,
            "completed": completed_count,
            "failed": 2 - completed_count,
            "cancelled": 0,
            "updated_at": datetime.now(UTC).isoformat(),
        },
    )
    assert finished.status_code == 200
    assert client.post(path, json=payload).status_code == 202


def test_queued_scan_expires_without_probe_polling(client: TestClient) -> None:
    _, discovery = completed_discovery(client)
    created = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": ["selected-device-0001"],
            "profile": "standard",
            "authorization_confirmed": True,
        },
    ).json()
    store = client.app.state.store
    command = store.read("commands", created["command_id"])
    command["expires_at"] = "2020-01-01T00:00:00Z"
    store.write("commands", created["command_id"], command)

    scan = client.get(f"/api/scans/{created['scan_id']}").json()
    assert scan["status"] == "failed"
    assert scan["stage"] == "command_expired"
    assert scan["failed"] == 1
    assert scan["queued"] == 0
    assert scan["targets"][0]["status"] == "failed"
    assert scan["completed_at"] is not None
    assert store.read("commands", created["command_id"])["status"] == "expired"
    listed = client.get("/api/scans").json()
    assert next(item for item in listed if item["scan_id"] == created["scan_id"])[
        "status"
    ] == "failed"


def test_queued_scan_cancels_without_probe_polling(client: TestClient) -> None:
    _, discovery = completed_discovery(client)
    created = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": ["selected-device-0001"],
            "profile": "standard",
            "authorization_confirmed": True,
        },
    ).json()

    scan = client.post(f"/api/scans/{created['scan_id']}/cancel").json()
    assert scan["status"] == "cancelled"
    assert scan["cancelled"] == 1
    assert scan["queued"] == 0
    assert scan["cancel_requested"] is True
    assert scan["targets"][0]["status"] == "cancelled"
    assert client.app.state.store.read("commands", created["command_id"])[
        "status"
    ] == "cancelled"


def test_claimed_scan_is_not_expired_by_queue_ttl(client: TestClient) -> None:
    agent, discovery = completed_discovery(client)
    created = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": ["selected-device-0001"],
            "profile": "full_tcp",
            "authorization_confirmed": True,
            "full_tcp_confirmed": True,
        },
    ).json()
    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}
    claimed = client.get("/agent/commands/next", headers=authorization).json()
    assert claimed["command_id"] == created["command_id"]
    store = client.app.state.store
    command = store.read("commands", created["command_id"])
    command["expires_at"] = "2020-01-01T00:00:00Z"
    store.write("commands", created["command_id"], command)

    scan = client.get(f"/api/scans/{created['scan_id']}").json()
    assert scan["status"] == "queued"
    assert store.read("commands", created["command_id"])["status"] == "claimed"


def test_scan_accepts_network_services_profile(client: TestClient) -> None:
    agent, discovery = completed_discovery(client)
    response = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": ["selected-device-0001"],
            "profile": "network_services",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 202
    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}
    command = client.get("/agent/commands/next", headers=authorization).json()
    assert command["payload"]["profile"] == "network_services"
    saved = client.get(f"/api/scans/{response.json()['scan_id']}").json()
    assert saved["profile_plan"]["tcp_ports"] == [
        22, 53, 80, 443, 445, 3389, 8080, 8443
    ]
    assert saved["profile_plan"]["udp_ports"] == [
        53, 67, 69, 123, 137, 161, 500, 4500, 5353, 1900
    ]
    assert saved["profile_plan"]["os_detection"] == "not_requested"


def test_full_tcp_requires_one_target_and_separate_confirmation(
    client: TestClient,
) -> None:
    agent, discovery = completed_discovery(client)
    path = f"/api/discoveries/{discovery['discovery_id']}/scan"
    request = {
        "device_ids": ["selected-device-0001"],
        "profile": "full_tcp",
        "authorization_confirmed": True,
    }
    missing_confirmation = client.post(path, json=request)
    assert missing_confirmation.status_code == 422
    assert "Confirm the Full TCP" in missing_confirmation.text

    too_many = client.post(
        path,
        json={
            **request,
            "device_ids": ["selected-device-0001", "selected-device-0002"],
            "full_tcp_confirmed": True,
        },
    )
    assert too_many.status_code == 422
    assert "one selected target" in too_many.text
    assert client.get("/api/scans").json() == []

    accepted = client.post(path, json={**request, "full_tcp_confirmed": True})
    assert accepted.status_code == 202
    saved = client.get(f"/api/scans/{accepted.json()['scan_id']}").json()
    assert saved["total"] == 1
    assert saved["profile_plan"]["tcp_all_ports"] is True
    assert saved["profile_plan"]["udp_ports"] == []
    assert saved["profile_plan"]["host_timeout_seconds"] == 2700
    command = client.get(
        "/agent/commands/next",
        headers={"Authorization": f"Bearer {agent['agent_credential']}"},
    ).json()
    assert command["payload"]["full_tcp_confirmed"] is True


def test_cancel_progress_stays_cancelling_until_terminal(client: TestClient) -> None:
    agent, discovery = completed_discovery(client)
    scan = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": ["selected-device-0001"],
            "profile": "standard",
            "authorization_confirmed": True,
        },
    ).json()
    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}
    client.get("/agent/commands/next", headers=authorization)
    path = f"/agent/scans/{scan['scan_id']}/progress"
    progress = {
        "schema_version": "1.0",
        "message_type": "scan.progress",
        "scan_id": scan["scan_id"],
        "agent_id": agent["agent_id"],
        "status": "running",
        "stage": "scanning",
        "total": 1,
        "queued": 0,
        "running": 1,
        "running_device_ids": ["selected-device-0001"],
        "completed": 0,
        "failed": 0,
        "cancelled": 0,
        "updated_at": datetime.now(UTC).isoformat(),
    }
    assert client.post(path, headers=authorization, json=progress).status_code == 200
    saved = client.get(f"/api/scans/{scan['scan_id']}").json()
    assert saved["targets"][0]["status"] == "running"
    assert client.post(f"/api/scans/{scan['scan_id']}/cancel").status_code == 200
    pending = client.post(path, headers=authorization, json=progress)
    assert pending.status_code == 200
    assert pending.json()["status"] == "cancelling"
    assert pending.json()["stage"] == "cancelling"
    assert pending.json()["last_progress_at"] is not None
    terminal = {
        **progress,
        "status": "cancelled",
        "stage": "completed",
        "running": 0,
        "running_device_ids": [],
        "cancelled": 1,
    }
    finished = client.post(path, headers=authorization, json=terminal)
    assert finished.json()["status"] == "cancelled"
    assert client.post(path, headers=authorization, json=progress).status_code == 422


def test_completed_command_reconciles_missing_final_progress(
    client: TestClient,
) -> None:
    agent, discovery = completed_discovery(client)
    scan = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": ["selected-device-0001", "selected-device-0002"],
            "profile": "standard",
            "authorization_confirmed": True,
        },
    ).json()
    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}
    client.get("/agent/commands/next", headers=authorization)
    now = datetime.now(UTC).isoformat()
    result = client.post(
        f"/agent/scans/{scan['scan_id']}/hosts/selected-device-0001/result",
        headers=authorization,
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
            "ports": [],
            "os_matches": [],
            "exposure_flags": [],
        },
    )
    assert result.status_code == 200
    for status in ("running", "completed"):
        response = client.post(
            f"/agent/commands/{scan['command_id']}/events",
            headers=authorization,
            json={
                "schema_version": "1.0",
                "message_type": "command.event",
                "status": status,
                "message": f"Scan {status}",
                "details": {},
                "occurred_at": now,
            },
        )
        assert response.status_code == 200
    saved = client.get(f"/api/scans/{scan['scan_id']}").json()
    assert saved["status"] == "partial"
    assert saved["completed"] == 1
    assert saved["failed"] == 1
    assert len(saved["results"]) == 1
    assert saved["targets"][1]["status"] == "failed"


def test_scan_change_summary_compares_previous_same_profile(
    client: TestClient,
) -> None:
    agent, discovery = completed_discovery(client, device_count=3)
    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}

    first = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": ["selected-device-0001", "selected-device-0002"],
            "profile": "network_services",
            "authorization_confirmed": True,
        },
    ).json()
    now = datetime.now(UTC).isoformat()
    client.post(
        f"/agent/scans/{first['scan_id']}/hosts/selected-device-0001/result",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "host_scan.result",
            "scan_id": first["scan_id"],
            "agent_id": agent["agent_id"],
            "device_id": "selected-device-0001",
            "ip": "192.168.1.10",
            "status": "completed",
            "started_at": now,
            "completed_at": now,
            "hostname": "server-1",
            "device_type": "server",
            "classification_confidence": 0.8,
            "ports": [{"protocol": "tcp", "port": 22, "state": "open"}],
            "os_matches": [],
            "exposure_flags": [
                {
                    "code": "remote-admin",
                    "severity": "high",
                    "title": "Remote administration exposed",
                    "evidence": "22/tcp ssh is open",
                }
            ],
            "error": None,
        },
    )
    client.post(
        f"/agent/scans/{first['scan_id']}/hosts/selected-device-0002/result",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "host_scan.result",
            "scan_id": first["scan_id"],
            "agent_id": agent["agent_id"],
            "device_id": "selected-device-0002",
            "ip": "192.168.1.11",
            "status": "completed",
            "started_at": now,
            "completed_at": now,
            "hostname": "server-2",
            "device_type": "server",
            "classification_confidence": 0.8,
            "ports": [{"protocol": "tcp", "port": 80, "state": "open"}],
            "os_matches": [],
            "exposure_flags": [],
            "error": None,
        },
    )
    client.post(
        f"/agent/scans/{first['scan_id']}/progress",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "scan.progress",
            "scan_id": first["scan_id"],
            "agent_id": agent["agent_id"],
            "status": "completed",
            "stage": "completed",
            "total": 2,
            "queued": 0,
            "running": 0,
            "completed": 2,
            "failed": 0,
            "cancelled": 0,
            "updated_at": now,
        },
    )

    second = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": ["selected-device-0001", "selected-device-0002"],
            "profile": "network_services",
            "authorization_confirmed": True,
        },
    ).json()
    later = datetime.now(UTC).isoformat()
    client.post(
        f"/agent/scans/{second['scan_id']}/hosts/selected-device-0001/result",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "host_scan.result",
            "scan_id": second["scan_id"],
            "agent_id": agent["agent_id"],
            "device_id": "selected-device-0001",
            "ip": "192.168.1.10",
            "status": "completed",
            "started_at": later,
            "completed_at": later,
            "hostname": "server-1",
            "device_type": "server",
            "classification_confidence": 0.8,
            "ports": [
                {"protocol": "tcp", "port": 22, "state": "open"},
                {"protocol": "tcp", "port": 443, "state": "open"},
                {"protocol": "tcp", "port": 80, "state": "open|filtered"},
            ],
            "os_matches": [],
            "exposure_flags": [],
            "error": None,
        },
    )
    client.post(
        f"/agent/scans/{second['scan_id']}/hosts/selected-device-0002/result",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "host_scan.result",
            "scan_id": second["scan_id"],
            "agent_id": agent["agent_id"],
            "device_id": "selected-device-0002",
            "ip": "192.168.1.11",
            "status": "completed",
            "started_at": later,
            "completed_at": later,
            "hostname": "server-2",
            "device_type": "server",
            "classification_confidence": 0.8,
            "ports": [],
            "os_matches": [],
            "exposure_flags": [],
            "error": None,
        },
    )

    client.post(
        f"/agent/scans/{second['scan_id']}/progress",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "scan.progress",
            "scan_id": second["scan_id"],
            "agent_id": agent["agent_id"],
            "status": "completed",
            "stage": "completed",
            "total": 2,
            "queued": 0,
            "running": 0,
            "completed": 2,
            "failed": 0,
            "cancelled": 0,
            "updated_at": later,
        },
    )

    report = client.get(f"/api/scans/{second['scan_id']}").json()
    changes = report["change_summary"]
    assert changes["baseline_scan_id"] == first["scan_id"]
    assert changes["new_host_count"] == 0
    assert changes["missing_host_count"] == 0
    assert changes["opened_port_count"] == 1
    assert changes["closed_port_count"] == 0
    assert changes["no_longer_confirmed_port_count"] == 1
    assert changes["resolved_finding_count"] == 1
    assert changes["new_hosts"] == []
    assert changes["missing_hosts"] == []
    assert changes["opened_ports"][0]["port"] == 443
    assert changes["no_longer_confirmed_ports"][0]["port"] == 80
    assert changes["resolved_findings"][0]["code"] == "remote-admin"
    action_summary = report["action_summary"]
    assert action_summary["risk_score"] > 0
    assert action_summary["risk_level"] in {"low", "medium", "high", "critical"}
    assert any(
        action["title"] == "Validate newly opened services"
        for action in action_summary["priority_actions"]
    )
    assets = client.get("/api/assets").json()["items"]
    first_asset = next(item for item in assets if item["last_ip"] == "192.168.1.10")
    observations = client.get(
        f"/api/assets/{first_asset['asset_id']}/observations"
    ).json()
    latest = observations[0]
    assert latest["source_id"] == second["scan_id"]
    assert latest["site_id"] == first_asset["site_id"]
    assert latest["agent_id"] == agent["agent_id"]
    assert latest["port_delta"]["baseline_scan_id"] == first["scan_id"]
    assert latest["port_delta"]["opened_ports"][0]["port"] == 443
    assert len(observations) == 3


def test_scan_baseline_requires_same_site_targets_and_complete_results() -> None:
    baseline = {
        "scan_id": "baseline",
        "site_id": "site-a",
        "agent_id": "probe-a",
        "profile": "standard",
        "profile_plan": {"tcp_ports": [22]},
        "created_at": "2026-01-01T00:00:00Z",
        "status": "completed",
        "targets": [{"device_id": "host-1", "ip": "10.0.0.1"}],
        "results": [{"device_id": "host-1", "ip": "10.0.0.1", "status": "completed"}],
    }
    current = {
        **baseline,
        "scan_id": "current",
        "created_at": "2026-01-02T00:00:00Z",
    }
    assert _previous_comparable_scan(current, [baseline]) == baseline
    assert _previous_comparable_scan(
        {**current, "targets": [{"device_id": "host-2", "ip": "10.0.0.2"}]},
        [baseline],
    ) is None
    assert _previous_comparable_scan(
        {**current, "site_id": "site-b"}, [baseline]
    ) is None
    assert _previous_comparable_scan(
        {**current, "status": "partial"}, [baseline]
    ) is None
    assert _previous_comparable_scan(
        {**current, "results": []}, [baseline]
    ) is None


def test_repeat_discovery_changes_require_same_completed_scope(
    client: TestClient,
) -> None:
    agent, first = completed_discovery(client, device_numbers=[1, 2])
    _, second = completed_discovery(
        client, agent=agent, device_numbers=[2, 3]
    )
    current = client.get(f"/api/discoveries/{second['discovery_id']}").json()
    changes = current["change_summary"]
    assert current["site_id"] is not None
    assert changes["baseline_discovery_id"] == first["discovery_id"]
    assert changes["new_host_count"] == 1
    assert changes["not_observed_count"] == 1
    assert changes["new_hosts"][0]["ip"] == "192.168.1.12"
    assert changes["not_observed_hosts"][0]["ip"] == "192.168.1.10"
    previous = client.get(f"/api/discoveries/{first['discovery_id']}").json()
    assert previous["devices"][0]["ip"] == "192.168.1.10"

    store = client.app.state.store
    partial = store.read("discoveries", second["discovery_id"])
    partial["status"] = "partial"
    store.write("discoveries", second["discovery_id"], partial)
    assert client.get(
        f"/api/discoveries/{second['discovery_id']}"
    ).json()["change_summary"]["baseline_discovery_id"] is None


def test_scan_rejects_unknown_or_excessive_device_selection(
    client: TestClient,
) -> None:
    _agent, discovery = completed_discovery(client)
    unknown = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": ["unknown-device"],
            "profile": "standard",
            "authorization_confirmed": True,
        },
    )
    assert unknown.status_code == 422

    excessive_discovery = completed_discovery(client, device_count=130)[1]
    excessive = client.post(
        f"/api/discoveries/{excessive_discovery['discovery_id']}/scan",
        json={
            "device_ids": [f"selected-device-{number:04d}" for number in range(1, 130)],
            "profile": "standard",
            "authorization_confirmed": True,
        },
    )
    assert excessive.status_code == 422


def test_scan_accepts_full_selection_from_larger_discovery(
    client: TestClient,
) -> None:
    _agent, discovery = completed_discovery(client, device_count=12)
    selected = [f"selected-device-{number:04d}" for number in range(1, 13)]

    response = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": selected,
            "profile": "standard",
            "authorization_confirmed": True,
        },
    )

    assert response.status_code == 202
    assert response.json()["total"] == 12
