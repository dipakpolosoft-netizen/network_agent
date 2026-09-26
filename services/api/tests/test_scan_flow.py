from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient
from test_discovery_flow import authenticated_agent


def completed_discovery(
    client: TestClient, device_count: int = 2
) -> tuple[dict, dict]:
    agent = authenticated_agent(client)
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
        for number in range(1, device_count + 1)
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
                    "cpe": "cpe:/a:openbsd:openssh:9.0",
                    "cpes": [
                        "cpe:/a:openbsd:openssh:9.0",
                        "cpe:/o:linux:linux_kernel:6.0",
                    ],
                }
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
    assert result_body["summary"]["tcp_ports"] == 1
    assert result_body["summary"]["service_fingerprints"] == 1
    assert result_body["summary"]["cpes"] == 2
    assert result_body["summary"]["servers"] == 2
    assert result_body["summary"]["network_devices"] == 0
    assert result_body["summary"]["snmp_enabled"] == 1
    assert result_body["summary"]["services"] == [{"label": "ssh/tcp", "count": 1}]
    assert result_body["summary"]["vendors"] == [{"label": "Example", "count": 2}]

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
            "device_ids": ["selected-device-0001", "selected-device-0003"],
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
            ],
            "os_matches": [],
            "exposure_flags": [],
            "error": None,
        },
    )
    client.post(
        f"/agent/scans/{second['scan_id']}/hosts/selected-device-0003/result",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "host_scan.result",
            "scan_id": second["scan_id"],
            "agent_id": agent["agent_id"],
            "device_id": "selected-device-0003",
            "ip": "192.168.1.12",
            "status": "completed",
            "started_at": later,
            "completed_at": later,
            "hostname": "server-3",
            "device_type": "server",
            "classification_confidence": 0.8,
            "ports": [],
            "os_matches": [],
            "exposure_flags": [],
            "error": None,
        },
    )

    report = client.get(f"/api/scans/{second['scan_id']}").json()
    changes = report["change_summary"]
    assert changes["baseline_scan_id"] == first["scan_id"]
    assert changes["new_host_count"] == 1
    assert changes["missing_host_count"] == 1
    assert changes["opened_port_count"] == 1
    assert changes["closed_port_count"] == 1
    assert changes["resolved_finding_count"] == 1
    assert changes["new_hosts"][0]["ip"] == "192.168.1.12"
    assert changes["missing_hosts"][0]["ip"] == "192.168.1.11"
    assert changes["opened_ports"][0]["port"] == 443
    assert changes["closed_ports"][0]["port"] == 80
    assert changes["resolved_findings"][0]["code"] == "remote-admin"
    action_summary = report["action_summary"]
    assert action_summary["risk_score"] > 0
    assert action_summary["risk_level"] in {"low", "medium", "high", "critical"}
    assert any(
        action["title"] == "Validate newly opened services"
        for action in action_summary["priority_actions"]
    )


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
