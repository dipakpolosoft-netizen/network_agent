from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from fastapi.testclient import TestClient
from test_scan_flow import completed_discovery

from forgesec_api.vulnerabilities.assessment import _fingerprint


def _scanned_asset(client: TestClient) -> tuple[dict, dict]:
    agent, discovery = completed_discovery(client, device_count=2)
    scan = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": ["selected-device-0001"],
            "profile": "standard",
            "authorization_confirmed": True,
        },
    ).json()
    now = datetime.now(UTC).isoformat()
    uploaded = client.post(
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
            "ports": [
                {
                    "protocol": "tcp",
                    "port": 80,
                    "state": "open",
                    "service": "http",
                    "product": "Example",
                    "version": "1.0",
                    "cpe": "cpe:/a:example:web:1.0",
                }
            ],
            "os_matches": [],
            "exposure_flags": [
                {
                    "code": "HTTP_EXPOSED",
                    "severity": "medium",
                    "title": "HTTP service exposed",
                    "evidence": "80/tcp open",
                }
            ],
            "error": None,
        },
    )
    assert uploaded.status_code == 200
    asset = next(
        item
        for item in client.get("/api/assets").json()["items"]
        if item["last_ip"] == "192.168.1.10"
    )
    return asset, scan


def test_asset_evidence_keeps_source_and_finding_classification(
    client: TestClient,
) -> None:
    asset, scan = _scanned_asset(client)
    store = client.app.state.store
    contexts = client.app.state.scan_service.observed_cpe_contexts(scan["scan_id"])
    now = datetime.now(UTC).isoformat()
    store.write(
        "vulnerability-assessments",
        scan["scan_id"],
        {
            "scan_id": scan["scan_id"],
            "assessed_at": now,
            "evidence_fingerprint": _fingerprint(contexts),
            "items": [
                {
                    "cpe": "cpe:/a:example:web:1.0",
                    "error": None,
                    "top_vulnerabilities": [
                        {
                            "cve_id": "CVE-2025-1234",
                            "severity": "high",
                            "description": "Potential version match",
                        }
                    ],
                }
            ],
        },
    )
    job_id = str(uuid4())
    store.write(
        "scanner-worker-jobs",
        job_id,
        {
            "job_id": job_id,
            "source_asset_id": asset["asset_id"],
            "source_scan_id": scan["scan_id"],
            "site_id": asset["site_id"],
            "target_ip": asset["last_ip"],
            "status": "completed",
            "template_profile": "http_baseline",
            "created_at": now,
            "completed_at": now,
            "summary": "One web configuration observation",
            "evidence": {
                "findings": [
                    {
                        "title": "Missing security header",
                        "matched_at": "http://192.168.1.10:80",
                        "severity": "low",
                        "template_id": "baseline",
                    }
                ],
                "target_url": "http://192.168.1.10:80",
            },
        },
    )
    response = client.get(f"/api/assets/{asset['asset_id']}/evidence")
    assert response.status_code == 200
    body = response.json()
    assert {(item["source"], item["classification"]) for item in body["items"]} == {
        ("host_scan", "exposure_signal"),
        ("nvd", "potential_cve"),
        ("nuclei", "configuration_observation"),
    }
    assert all(item["current"] for item in body["items"])
    assert all(item["scan_id"] == scan["scan_id"] for item in body["items"])
    assert body["runs"][0]["job_id"] == job_id
    wrong_site_job = dict(store.read("scanner-worker-jobs", job_id))
    wrong_site_job["job_id"] = str(uuid4())
    wrong_site_job["site_id"] = str(uuid4())
    store.write("scanner-worker-jobs", wrong_site_job["job_id"], wrong_site_job)
    assert (
        len(client.get(f"/api/assets/{asset['asset_id']}/evidence").json()["runs"]) == 1
    )
    other = next(
        item
        for item in client.get("/api/assets").json()["items"]
        if item["asset_id"] != asset["asset_id"]
    )
    assert client.get(f"/api/assets/{other['asset_id']}/evidence").json()["items"] == []
    assert client.get(f"/api/assets/{uuid4()}/evidence").status_code == 404

    stored_scan = store.read("scans", scan["scan_id"])
    stored_scan["results"][0]["ports"][0]["version"] = "2.0"
    store.write("scans", scan["scan_id"], stored_scan)
    changed = client.get(f"/api/assets/{asset['asset_id']}/evidence").json()
    assert (
        next(item for item in changed["items"] if item["source"] == "nvd")["current"]
        is False
    )


def test_failed_worker_run_is_not_finding_and_inventory_is_fact(
    client: TestClient,
) -> None:
    asset, scan = _scanned_asset(client)
    store = client.app.state.store
    now = datetime.now(UTC).isoformat()
    for status, source in (("failed", "greenbone"), ("completed", "ssh_inventory")):
        job_id = str(uuid4())
        store.write(
            "scanner-worker-jobs",
            job_id,
            {
                "job_id": job_id,
                "source_asset_id": asset["asset_id"],
                "source_scan_id": scan["scan_id"],
                "site_id": asset["site_id"],
                "target_ip": asset["last_ip"],
                "status": status,
                "assessment_profile": "greenbone_single_host"
                if source == "greenbone"
                else None,
                "inventory_profile": "linux_ssh_readonly"
                if source == "ssh_inventory"
                else None,
                "created_at": now,
                "completed_at": now,
                "summary": status,
                "evidence": {}
                if status == "failed"
                else {
                    "hostname": "host-1",
                    "os_name": "Linux",
                    "os_version": "1",
                    "kernel": "6.0",
                    "packages": [{"name": "example", "version": "1"}],
                    "packages_truncated": False,
                },
            },
        )
    result = client.get(f"/api/assets/{asset['asset_id']}/evidence").json()
    assert [item["source"] for item in result["items"]] == ["host_scan"]
    assert {run["status"] for run in result["runs"]} == {"failed", "completed"}
    assert result["latest_inventory"]["package_count"] == 1


def test_greenbone_result_is_bounded_scanner_finding(client: TestClient) -> None:
    asset, scan = _scanned_asset(client)
    store = client.app.state.store
    now = datetime.now(UTC).isoformat()
    job_id = str(uuid4())
    store.write(
        "scanner-worker-jobs",
        job_id,
        {
            "job_id": job_id,
            "source_asset_id": asset["asset_id"],
            "source_scan_id": scan["scan_id"],
            "site_id": asset["site_id"],
            "target_ip": asset["last_ip"],
            "status": "completed",
            "assessment_profile": "greenbone_single_host",
            "created_at": now,
            "completed_at": now,
            "summary": "One finding",
            "evidence": {
                "truncated": True,
                "findings": [
                    {
                        "name": "Service weakness",
                        "severity": 8.4,
                        "host": asset["last_ip"],
                        "port": "80/tcp",
                        "nvt_oid": "1.2.3",
                        "cves": ["CVE-2025-1234"],
                    }
                ],
            },
        },
    )
    result = client.get(f"/api/assets/{asset['asset_id']}/evidence").json()
    finding = next(item for item in result["items"] if item["source"] == "greenbone")
    assert finding["classification"] == "scanner_finding"
    assert finding["severity"] == "high"
    assert finding["source_id"] == job_id
    assert result["truncated"] is True
