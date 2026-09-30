from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient
from test_scan_flow import completed_discovery

from forgesec_api.main import create_app
from forgesec_api.settings import Settings
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

    assessment = store.read("vulnerability-assessments", scan["scan_id"])
    assessment["scan_id"] = str(uuid4())
    store.write("vulnerability-assessments", scan["scan_id"], assessment)
    changed = client.get(f"/api/assets/{asset['asset_id']}/evidence").json()
    assert all(item["source"] != "nvd" for item in changed["items"])


def test_worker_evidence_requires_matching_source_scan_and_target(
    client: TestClient,
) -> None:
    asset, scan = _scanned_asset(client)
    store = client.app.state.store
    now = datetime.now(UTC).isoformat()
    valid_id = str(uuid4())
    valid = {
        "job_id": valid_id,
        "source_asset_id": asset["asset_id"],
        "source_scan_id": scan["scan_id"],
        "site_id": asset["site_id"],
        "target_ip": asset["last_ip"],
        "target_port": 80,
        "target_scheme": "http",
        "status": "completed",
        "template_profile": "http_baseline",
        "created_at": now,
        "completed_at": now,
        "summary": "One observation",
        "evidence": {
            "target_url": f"http://{asset['last_ip']}:80",
            "findings": [
                {
                    "title": "Missing security header",
                    "matched_at": f"http://{asset['last_ip']}:80",
                    "severity": "low",
                    "template_id": "baseline",
                }
            ],
        },
    }
    store.write("scanner-worker-jobs", valid_id, valid)
    wrong_scan = {**valid, "job_id": str(uuid4()), "source_scan_id": str(uuid4())}
    wrong_target = {**valid, "job_id": str(uuid4()), "target_ip": "192.168.1.11"}
    store.write("scanner-worker-jobs", wrong_scan["job_id"], wrong_scan)
    store.write("scanner-worker-jobs", wrong_target["job_id"], wrong_target)

    path = f"/api/assets/{asset['asset_id']}/evidence"
    evidence = client.get(path).json()
    assert [run["job_id"] for run in evidence["runs"]] == [valid_id]
    nuclei_sources = [
        item["source_id"] for item in evidence["items"] if item["source"] == "nuclei"
    ]
    assert nuclei_sources == [valid_id]

    stored_asset = store.read("assets", asset["asset_id"])
    stored_asset["last_ip"] = "192.168.1.12"
    store.write("assets", asset["asset_id"], stored_asset)
    historical = client.get(path).json()
    assert historical["runs"][0]["job_id"] == valid_id
    assert historical["runs"][0]["current"] is False


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


def test_nvd_candidate_and_greenbone_finding_keep_separate_reviews(
    client: TestClient,
) -> None:
    asset, scan = _scanned_asset(client)
    store = client.app.state.store
    now = datetime.now(UTC).isoformat()
    store.write(
        "vulnerability-assessments",
        scan["scan_id"],
        {
            "scan_id": scan["scan_id"],
            "assessed_at": now,
            "evidence_fingerprint": _fingerprint(
                client.app.state.scan_service.observed_cpe_contexts(scan["scan_id"])
            ),
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
            "assessment_profile": "greenbone_single_host",
            "created_at": now,
            "completed_at": now,
            "summary": "One scanner finding",
            "evidence": {
                "truncated": False,
                "findings": [
                    {
                        "result_id": str(uuid4()),
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
    path = f"/api/assets/{asset['asset_id']}/evidence"
    items = client.get(path).json()["items"]
    candidate = next(item for item in items if item["source"] == "nvd")
    scanner = next(item for item in items if item["source"] == "greenbone")
    assert candidate["classification"] == "potential_cve"
    assert scanner["classification"] == "scanner_finding"
    assert candidate["review_id"] != scanner["review_id"]
    assert client.patch(
        f"{path}/{candidate['review_id']}/review",
        json={"status": "false_positive", "note": "Version not affected"},
    ).status_code == 200
    refreshed = client.get(path).json()["items"]
    assert next(item for item in refreshed if item["source"] == "nvd")[
        "review_status"
    ] == "false_positive"
    assert next(item for item in refreshed if item["source"] == "greenbone")[
        "review_status"
    ] == "unreviewed"


def test_review_disposition_is_saved_audited_and_asset_scoped(
    client: TestClient,
) -> None:
    asset, _ = _scanned_asset(client)
    evidence = client.get(f"/api/assets/{asset['asset_id']}/evidence").json()
    item = evidence["items"][0]
    assert item["review_status"] == "unreviewed"
    route = f"/api/assets/{asset['asset_id']}/evidence/{item['review_id']}/review"
    assert client.patch(route, json={"status": "false_positive"}).status_code == 422
    assert (
        client.patch(route, json={"status": "false_positive", "note": " "}).status_code
        == 422
    )
    saved = client.patch(
        route, json={"status": "false_positive", "note": "Verified with owner"}
    )
    assert saved.status_code == 200
    assert saved.json()["review_status"] == "false_positive"
    assert saved.json()["review_note"] == "Verified with owner"
    assert (
        client.get(f"/api/assets/{asset['asset_id']}/evidence").json()["items"][0][
            "review_status"
        ]
        == "false_positive"
    )
    events = [
        json.loads(line)
        for line in (client.app.state.store.root / "activity" / "activity.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert any(event["event_type"] == "asset_evidence.reviewed" for event in events)
    other = next(
        entry
        for entry in client.get("/api/assets").json()["items"]
        if entry["asset_id"] != asset["asset_id"]
    )
    assert (
        client.patch(
            f"/api/assets/{other['asset_id']}/evidence/{item['review_id']}/review",
            json={"status": "confirmed"},
        ).status_code
        == 404
    )
    assert (
        client.patch(
            f"/api/assets/{asset['asset_id']}/evidence/{'0' * 64}/review",
            json={"status": "confirmed"},
        ).status_code
        == 404
    )


def test_nvd_reassessment_does_not_inherit_old_review(client: TestClient) -> None:
    asset, scan = _scanned_asset(client)
    store = client.app.state.store
    scan_id = scan["scan_id"]
    assessment = {
        "scan_id": scan_id,
        "assessed_at": datetime.now(UTC).isoformat(),
        "evidence_fingerprint": _fingerprint(
            client.app.state.scan_service.observed_cpe_contexts(scan_id)
        ),
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
    }
    store.write("vulnerability-assessments", scan_id, assessment)
    path = f"/api/assets/{asset['asset_id']}/evidence"
    item = next(
        item for item in client.get(path).json()["items"] if item["source"] == "nvd"
    )
    review = client.patch(
        f"{path}/{item['review_id']}/review",
        json={"status": "false_positive", "note": "Version not affected"},
    )
    assert review.status_code == 200
    assert next(
        item for item in client.get(path).json()["items"] if item["source"] == "nvd"
    )["review_status"] == "false_positive"

    assessment["assessed_at"] = (
        datetime.fromisoformat(review.json()["reviewed_at"]) + timedelta(seconds=1)
    ).isoformat()
    assessment["items"][0]["top_vulnerabilities"][0]["description"] = (
        "Updated applicability"
    )
    store.write("vulnerability-assessments", scan_id, assessment)
    refreshed = next(
        item for item in client.get(path).json()["items"] if item["source"] == "nvd"
    )
    assert refreshed["review_id"] == item["review_id"]
    assert refreshed["review_status"] == "unreviewed"
    assert refreshed["review_note"] is None
    assert store.read("asset-evidence-reviews", item["review_id"])["status"] == (
        "false_positive"
    )


def test_misfiled_review_does_not_change_evidence_status(client: TestClient) -> None:
    asset, _ = _scanned_asset(client)
    path = f"/api/assets/{asset['asset_id']}/evidence"
    item = client.get(path).json()["items"][0]
    review = client.patch(
        f"{path}/{item['review_id']}/review",
        json={"status": "investigating"},
    )
    assert review.status_code == 200
    store = client.app.state.store
    saved = store.read("asset-evidence-reviews", item["review_id"])
    saved["source"] = "nuclei"
    store.write("asset-evidence-reviews", item["review_id"], saved)
    assert client.get(path).json()["items"][0]["review_status"] == "unreviewed"


def test_completed_worker_supersedes_older_finding_but_failed_job_does_not(
    client: TestClient,
) -> None:
    asset, scan = _scanned_asset(client)
    store = client.app.state.store
    now = datetime.now(UTC).isoformat()
    jobs = []
    for index, status in enumerate(("completed", "failed", "completed")):
        job_id = str(uuid4())
        job = {
            "job_id": job_id,
            "source_asset_id": asset["asset_id"],
            "source_scan_id": scan["scan_id"],
            "site_id": asset["site_id"],
            "target_ip": asset["last_ip"],
            "target_port": 80,
            "target_scheme": "http",
            "template_profile": "http_baseline",
            "status": status,
            "created_at": f"2026-01-0{index + 1}T00:00:00+00:00",
            "completed_at": now,
            "summary": status,
            "evidence": {
                "target_url": f"http://{asset['last_ip']}:80",
                "findings": [
                    {
                        "template_id": "baseline",
                        "title": "Missing header",
                        "matched_at": f"http://{asset['last_ip']}:80",
                        "severity": "low",
                    }
                ],
            },
        }
        store.write("scanner-worker-jobs", job_id, job)
        jobs.append(job)
    result = client.get(f"/api/assets/{asset['asset_id']}/evidence").json()
    nuclei = [item for item in result["items"] if item["source"] == "nuclei"]
    assert len(nuclei) == 2
    assert (
        next(item for item in nuclei if item["source_id"] == jobs[0]["job_id"])[
            "current"
        ]
        is False
    )
    assert (
        next(item for item in nuclei if item["source_id"] == jobs[2]["job_id"])[
            "current"
        ]
        is True
    )
    assert all(item["source_id"] != jobs[1]["job_id"] for item in nuclei)
    jobs[2]["evidence"]["findings"] = []
    store.write("scanner-worker-jobs", jobs[2]["job_id"], jobs[2])
    result = client.get(f"/api/assets/{asset['asset_id']}/evidence").json()
    nuclei = [item for item in result["items"] if item["source"] == "nuclei"]
    assert len(nuclei) == 1
    assert nuclei[0]["current"] is False
    assert {run["status"] for run in result["runs"]} == {"completed", "failed"}


def test_viewer_cannot_review_evidence(settings: Settings) -> None:
    app = create_app(replace(settings, auth_required=True))
    with TestClient(app) as client:
        app.state.auth_service.create_user(
            "viewer@example.test", "another correct password", "viewer"
        )
        session = client.post(
            "/api/auth/login",
            json={
                "email": "viewer@example.test",
                "password": "another correct password",
            },
        ).json()
        response = client.patch(
            f"/api/assets/{uuid4()}/evidence/{'0' * 64}/review",
            headers={"X-CSRF-Token": session["csrf_token"]},
            json={"status": "confirmed"},
        )
        assert response.status_code == 403


def test_mismatched_scan_provenance_is_not_reviewable(client: TestClient) -> None:
    asset, scan = _scanned_asset(client)
    store = client.app.state.store
    stored_scan = store.read("scans", scan["scan_id"])
    stored_scan["site_id"] = str(uuid4())
    store.write("scans", scan["scan_id"], stored_scan)
    response = client.get(f"/api/assets/{asset['asset_id']}/evidence")
    assert response.status_code == 200
    assert response.json()["items"] == []
