from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from test_scan_flow import completed_discovery


def _claimed_scan(
    client: TestClient, *, device_count: int = 1
) -> tuple[dict, dict, dict]:
    agent, discovery = completed_discovery(client, device_count=device_count)
    scan = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": [
                f"selected-device-{number:04d}"
                for number in range(1, device_count + 1)
            ],
            "profile": "standard",
            "authorization_confirmed": True,
        },
    ).json()
    authorization = {"Authorization": f"Bearer {agent['agent_credential']}"}
    client.get("/agent/commands/next", headers=authorization)
    return agent, scan, authorization


def _completed_result(agent: dict, scan: dict) -> dict:
    now = datetime.now(UTC).isoformat()
    return {
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
    }


def test_retrying_identical_host_result_does_not_duplicate_evidence(
    client: TestClient,
) -> None:
    agent, scan, authorization = _claimed_scan(client)
    path = (
        f"/agent/scans/{scan['scan_id']}/hosts/selected-device-0001/result"
    )
    result = _completed_result(agent, scan)

    first = client.post(path, headers=authorization, json=result)
    retry = client.post(path, headers=authorization, json=result)

    assert first.status_code == retry.status_code == 200
    assert first.json()["results"] == retry.json()["results"]
    assert len(retry.json()["results"]) == 1


def test_terminal_cancelled_scan_rejects_late_host_result(
    client: TestClient,
) -> None:
    agent, scan, authorization = _claimed_scan(client)
    cancelled = client.post(f"/api/scans/{scan['scan_id']}/cancel")
    assert cancelled.status_code == 200
    # A claimed command is still cancelling until the agent reports its outcome.
    now = datetime.now(UTC).isoformat()
    event = client.post(
        f"/agent/commands/{scan['command_id']}/events",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "command.event",
            "status": "cancelled",
            "message": "Scan cancelled",
            "details": {},
            "occurred_at": now,
        },
    )
    assert event.status_code == 200
    assert client.get(f"/api/scans/{scan['scan_id']}").json()["status"] == "cancelled"

    response = client.post(
        f"/agent/scans/{scan['scan_id']}/hosts/selected-device-0001/result",
        headers=authorization,
        json=_completed_result(agent, scan),
    )

    assert response.status_code == 422
    saved = client.get(f"/api/scans/{scan['scan_id']}").json()
    assert saved["status"] == "cancelled"
    assert saved["completed"] == 0
    assert saved["results"] == []


def test_cancelled_before_claim_rejects_late_host_result(
    client: TestClient,
) -> None:
    agent, discovery = completed_discovery(client)
    scan = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": ["selected-device-0001"],
            "profile": "standard",
            "authorization_confirmed": True,
        },
    ).json()
    cancelled = client.post(f"/api/scans/{scan['scan_id']}/cancel")
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"

    response = client.post(
        f"/agent/scans/{scan['scan_id']}/hosts/selected-device-0001/result",
        headers={"Authorization": f"Bearer {agent['agent_credential']}"},
        json=_completed_result(agent, scan),
    )

    assert response.status_code == 422
    assert client.get(f"/api/scans/{scan['scan_id']}").json()["results"] == []


def test_identical_result_retry_after_terminal_scan_is_idempotent(
    client: TestClient,
) -> None:
    agent, scan, authorization = _claimed_scan(client)
    path = f"/agent/scans/{scan['scan_id']}/hosts/selected-device-0001/result"
    result = _completed_result(agent, scan)
    assert client.post(path, headers=authorization, json=result).status_code == 200
    now = datetime.now(UTC).isoformat()
    for status in ("running", "completed"):
        event = client.post(
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
        assert event.status_code == 200
    assert client.get(f"/api/scans/{scan['scan_id']}").json()["status"] == "completed"

    retry = client.post(path, headers=authorization, json=result)
    assert retry.status_code == 200
    assert len(retry.json()["results"]) == 1


def test_raw_xml_fingerprint_and_hostname_source_survive_api_round_trip(
    client: TestClient,
) -> None:
    agent, scan, authorization = _claimed_scan(client)
    path = f"/agent/scans/{scan['scan_id']}/hosts/selected-device-0001/result"
    result = _completed_result(agent, scan)
    result.update(
        hostname="server.local",
        hostname_source="nmap",
        raw_xml_sha256="a" * 64,
    )

    response = client.post(path, headers=authorization, json=result)
    assert response.status_code == 200
    saved = client.get(f"/api/scans/{scan['scan_id']}").json()["results"][0]
    assert saved["hostname_source"] == "nmap"
    assert saved["raw_xml_sha256"] == "a" * 64


def test_invalid_raw_xml_fingerprint_is_rejected(client: TestClient) -> None:
    agent, scan, authorization = _claimed_scan(client)
    result = _completed_result(agent, scan)
    result["raw_xml_sha256"] = "not-a-sha256"

    response = client.post(
        f"/agent/scans/{scan['scan_id']}/hosts/selected-device-0001/result",
        headers=authorization,
        json=result,
    )

    assert response.status_code == 422


def test_progress_cannot_downgrade_uploaded_completed_host(
    client: TestClient,
) -> None:
    agent, scan, authorization = _claimed_scan(client)
    result = _completed_result(agent, scan)
    client.post(
        f"/agent/scans/{scan['scan_id']}/hosts/selected-device-0001/result",
        headers=authorization,
        json=result,
    )

    response = client.post(
        f"/agent/scans/{scan['scan_id']}/progress",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "scan.progress",
            "scan_id": scan["scan_id"],
            "agent_id": agent["agent_id"],
            "status": "failed",
            "stage": "result_delivery_failed",
            "total": 1,
            "queued": 0,
            "running": 0,
            "completed": 0,
            "failed": 1,
            "cancelled": 0,
            "updated_at": datetime.now(UTC).isoformat(),
        },
    )

    assert response.status_code == 422
    assert client.get(f"/api/scans/{scan['scan_id']}").json()["status"] != "failed"


def test_final_progress_cannot_claim_an_unsaved_completed_host(
    client: TestClient,
) -> None:
    agent, scan, authorization = _claimed_scan(client)
    response = client.post(
        f"/agent/scans/{scan['scan_id']}/progress",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "scan.progress",
            "scan_id": scan["scan_id"],
            "agent_id": agent["agent_id"],
            "status": "completed",
            "stage": "completed",
            "total": 1,
            "queued": 0,
            "running": 0,
            "completed": 1,
            "failed": 0,
            "cancelled": 0,
            "updated_at": datetime.now(UTC).isoformat(),
        },
    )

    assert response.status_code == 422
    assert client.get(f"/api/scans/{scan['scan_id']}").json()["status"] != "completed"


def test_failed_command_with_all_results_saved_reconciles_completed(
    client: TestClient,
) -> None:
    agent, scan, authorization = _claimed_scan(client)
    result = _completed_result(agent, scan)
    client.post(
        f"/agent/scans/{scan['scan_id']}/hosts/selected-device-0001/result",
        headers=authorization,
        json=result,
    )
    now = datetime.now(UTC).isoformat()
    for status in ("running", "failed"):
        event = client.post(
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
        assert event.status_code == 200

    saved = client.get(f"/api/scans/{scan['scan_id']}").json()
    assert saved["status"] == "completed"
    assert saved["stage"] == "command_failed"
    assert saved["completed"] == 1
    assert saved["failed"] == 0


@pytest.mark.parametrize(
    ("device_count", "expected_status", "expected_cancelled"),
    [(1, "completed", 0), (2, "partial", 1)],
)
def test_cancelled_command_preserves_saved_results(
    client: TestClient, device_count: int, expected_status: str,
    expected_cancelled: int,
) -> None:
    agent, scan, authorization = _claimed_scan(
        client, device_count=device_count
    )
    now = datetime.now(UTC).isoformat()
    running = client.post(
        f"/agent/commands/{scan['command_id']}/events",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "command.event",
            "status": "running",
            "message": "Scan running",
            "details": {},
            "occurred_at": now,
        },
    )
    assert running.status_code == 200
    result = client.post(
        f"/agent/scans/{scan['scan_id']}/hosts/selected-device-0001/result",
        headers=authorization,
        json=_completed_result(agent, scan),
    )
    assert result.status_code == 200
    assert client.post(f"/api/scans/{scan['scan_id']}/cancel").status_code == 200
    cancelled = client.post(
        f"/agent/commands/{scan['command_id']}/events",
        headers=authorization,
        json={
            "schema_version": "1.0",
            "message_type": "command.event",
            "status": "cancelled",
            "message": "Scan cancelled",
            "details": {},
            "occurred_at": now,
        },
    )
    assert cancelled.status_code == 200

    saved = client.get(f"/api/scans/{scan['scan_id']}").json()
    assert saved["status"] == expected_status
    assert saved["completed"] == 1
    assert saved["cancelled"] == expected_cancelled
    assert saved["failed"] == 0
    assert [target["status"] for target in saved["targets"]] == (
        ["completed", "cancelled"] if expected_cancelled else ["completed"]
    )
