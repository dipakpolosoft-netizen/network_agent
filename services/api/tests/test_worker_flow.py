from __future__ import annotations

from dataclasses import replace
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from forgesec_api.main import create_app
from forgesec_api.settings import Settings
from forgesec_api.workers.service import WorkerScopeError


def setup_site(client: TestClient, name: str, cidr: str) -> str:
    site = client.post("/api/sites", json={"name": name}).json()
    scope = client.post(
        f"/api/sites/{site['site_id']}/scopes",
        json={
            "cidr": cidr,
            "label": "Approved LAN",
            "exclusions": [cidr.replace("0/24", "99/32")],
            "scan_profiles": ["inventory", "network_services"],
        },
    )
    assert scope.status_code == 201
    return site["site_id"]


def provision(client: TestClient, site_id: str) -> dict:
    response = client.post(
        "/api/workers",
        json={
            "site_id": site_id,
            "label": "Central worker",
            "capabilities": ["network_inventory", "service_fingerprint"],
        },
    )
    assert response.status_code == 201
    return response.json()


def heartbeat(client: TestClient, worker: dict) -> None:
    response = client.post(
        "/worker/heartbeat",
        headers={"Authorization": f"Bearer {worker['credential']}"},
        json={
            "schema_version": "1.0",
            "worker_id": worker["worker_id"],
            "version": "0.1.0",
            "available_capabilities": ["network_inventory"],
        },
    )
    assert response.status_code == 200
    assert response.json()["status"] == "online"


def test_worker_contract_scope_lease_result_and_revoke(
    client: TestClient, settings: Settings
) -> None:
    site_id = setup_site(client, "HQ", "10.24.0.0/24")
    other_site = setup_site(client, "Branch", "10.25.0.0/24")
    worker = provision(client, site_id)
    other_worker = provision(client, other_site)
    credential = worker["credential"]
    headers = {"Authorization": f"Bearer {credential}"}
    assert credential not in str(client.get("/api/workers").json())
    persisted = list((settings.runtime_data_dir / "scanner-workers").glob("*.json"))
    assert persisted
    assert all(credential not in path.read_text(encoding="utf-8") for path in persisted)
    assert client.get("/worker/jobs/next").status_code == 401
    assert client.get("/worker/jobs/next", headers=headers).status_code == 204
    assert (
        client.post(
            "/worker/heartbeat",
            headers=headers,
            json={
                "schema_version": "1.0",
                "worker_id": worker["worker_id"],
                "version": "0.1.0",
                "available_capabilities": ["vulnerability_assessment"],
            },
        ).status_code
        == 409
    )
    heartbeat(client, worker)
    heartbeat(client, other_worker)

    service = client.app.state.worker_service
    with pytest.raises(WorkerScopeError):
        service.enqueue(
            site_id=site_id,
            capability="network_inventory",
            target_ip="10.24.0.99",
            profile="inventory",
        )
    job = service.enqueue(
        site_id=site_id,
        capability="network_inventory",
        target_ip="10.24.0.10",
        profile="inventory",
    )
    service.enqueue(
        site_id=other_site,
        capability="network_inventory",
        target_ip="10.25.0.10",
        profile="inventory",
    )
    claim = client.get("/worker/jobs/next", headers=headers)
    assert claim.status_code == 200
    assert claim.json()["job_id"] == job["job_id"]
    assert claim.json()["target_ip"] == "10.24.0.10"
    assert client.get("/worker/jobs/next", headers=headers).status_code == 204
    other_claim = client.get(
        "/worker/jobs/next",
        headers={"Authorization": f"Bearer {other_worker['credential']}"},
    )
    assert other_claim.status_code == 200
    assert other_claim.json()["site_id"] == other_site
    lease = claim.json()["lease_id"]
    assert (
        client.post(
            f"/worker/jobs/{job['job_id']}/heartbeat",
            headers=headers,
            json={"lease_id": str(uuid4())},
        ).status_code
        == 409
    )
    assert (
        client.post(
            f"/worker/jobs/{job['job_id']}/heartbeat",
            headers=headers,
            json={"lease_id": lease},
        ).status_code
        == 200
    )
    result = {
        "schema_version": "1.0",
        "lease_id": lease,
        "status": "completed",
        "summary": "Inventory evidence collected",
        "evidence": {"observed_ports": [22, 443]},
    }
    assert (
        client.post(
            f"/worker/jobs/{job['job_id']}/result",
            headers={"Authorization": f"Bearer {other_worker['credential']}"},
            json=result,
        ).status_code
        == 409
    )
    completed = client.post(
        f"/worker/jobs/{job['job_id']}/result", headers=headers, json=result
    )
    assert completed.status_code == 200
    assert completed.json()["status"] == "completed"
    assert (
        client.post(
            f"/worker/jobs/{job['job_id']}/result", headers=headers, json=result
        ).status_code
        == 200
    )
    assert client.post(f"/api/workers/{worker['worker_id']}/revoke").status_code == 200
    assert client.get("/worker/jobs/next", headers=headers).status_code == 401


def test_removed_scope_and_expired_lease_block_worker_result(
    client: TestClient,
) -> None:
    site_id = setup_site(client, "Lab", "10.26.0.0/24")
    worker = provision(client, site_id)
    heartbeat(client, worker)
    headers = {"Authorization": f"Bearer {worker['credential']}"}
    service = client.app.state.worker_service
    job = service.enqueue(
        site_id=site_id,
        capability="network_inventory",
        target_ip="10.26.0.10",
        profile="inventory",
    )
    first = client.get("/worker/jobs/next", headers=headers).json()
    record = service.store.read("scanner-worker-jobs", job["job_id"])
    record["lease_expires_at"] = "2020-01-01T00:00:00Z"
    service.store.write("scanner-worker-jobs", job["job_id"], record)
    second = client.get("/worker/jobs/next", headers=headers).json()
    assert second["attempt"] == 2
    assert second["lease_id"] != first["lease_id"]
    assert (
        client.post(
            f"/worker/jobs/{job['job_id']}/result",
            headers=headers,
            json={
                "schema_version": "1.0",
                "lease_id": first["lease_id"],
                "status": "completed",
                "summary": "Stale result",
            },
        ).status_code
        == 409
    )
    scope_id = client.get(f"/api/sites/{site_id}/scopes").json()[0]["scope_id"]
    assert client.delete(f"/api/sites/{site_id}/scopes/{scope_id}").status_code == 204
    assert (
        client.post(
            f"/worker/jobs/{job['job_id']}/result",
            headers=headers,
            json={
                "schema_version": "1.0",
                "lease_id": second["lease_id"],
                "status": "completed",
                "summary": "No longer approved",
            },
        ).status_code
        == 409
    )
    assert service.list_jobs()[0]["status"] == "cancelled"


def test_revocation_requeues_lease_and_removed_scope_cancels_queue(
    client: TestClient,
) -> None:
    site_id = setup_site(client, "Test site", "10.27.0.0/24")
    first = provision(client, site_id)
    replacement = provision(client, site_id)
    heartbeat(client, first)
    heartbeat(client, replacement)
    service = client.app.state.worker_service
    job = service.enqueue(
        site_id=site_id,
        capability="network_inventory",
        target_ip="10.27.0.10",
        profile="inventory",
    )
    first_headers = {"Authorization": f"Bearer {first['credential']}"}
    assert client.get("/worker/jobs/next", headers=first_headers).status_code == 200
    assert client.post(f"/api/workers/{first['worker_id']}/revoke").status_code == 200
    assert (
        service.store.read("scanner-worker-jobs", job["job_id"])["status"] == "queued"
    )
    replacement_headers = {"Authorization": f"Bearer {replacement['credential']}"}
    retry = client.get("/worker/jobs/next", headers=replacement_headers)
    assert retry.status_code == 200
    assert retry.json()["attempt"] == 2

    pending = service.enqueue(
        site_id=site_id,
        capability="network_inventory",
        target_ip="10.27.0.11",
        profile="inventory",
    )
    scope_id = client.get(f"/api/sites/{site_id}/scopes").json()[0]["scope_id"]
    assert client.delete(f"/api/sites/{site_id}/scopes/{scope_id}").status_code == 204
    assert (
        client.post(
            f"/worker/jobs/{job['job_id']}/heartbeat",
            headers=replacement_headers,
            json={"lease_id": retry.json()["lease_id"]},
        ).status_code
        == 409
    )
    assert (
        client.get("/worker/jobs/next", headers=replacement_headers).status_code == 204
    )
    assert (
        service.store.read("scanner-worker-jobs", pending["job_id"])["status"]
        == "cancelled"
    )


def test_only_admin_can_provision_worker(settings: Settings) -> None:
    app = create_app(replace(settings, auth_required=True))
    with TestClient(app) as client:
        app.state.auth_service.create_user(
            "operator@example.test", "operator password here", "operator"
        )
        login = client.post(
            "/api/auth/login",
            json={
                "email": "operator@example.test",
                "password": "operator password here",
            },
        ).json()
        response = client.post(
            "/api/workers",
            headers={"X-CSRF-Token": login["csrf_token"]},
            json={
                "site_id": str(uuid4()),
                "label": "Unauthorized",
                "capabilities": ["network_inventory"],
            },
        )
        assert response.status_code == 403


def test_worker_job_history_filters_by_site_and_asset(client: TestClient) -> None:
    hq = setup_site(client, "HQ", "10.40.0.0/24")
    branch = setup_site(client, "Branch", "10.41.0.0/24")
    asset_id = str(uuid4())
    service = client.app.state.worker_service
    first = service.enqueue(
        site_id=hq,
        capability="network_inventory",
        target_ip="10.40.0.10",
        profile="inventory",
        source_asset_id=asset_id,
    )
    service.enqueue(
        site_id=hq,
        capability="network_inventory",
        target_ip="10.40.0.11",
        profile="inventory",
    )
    service.enqueue(
        site_id=branch,
        capability="network_inventory",
        target_ip="10.41.0.10",
        profile="inventory",
    )
    by_site = client.get("/api/worker-jobs", params={"site_id": hq})
    assert by_site.status_code == 200
    assert len(by_site.json()) == 2
    assert {job["site_id"] for job in by_site.json()} == {hq}
    both = client.get("/api/worker-jobs", params={"site_id": hq, "asset_id": asset_id})
    assert [job["job_id"] for job in both.json()] == [first["job_id"]]
    assert "evidence" not in both.json()[0]
