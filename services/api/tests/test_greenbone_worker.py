from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from uuid import uuid4
from xml.etree import ElementTree as ET

import pytest
from fastapi.testclient import TestClient
from test_nuclei_worker import ready_worker, web_asset

from forgesec_api.main import create_app
from forgesec_api.settings import Settings
from forgesec_api.workers.greenbone_runtime import (
    GreenboneSettings,
    WorkerLeaseLost,
    _findings,
    _target,
    run_forever,
    run_greenbone,
)
from forgesec_api.workers.runtime_client import WorkerRuntimeError

TASK_ID = "00000000-0000-0000-0000-000000000011"
TARGET_ID = "00000000-0000-0000-0000-000000000012"
REPORT_ID = "00000000-0000-0000-0000-000000000013"
RESULT_ID = "00000000-0000-0000-0000-000000000014"
CONFIG_ID = "00000000-0000-0000-0000-000000000015"
SCANNER_ID = "00000000-0000-0000-0000-000000000016"
PORT_LIST_ID = "00000000-0000-0000-0000-000000000017"


def greenbone_worker(client: TestClient, site_id: str) -> dict:
    worker = client.post(
        "/api/workers",
        json={
            "site_id": site_id,
            "label": "Advanced worker",
            "capabilities": ["greenbone_assessment"],
        },
    ).json()
    response = client.post(
        "/worker/heartbeat",
        headers={"Authorization": f"Bearer {worker['credential']}"},
        json={
            "schema_version": "1.0",
            "worker_id": worker["worker_id"],
            "version": "0.1.0-greenbone",
            "available_capabilities": ["greenbone_assessment"],
        },
    )
    assert response.status_code == 200
    return worker


def greenbone_request(asset_id: str) -> dict:
    return {
        "asset_id": asset_id,
        "authorization_confirmed": True,
        "maintenance_window_confirmed": True,
    }


def test_greenbone_job_is_site_bound_and_evidence_is_bounded(
    client: TestClient,
) -> None:
    agent, asset = web_asset(client)
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    path = "/api/worker-jobs/greenbone"
    payload = greenbone_request(asset["asset_id"])
    assert client.post(path, json=payload).status_code == 409
    assert (
        client.post(
            path, json={**payload, "maintenance_window_confirmed": False}
        ).status_code
        == 422
    )
    nuclei = ready_worker(client, site_id)
    worker = greenbone_worker(client, site_id)
    queued = client.post(path, json=payload)
    assert queued.status_code == 202
    job = queued.json()
    assert job["capability"] == "greenbone_assessment"
    assert job["profile"] == "full_tcp"
    assert job["assessment_profile"] == "greenbone_single_host"
    assert job["target_ip"] == asset["last_ip"]
    assert client.post(path, json=payload).status_code == 409
    nuclei_headers = {"Authorization": f"Bearer {nuclei['credential']}"}
    greenbone_headers = {"Authorization": f"Bearer {worker['credential']}"}
    assert client.get("/worker/jobs/next", headers=nuclei_headers).status_code == 204
    claim = client.get("/worker/jobs/next", headers=greenbone_headers).json()
    assert claim["job_id"] == job["job_id"]
    renewed = client.post(
        f"/worker/jobs/{job['job_id']}/heartbeat",
        headers=greenbone_headers,
        json={"lease_id": claim["lease_id"], "progress": 38, "phase": "Running"},
    )
    assert renewed.status_code == 200
    assert renewed.json()["progress"] == 38
    evidence = {
        "schema_version": "1.0",
        "engine": "greenbone",
        "target_ip": job["target_ip"],
        "assessment_profile": "greenbone_single_host",
        "task_id": TASK_ID,
        "report_id": REPORT_ID,
        "findings": [
            {
                "result_id": RESULT_ID,
                "name": "Example finding",
                "severity": 7.5,
                "host": job["target_ip"],
                "port": "8080/tcp",
                "nvt_oid": "1.3.6.1.4.1.25623.1.0.1",
                "cves": ["CVE-2025-12345"],
            }
        ],
        "truncated": False,
    }
    result = {
        "schema_version": "1.0",
        "lease_id": claim["lease_id"],
        "status": "completed",
        "summary": "1 Greenbone finding returned",
        "evidence": evidence,
    }
    foreign = {
        **result,
        "evidence": {
            **evidence,
            "findings": [{**evidence["findings"][0], "host": "192.168.1.99"}],
        },
    }
    assert (
        client.post(
            f"/worker/jobs/{job['job_id']}/result",
            headers=greenbone_headers,
            json=foreign,
        ).status_code
        == 409
    )
    assert (
        client.post(
            f"/worker/jobs/{job['job_id']}/result",
            headers=greenbone_headers,
            json=result,
        ).status_code
        == 200
    )
    detail = client.get(f"/api/worker-jobs/{job['job_id']}").json()
    assert detail["progress"] == 100
    assert detail["evidence"]["engine"] == "greenbone"
    assert detail["evidence"]["findings"][0]["host"] == asset["last_ip"]
    assert "evidence" not in client.get("/api/worker-jobs").json()[0]


def test_greenbone_requires_full_tcp_approval_and_current_asset(
    client: TestClient,
) -> None:
    agent, asset = web_asset(client)
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    worker = greenbone_worker(client, site_id)
    scope = client.get(f"/api/sites/{site_id}/scopes").json()[0]
    stored = client.app.state.store.read("approved-scopes", scope["scope_id"])
    stored["scan_profiles"] = ["standard"]
    client.app.state.store.write("approved-scopes", scope["scope_id"], stored)
    payload = greenbone_request(asset["asset_id"])
    assert client.post("/api/worker-jobs/greenbone", json=payload).status_code == 409
    stored["scan_profiles"].append("full_tcp")
    client.app.state.store.write("approved-scopes", scope["scope_id"], stored)
    job = client.post("/api/worker-jobs/greenbone", json=payload).json()
    saved_asset = client.app.state.store.read("assets", asset["asset_id"])
    saved_asset["last_ip"] = "192.168.1.11"
    client.app.state.store.write("assets", asset["asset_id"], saved_asset)
    assert (
        client.get(
            "/worker/jobs/next",
            headers={"Authorization": f"Bearer {worker['credential']}"},
        ).status_code
        == 204
    )
    assert (
        client.get(f"/api/worker-jobs/{job['job_id']}").json()["status"] == "cancelled"
    )


def test_greenbone_cancel_revokes_active_lease(client: TestClient) -> None:
    agent, asset = web_asset(client)
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    worker = greenbone_worker(client, site_id)
    headers = {"Authorization": f"Bearer {worker['credential']}"}
    job = client.post(
        "/api/worker-jobs/greenbone", json=greenbone_request(asset["asset_id"])
    ).json()
    claim = client.get("/worker/jobs/next", headers=headers).json()
    cancelled = client.post(f"/api/worker-jobs/{job['job_id']}/cancel")
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"
    assert (
        client.post(
            f"/worker/jobs/{job['job_id']}/heartbeat",
            headers=headers,
            json={"lease_id": claim["lease_id"]},
        ).status_code
        == 409
    )
    assert (
        client.post(
            "/api/worker-jobs/greenbone", json=greenbone_request(asset["asset_id"])
        ).status_code
        == 409
    )
    assert client.post(f"/api/worker-jobs/{job['job_id']}/cancel").status_code == 409


def test_greenbone_worker_failure_is_not_a_clean_report(client: TestClient) -> None:
    agent, asset = web_asset(client)
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    worker = greenbone_worker(client, site_id)
    headers = {"Authorization": f"Bearer {worker['credential']}"}
    job = client.post(
        "/api/worker-jobs/greenbone", json=greenbone_request(asset["asset_id"])
    ).json()
    claim = client.get("/worker/jobs/next", headers=headers).json()
    failed = client.post(
        f"/worker/jobs/{job['job_id']}/result",
        headers=headers,
        json={
            "schema_version": "1.0",
            "lease_id": claim["lease_id"],
            "status": "failed",
            "summary": "Greenbone did not verify the target host",
            "evidence": {},
        },
    )
    assert failed.status_code == 200
    detail = client.get(f"/api/worker-jobs/{job['job_id']}").json()
    assert detail["status"] == "failed"
    assert detail["evidence"] is None
    assert "did not verify" in detail["summary"]


def test_greenbone_queue_is_admin_only_and_csrf_protected(settings: Settings) -> None:
    app = create_app(replace(settings, auth_required=True))
    with TestClient(app) as client:
        auth = app.state.auth_service
        auth.create_user("operator@example.test", "operator password 123", "operator")
        auth.create_user("admin@example.test", "admin password 123", "admin")
        payload = greenbone_request("00000000-0000-0000-0000-000000000001")
        assert (
            client.post("/api/worker-jobs/greenbone", json=payload).status_code == 401
        )
        signed_in = client.post(
            "/api/auth/login",
            json={
                "email": "operator@example.test",
                "password": "operator password 123",
            },
        )
        assert signed_in.status_code == 200
        assert (
            client.post(
                "/api/worker-jobs/greenbone",
                json=payload,
                headers={"X-CSRF-Token": signed_in.json()["csrf_token"]},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/api/worker-jobs/00000000-0000-0000-0000-000000000001/cancel",
                headers={"X-CSRF-Token": signed_in.json()["csrf_token"]},
            ).status_code
            == 403
        )
        client.post(
            "/api/auth/logout",
            headers={"X-CSRF-Token": signed_in.json()["csrf_token"]},
        )
        admin = client.post(
            "/api/auth/login",
            json={"email": "admin@example.test", "password": "admin password 123"},
        )
        assert (
            client.post("/api/worker-jobs/greenbone", json=payload).status_code == 403
        )
        assert (
            client.post(
                "/api/worker-jobs/greenbone",
                json=payload,
                headers={"X-CSRF-Token": admin.json()["csrf_token"]},
            ).status_code
            == 409
        )


class FakeGmp:
    def __init__(self):
        self.statuses = iter(["New", "Running", "Done"])
        self.started = False
        self.stopped = False
        self.created_targets = 0
        self.created_tasks = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def authenticate(self, username, password):
        assert username == "forgesec"
        assert password == "secret"

    def get_targets(self, **kwargs):
        return ET.fromstring("<get_targets_response />")

    def create_target(self, **kwargs):
        assert kwargs["hosts"] == ["192.168.1.10"]
        assert kwargs["port_list_id"] == PORT_LIST_ID
        self.created_targets += 1
        return ET.fromstring(f'<create_target_response id="{TARGET_ID}" />')

    def get_tasks(self, **kwargs):
        return ET.fromstring("<get_tasks_response />")

    def create_task(self, **kwargs):
        assert kwargs["config_id"] == CONFIG_ID
        assert kwargs["scanner_id"] == SCANNER_ID
        self.created_tasks += 1
        return ET.fromstring(f'<create_task_response id="{TASK_ID}" />')

    def get_task(self, task_id):
        assert task_id == TASK_ID
        status = next(self.statuses)
        return ET.fromstring(
            f'<get_task_response><task id="{TASK_ID}"><status>{status}</status>'
            f'<progress>50</progress><target id="{TARGET_ID}" />'
            f'<config id="{CONFIG_ID}" /><scanner id="{SCANNER_ID}" />'
            f'<last_report><report id="{REPORT_ID}" /></last_report>'
            "</task></get_task_response>"
        )

    def start_task(self, task_id):
        self.started = True
        return ET.fromstring(
            f"<start_task_response><report_id>{REPORT_ID}</report_id></start_task_response>"
        )

    def get_report(self, report_id, **kwargs):
        assert report_id == REPORT_ID
        return ET.fromstring(
            f'<get_report_response><report id="{REPORT_ID}">'
            f'<report id="{REPORT_ID}"><results><result id="{RESULT_ID}">'
            "<host>192.168.1.10</host><port>8080/tcp</port>"
            "<name>Example finding</name><severity>7.5</severity>"
            '<nvt oid="1.3.6.1.4.1.1"><refs>'
            '<ref type="cve" id="CVE-2025-12345" />'
            "</refs></nvt></result></results></report>"
            "</report></get_report_response>"
        )

    def stop_task(self, task_id):
        self.stopped = True


class ExistingTaskGmp(FakeGmp):
    def __init__(self):
        super().__init__()
        self.statuses = iter(["Running", "Done"])

    def get_targets(self, **kwargs):
        name = f"ForgeSec advanced {runtime_job()['job_id']}"
        return ET.fromstring(
            f'<get_targets_response><target id="{TARGET_ID}">'
            f"<name>{name}</name></target></get_targets_response>"
        )

    def get_target(self, target_id):
        return ET.fromstring(
            f'<get_target_response><target id="{TARGET_ID}">'
            f'<hosts>192.168.1.10</hosts><port_list id="{PORT_LIST_ID}" />'
            "</target></get_target_response>"
        )

    def get_tasks(self, **kwargs):
        name = f"ForgeSec advanced {runtime_job()['job_id']}"
        return ET.fromstring(
            f'<get_tasks_response><task id="{TASK_ID}">'
            f"<name>{name}</name></task></get_tasks_response>"
        )


def runtime_job() -> dict:
    return {
        "schema_version": "1.0",
        "job_id": "00000000-0000-0000-0000-000000000021",
        "lease_id": "00000000-0000-0000-0000-000000000022",
        "source_asset_id": "00000000-0000-0000-0000-000000000023",
        "source_scan_id": "00000000-0000-0000-0000-000000000024",
        "target_ip": "192.168.1.10",
        "target_port": None,
        "target_scheme": None,
        "template_profile": None,
        "profile": "full_tcp",
        "capability": "greenbone_assessment",
        "assessment_profile": "greenbone_single_host",
    }


def runtime_settings() -> GreenboneSettings:
    return GreenboneSettings(
        socket_path=Path("/run/gvmd/gvmd.sock"),
        username="forgesec",
        password="secret",
        config_id=CONFIG_ID,
        scanner_id=SCANNER_ID,
        port_list_id=PORT_LIST_ID,
    )


def test_greenbone_adapter_creates_single_host_task_and_reduces_results() -> None:
    gmp = FakeGmp()
    phases = []
    evidence = run_greenbone(
        runtime_job(),
        runtime_settings(),
        on_tick=lambda progress, phase: phases.append((progress, phase)),
        gmp_factory=lambda settings: gmp,
        sleep=lambda seconds: None,
    )
    assert gmp.created_targets == 1
    assert gmp.created_tasks == 1
    assert gmp.started
    assert not gmp.stopped
    assert evidence["engine"] == "greenbone"
    assert evidence["target_ip"] == "192.168.1.10"
    assert evidence["findings"][0]["cves"] == ["CVE-2025-12345"]
    assert (100, "Collecting results") in phases
    with pytest.raises(WorkerRuntimeError):
        _target({**runtime_job(), "target_ip": "not-an-ip"})


def test_greenbone_adapter_stops_task_when_lease_is_lost() -> None:
    gmp = FakeGmp()

    def lose_lease(progress, phase):
        if phase == "New":
            raise WorkerLeaseLost("Lease lost")

    with pytest.raises(WorkerLeaseLost):
        run_greenbone(
            runtime_job(),
            runtime_settings(),
            on_tick=lose_lease,
            gmp_factory=lambda settings: gmp,
            sleep=lambda seconds: None,
        )
    assert gmp.started
    assert gmp.stopped


def test_greenbone_rechecks_lease_before_start_task() -> None:
    gmp = FakeGmp()

    def lose_lease(progress, phase):
        if phase == "Starting":
            raise WorkerLeaseLost("Scope removed")

    with pytest.raises(WorkerLeaseLost):
        run_greenbone(
            runtime_job(),
            runtime_settings(),
            on_tick=lose_lease,
            gmp_factory=lambda settings: gmp,
            sleep=lambda seconds: None,
        )
    assert gmp.created_tasks == 1
    assert gmp.started is False


@pytest.mark.parametrize("lease_available", [True, False])
def test_greenbone_worker_renews_before_gmp_and_each_checkpoint(
    monkeypatch: pytest.MonkeyPatch, lease_available: bool
) -> None:
    events: list[str] = []
    job = runtime_job()

    class Client:
        def __init__(self):
            self.claims = 0

        def heartbeat(self):
            events.append("heartbeat")

        def claim(self):
            self.claims += 1
            if self.claims > 1:
                raise KeyboardInterrupt
            return job

        def renew(self, claimed_job, *, progress=None, phase=None):
            assert claimed_job is job
            events.append(f"renew:{phase}")
            if not lease_available:
                raise WorkerRuntimeError("HTTP 409")

        def finish(self, claimed_job, status, summary, evidence):
            assert claimed_job is job
            assert status == "completed"
            events.append("finish")

    def fake_scan(claimed_job, settings, *, on_tick):
        assert claimed_job is job
        events.append("gmp")
        on_tick(None, "Preparing")
        on_tick(None, "Starting")
        on_tick(50, "Running")
        return {"findings": []}

    monkeypatch.setattr(
        "forgesec_api.workers.greenbone_runtime.run_greenbone", fake_scan
    )
    with pytest.raises(KeyboardInterrupt):
        run_forever(Client(), runtime_settings())
    assert events == (
        [
            "heartbeat",
            "renew:Preparing",
            "gmp",
            "renew:Preparing",
            "renew:Starting",
            "renew:Running",
            "finish",
        ]
        if lease_available
        else ["heartbeat", "renew:Preparing"]
    )


def test_greenbone_adapter_stops_task_on_keyboard_interrupt() -> None:
    gmp = FakeGmp()

    def interrupt(progress, phase):
        if phase == "New":
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        run_greenbone(
            runtime_job(),
            runtime_settings(),
            on_tick=interrupt,
            gmp_factory=lambda settings: gmp,
            sleep=lambda seconds: None,
        )
    assert gmp.started
    assert gmp.stopped


def test_greenbone_retry_reattaches_without_creating_duplicate_task() -> None:
    gmp = ExistingTaskGmp()
    evidence = run_greenbone(
        runtime_job(),
        runtime_settings(),
        on_tick=lambda progress, phase: None,
        gmp_factory=lambda settings: gmp,
        sleep=lambda seconds: None,
    )
    assert evidence["report_id"] == REPORT_ID
    assert gmp.created_targets == 0
    assert gmp.created_tasks == 0
    assert not gmp.started


def test_greenbone_report_rejects_foreign_host() -> None:
    class ForeignReportGmp(FakeGmp):
        def get_report(self, report_id, **kwargs):
            response = super().get_report(report_id, **kwargs)
            response.find(".//result/host").text = "192.168.1.99"
            return response

    gmp = ForeignReportGmp()
    with pytest.raises(WorkerRuntimeError, match="out-of-scope"):
        run_greenbone(
            runtime_job(),
            runtime_settings(),
            on_tick=lambda progress, phase: None,
            gmp_factory=lambda settings: gmp,
            sleep=lambda seconds: None,
        )
    assert gmp.stopped


def test_greenbone_report_checks_entire_bounded_page_and_total() -> None:
    response = ET.fromstring(
        f'<get_report_response><report id="{REPORT_ID}">'
        f'<report id="{REPORT_ID}"><scan_run_status>Done</scan_run_status>'
        "<hosts><count>1</count></hosts><errors><count>0</count></errors>"
        "<result_count><filtered>75</filtered></result_count><results />"
        "</report></report></get_report_response>"
    )
    results = response.find("report/report/results")
    for _ in range(51):
        item = ET.SubElement(results, "result", id=str(uuid4()))
        ET.SubElement(item, "host").text = "192.168.1.10"
        ET.SubElement(item, "severity").text = "5.0"
    results[-1].find("host").text = "192.168.1.99"
    with pytest.raises(WorkerRuntimeError, match="out-of-scope"):
        _findings(response, "192.168.1.10", REPORT_ID)

    results[-1].find("host").text = "192.168.1.10"
    findings, truncated = _findings(response, "192.168.1.10", REPORT_ID)
    assert len(findings) == 50
    assert truncated is True
    results.remove(results[-1])
    findings, truncated = _findings(response, "192.168.1.10", REPORT_ID)
    assert len(findings) == 50
    assert truncated is True

    results.remove(results[-1])
    with pytest.raises(WorkerRuntimeError, match="result page is incomplete"):
        _findings(response, "192.168.1.10", REPORT_ID)

    response.find("report/report/result_count/filtered").text = "50"
    with pytest.raises(WorkerRuntimeError, match="result page is incomplete"):
        _findings(response, "192.168.1.10", REPORT_ID)


def test_empty_greenbone_report_requires_completed_host_coverage() -> None:
    response = ET.fromstring(
        f'<get_report_response><report id="{REPORT_ID}">'
        f'<report id="{REPORT_ID}"><scan_run_status>Done</scan_run_status>'
        "<hosts><count>0</count></hosts><errors><count>0</count></errors>"
        "<result_count><filtered>0</filtered></result_count><results />"
        "</report></report></get_report_response>"
    )
    with pytest.raises(WorkerRuntimeError, match="did not verify"):
        _findings(response, "192.168.1.10", REPORT_ID)

    response.find("report/report/hosts/count").text = "1"
    assert _findings(response, "192.168.1.10", REPORT_ID) == ([], False)
    response.find("report/report/result_count/filtered").text = "1"
    with pytest.raises(WorkerRuntimeError, match="omitted expected"):
        _findings(response, "192.168.1.10", REPORT_ID)
    response.find("report/report/result_count/filtered").text = "0"
    response.find("report/report/errors/count").text = "1"
    with pytest.raises(WorkerRuntimeError, match="scan errors"):
        _findings(response, "192.168.1.10", REPORT_ID)
    response.find("report/report/errors").remove(
        response.find("report/report/errors/count")
    )
    with pytest.raises(WorkerRuntimeError, match="coverage is unavailable"):
        _findings(response, "192.168.1.10", REPORT_ID)


def test_greenbone_start_failure_attempts_task_cleanup() -> None:
    class UncertainStartGmp(FakeGmp):
        def start_task(self, task_id):
            self.started = True
            raise OSError("GMP response was lost after starting")

    gmp = UncertainStartGmp()
    with pytest.raises(OSError):
        run_greenbone(
            runtime_job(),
            runtime_settings(),
            on_tick=lambda progress, phase: None,
            gmp_factory=lambda settings: gmp,
            sleep=lambda seconds: None,
        )
    assert gmp.stopped is True
