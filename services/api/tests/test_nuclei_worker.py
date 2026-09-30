from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from test_scan_flow import completed_discovery

from forgesec_api.main import create_app
from forgesec_api.settings import Settings
from forgesec_api.workers.nuclei_runtime import (
    WorkerLeaseLost,
    WorkerRuntimeError,
    _base_url,
    build_command,
    parse_findings,
    run_forever,
    run_nuclei,
    verify_clear_response,
)

TEMPLATE_ID = "forgesec-http-missing-x-content-type-options"


def web_asset(client: TestClient) -> tuple[dict, dict]:
    agent, discovery = completed_discovery(client, device_count=1)
    scan = client.post(
        f"/api/discoveries/{discovery['discovery_id']}/scan",
        json={
            "device_ids": ["selected-device-0001"],
            "profile": "standard",
            "authorization_confirmed": True,
        },
    ).json()
    now = datetime.now(UTC).isoformat()
    result = client.post(
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
            "hostname": "test-web",
            "device_type": "server",
            "classification_confidence": 0.9,
            "ports": [
                {
                    "protocol": "tcp",
                    "port": 8080,
                    "state": "open",
                    "service": "http",
                    "product": "Example",
                    "version": "1.0",
                },
                {"protocol": "tcp", "port": 22, "state": "open", "service": "ssh"},
            ],
            "os_matches": [],
            "exposure_flags": [],
            "error": None,
        },
    )
    assert result.status_code == 200
    asset = client.get("/api/assets").json()["items"][0]
    return agent, asset


def ready_worker(client: TestClient, site_id: str) -> dict:
    worker = client.post(
        "/api/workers",
        json={
            "site_id": site_id,
            "label": "Nuclei worker",
            "capabilities": ["vulnerability_assessment"],
        },
    ).json()
    heartbeat = client.post(
        "/worker/heartbeat",
        headers={"Authorization": f"Bearer {worker['credential']}"},
        json={
            "schema_version": "1.0",
            "worker_id": worker["worker_id"],
            "version": "0.1.0-nuclei",
            "available_capabilities": ["vulnerability_assessment"],
        },
    )
    assert heartbeat.status_code == 200
    return worker


def test_nuclei_job_requires_observed_web_service_and_validates_evidence(
    client: TestClient,
) -> None:
    agent, asset = web_asset(client)
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    path = "/api/worker-jobs/nuclei"
    request = {
        "asset_id": asset["asset_id"],
        "port": 8080,
        "scheme": "http",
        "authorization_confirmed": True,
    }
    assert client.post(path, json=request).status_code == 409
    worker = ready_worker(client, site_id)
    headers = {"Authorization": f"Bearer {worker['credential']}"}
    assert client.post(path, json={**request, "port": 22}).status_code == 409
    assert client.post(path, json={**request, "port": 8443}).status_code == 409
    assert (
        client.post(
            path, json={**request, "authorization_confirmed": False}
        ).status_code
        == 422
    )
    queued = client.post(path, json=request)
    assert queued.status_code == 202
    job = queued.json()
    assert job["target_ip"] == "192.168.1.10"
    assert job["target_port"] == 8080
    assert job["source_asset_id"] == asset["asset_id"]
    assert client.post(path, json=request).status_code == 409
    assert (
        len(
            client.get(
                "/api/worker-jobs", params={"asset_id": asset["asset_id"]}
            ).json()
        )
        == 1
    )

    claimed = client.get("/worker/jobs/next", headers=headers).json()
    assert claimed["job_id"] == job["job_id"]
    assert claimed["template_profile"] == "http_baseline"
    result = {
        "schema_version": "1.0",
        "lease_id": claimed["lease_id"],
        "status": "completed",
        "summary": "1 web configuration observation",
        "evidence": {
            "schema_version": "1.0",
            "engine": "nuclei",
            "target_url": "http://192.168.1.10:8080",
            "template_profile": "http_baseline",
            "findings": [
                {
                    "template_id": TEMPLATE_ID,
                    "severity": "low",
                    "title": "Missing X-Content-Type-Options header",
                    "matched_at": "http://192.168.1.10:8080/",
                }
            ],
        },
    }
    foreign = json.loads(json.dumps(result))
    foreign["evidence"]["findings"][0]["matched_at"] = "http://192.168.1.99:8080/"
    assert (
        client.post(
            f"/worker/jobs/{job['job_id']}/result", headers=headers, json=foreign
        ).status_code
        == 409
    )
    completed = client.post(
        f"/worker/jobs/{job['job_id']}/result", headers=headers, json=result
    )
    assert completed.status_code == 200
    detail = client.get(f"/api/worker-jobs/{job['job_id']}").json()
    assert detail["evidence"]["findings"][0]["template_id"] == TEMPLATE_ID
    assert "evidence" not in client.get("/api/worker-jobs").json()[0]


def test_nuclei_job_cancels_when_asset_ip_changes(client: TestClient) -> None:
    agent, asset = web_asset(client)
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    worker = ready_worker(client, site_id)
    queued = client.post(
        "/api/worker-jobs/nuclei",
        json={
            "asset_id": asset["asset_id"],
            "port": 8080,
            "scheme": "http",
            "authorization_confirmed": True,
        },
    ).json()
    stored = client.app.state.store.read("assets", asset["asset_id"])
    stored["last_ip"] = "192.168.1.11"
    client.app.state.store.write("assets", asset["asset_id"], stored)
    assert (
        client.get(
            "/worker/jobs/next",
            headers={"Authorization": f"Bearer {worker['credential']}"},
        ).status_code
        == 204
    )
    assert (
        client.get(f"/api/worker-jobs/{queued['job_id']}").json()["status"]
        == "cancelled"
    )


def test_nuclei_job_stops_if_claimed_asset_changes(client: TestClient) -> None:
    agent, asset = web_asset(client)
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    worker = ready_worker(client, site_id)
    headers = {"Authorization": f"Bearer {worker['credential']}"}
    queued = client.post(
        "/api/worker-jobs/nuclei",
        json={
            "asset_id": asset["asset_id"],
            "port": 8080,
            "scheme": "http",
            "authorization_confirmed": True,
        },
    ).json()
    claimed = client.get("/worker/jobs/next", headers=headers).json()
    stored = client.app.state.store.read("assets", asset["asset_id"])
    stored["last_ip"] = "192.168.1.11"
    client.app.state.store.write("assets", asset["asset_id"], stored)
    rejected = client.post(
        f"/worker/jobs/{queued['job_id']}/result",
        headers=headers,
        json={
            "schema_version": "1.0",
            "lease_id": claimed["lease_id"],
            "status": "failed",
            "summary": "Target changed",
            "evidence": {},
        },
    )
    assert rejected.status_code == 409
    detail = client.get(f"/api/worker-jobs/{queued['job_id']}").json()
    assert detail["status"] == "cancelled"
    assert detail["summary"] == "Source asset changed after job creation"


def test_nuclei_stop_invalidates_lease_and_failed_result_has_no_evidence(
    client: TestClient,
) -> None:
    agent, asset = web_asset(client)
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    worker = ready_worker(client, site_id)
    headers = {"Authorization": f"Bearer {worker['credential']}"}
    request = {
        "asset_id": asset["asset_id"],
        "port": 8080,
        "scheme": "http",
        "authorization_confirmed": True,
    }
    queued = client.post("/api/worker-jobs/nuclei", json=request).json()
    stopped = client.post(f"/api/worker-jobs/{queued['job_id']}/cancel")
    assert stopped.status_code == 200
    assert stopped.json()["status"] == "cancelled"
    assert client.get("/worker/jobs/next", headers=headers).status_code == 204

    queued = client.post("/api/worker-jobs/nuclei", json=request).json()
    claimed = client.get("/worker/jobs/next", headers=headers).json()
    bad = client.post(
        f"/worker/jobs/{queued['job_id']}/result",
        headers=headers,
        json={
            "schema_version": "1.0",
            "lease_id": claimed["lease_id"],
            "status": "failed",
            "summary": "No route to target",
            "evidence": {"findings": []},
        },
    )
    assert bad.status_code == 409
    stopped = client.post(f"/api/worker-jobs/{queued['job_id']}/cancel")
    assert stopped.status_code == 200
    assert (
        client.post(
            f"/worker/jobs/{queued['job_id']}/heartbeat",
            headers=headers,
            json={"lease_id": claimed["lease_id"]},
        ).status_code
        == 409
    )
    assert (
        client.post(
            f"/worker/jobs/{queued['job_id']}/result",
            headers=headers,
            json={
                "schema_version": "1.0",
                "lease_id": claimed["lease_id"],
                "status": "completed",
                "summary": "Late result",
                "evidence": {},
            },
        ).status_code
        == 409
    )
    detail = client.get(f"/api/worker-jobs/{queued['job_id']}").json()
    assert detail["status"] == "cancelled"
    assert detail["evidence"] is None


def test_operator_can_stop_web_check_but_not_advanced_job(
    client: TestClient, settings: Settings
) -> None:
    agent, asset = web_asset(client)
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    ready_worker(client, site_id)
    queued = client.post(
        "/api/worker-jobs/nuclei",
        json={
            "asset_id": asset["asset_id"],
            "port": 8080,
            "scheme": "http",
            "authorization_confirmed": True,
        },
    ).json()
    advanced = dict(
        client.app.state.store.read("scanner-worker-jobs", queued["job_id"])
    )
    advanced["job_id"] = str(uuid4())
    advanced["template_profile"] = None
    advanced["assessment_profile"] = "greenbone_single_host"
    client.app.state.store.write("scanner-worker-jobs", advanced["job_id"], advanced)

    app = create_app(replace(settings, auth_required=True))
    with TestClient(app) as protected:
        app.state.auth_service.create_user(
            "operator@example.test", "operator password 123", "operator"
        )
        login = protected.post(
            "/api/auth/login",
            json={
                "email": "operator@example.test",
                "password": "operator password 123",
            },
        ).json()
        headers = {"X-CSRF-Token": login["csrf_token"]}
        assert (
            protected.post(
                f"/api/worker-jobs/{advanced['job_id']}/cancel", headers=headers
            ).status_code
            == 403
        )
        assert (
            protected.post(
                f"/api/worker-jobs/{queued['job_id']}/cancel", headers=headers
            ).json()["status"]
            == "cancelled"
        )


def test_nuclei_enqueue_requires_operator_and_csrf(settings: Settings) -> None:
    app = create_app(replace(settings, auth_required=True))
    with TestClient(app) as client:
        auth = app.state.auth_service
        auth.create_user("viewer@example.test", "viewer password 123", "viewer")
        auth.create_user("operator@example.test", "operator password 123", "operator")
        payload = {
            "asset_id": "00000000-0000-0000-0000-000000000001",
            "port": 8080,
            "scheme": "http",
            "authorization_confirmed": True,
        }
        assert client.post("/api/worker-jobs/nuclei", json=payload).status_code == 401
        viewer = client.post(
            "/api/auth/login",
            json={"email": "viewer@example.test", "password": "viewer password 123"},
        )
        assert viewer.status_code == 200
        assert (
            client.post(
                "/api/worker-jobs/nuclei",
                json=payload,
                headers={"X-CSRF-Token": viewer.json()["csrf_token"]},
            ).status_code
            == 403
        )
        client.post(
            "/api/auth/logout",
            headers={"X-CSRF-Token": viewer.json()["csrf_token"]},
        )
        operator = client.post(
            "/api/auth/login",
            json={
                "email": "operator@example.test",
                "password": "operator password 123",
            },
        )
        assert operator.status_code == 200
        assert client.post("/api/worker-jobs/nuclei", json=payload).status_code == 403
        assert (
            client.post(
                "/api/worker-jobs/nuclei",
                json=payload,
                headers={"X-CSRF-Token": operator.json()["csrf_token"]},
            ).status_code
            == 409
        )


def test_nuclei_runtime_has_fixed_template_and_rejects_foreign_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "nuclei.exe"
    binary.write_bytes(b"test")
    output = tmp_path / "results.jsonl"
    target = "http://10.10.1.4:8080"
    command = build_command(binary, target, output)
    assert command[command.index("-t") + 1].endswith(
        "forgesec-http-missing-x-content-type-options.yaml"
    )
    assert {"-ni", "-duc", "-dr", "-or", "-rl", "-c"}.issubset(command)
    assert "-ut" not in command
    assert "-as" not in command
    assert _base_url("http://127.0.0.1:8000/") == "http://127.0.0.1:8000"
    with pytest.raises(WorkerRuntimeError):
        _base_url("http://remote.example:8000")

    output.write_text(
        json.dumps(
            {"template-id": TEMPLATE_ID, "matched-at": "http://10.10.1.5:8080/"}
        ),
        encoding="utf-8",
    )
    with pytest.raises(WorkerRuntimeError, match="out-of-policy"):
        parse_findings(output, target)

    calls = []

    class FakeProcess:
        returncode = 0

        def __init__(self, arguments, **kwargs):
            calls.append((arguments, kwargs))
            file = Path(arguments[arguments.index("-jle") + 1])
            file.write_text(
                json.dumps({"template-id": TEMPLATE_ID, "matched-at": f"{target}/"}),
                encoding="utf-8",
            )

        def poll(self):
            return 0

    monkeypatch.setattr(
        "forgesec_api.workers.nuclei_runtime.subprocess.Popen", FakeProcess
    )
    evidence = run_nuclei(
        {
            "schema_version": "1.0",
            "capability": "vulnerability_assessment",
            "template_profile": "http_baseline",
            "job_id": "00000000-0000-0000-0000-000000000001",
            "lease_id": "00000000-0000-0000-0000-000000000002",
            "target_ip": "10.10.1.4",
            "target_port": 8080,
            "target_scheme": "http",
        },
        binary,
        on_tick=lambda _force=False: None,
    )
    assert evidence["findings"][0]["template_id"] == TEMPLATE_ID
    assert "FORGESEC_WORKER_CREDENTIAL" not in calls[0][1]["env"]


def test_empty_nuclei_result_requires_verified_http_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "nuclei.exe"
    binary.write_bytes(b"test")
    target = "http://10.10.1.4:8080"
    job = {
        "schema_version": "1.0",
        "capability": "vulnerability_assessment",
        "template_profile": "http_baseline",
        "job_id": "00000000-0000-0000-0000-000000000001",
        "lease_id": "00000000-0000-0000-0000-000000000002",
        "target_ip": "10.10.1.4",
        "target_port": 8080,
        "target_scheme": "http",
    }

    class FakeProcess:
        returncode = 0

        def __init__(self, arguments, **kwargs):
            pass

        def poll(self):
            return 0

    monkeypatch.setattr(
        "forgesec_api.workers.nuclei_runtime.subprocess.Popen", FakeProcess
    )
    checked = []
    monkeypatch.setattr(
        "forgesec_api.workers.nuclei_runtime.verify_clear_response",
        lambda origin: checked.append(origin),
    )
    assert run_nuclei(job, binary, on_tick=lambda _force=False: None)["findings"] == []
    assert checked == [target]


def test_lost_lease_prevents_follow_up_http_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "nuclei.exe"
    binary.write_bytes(b"test")
    job = {
        "schema_version": "1.0",
        "capability": "vulnerability_assessment",
        "template_profile": "http_baseline",
        "job_id": "00000000-0000-0000-0000-000000000001",
        "lease_id": "00000000-0000-0000-0000-000000000002",
        "target_ip": "10.10.1.4",
        "target_port": 8080,
        "target_scheme": "http",
    }

    class FakeProcess:
        returncode = 0

        def __init__(self, arguments, **kwargs):
            pass

        def poll(self):
            return 0

    checked = []
    monkeypatch.setattr(
        "forgesec_api.workers.nuclei_runtime.subprocess.Popen", FakeProcess
    )
    monkeypatch.setattr(
        "forgesec_api.workers.nuclei_runtime.verify_clear_response",
        lambda target: checked.append(target),
    )

    def cancelled(force: bool = False) -> None:
        assert force is True
        raise WorkerLeaseLost("cancelled")

    with pytest.raises(WorkerLeaseLost):
        run_nuclei(job, binary, on_tick=cancelled)
    assert checked == []


def test_lost_lease_terminates_running_nuclei(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "nuclei.exe"
    binary.write_bytes(b"test")
    processes = []

    class FakeProcess:
        returncode = None
        terminated = False

        def __init__(self, arguments, **kwargs):
            processes.append(self)

        def poll(self):
            return self.returncode

        def terminate(self):
            self.terminated = True

        def wait(self, timeout):
            self.returncode = -1

    monkeypatch.setattr(
        "forgesec_api.workers.nuclei_runtime.subprocess.Popen", FakeProcess
    )
    with pytest.raises(WorkerLeaseLost):
        run_nuclei(
            {
                "schema_version": "1.0",
                "capability": "vulnerability_assessment",
                "template_profile": "http_baseline",
                "job_id": "00000000-0000-0000-0000-000000000001",
                "lease_id": "00000000-0000-0000-0000-000000000002",
                "target_ip": "10.10.1.4",
                "target_port": 8080,
                "target_scheme": "http",
            },
            binary,
            on_tick=lambda _force=False: (_ for _ in ()).throw(
                WorkerLeaseLost("stopped")
            ),
        )
    assert processes[0].terminated is True


def test_nuclei_start_and_output_fail_as_worker_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "nuclei.exe"
    binary.write_bytes(b"test")
    job = {
        "schema_version": "1.0",
        "capability": "vulnerability_assessment",
        "template_profile": "http_baseline",
        "job_id": "00000000-0000-0000-0000-000000000001",
        "lease_id": "00000000-0000-0000-0000-000000000002",
        "target_ip": "10.10.1.4",
        "target_port": 8080,
        "target_scheme": "http",
    }

    def cannot_start(*args, **kwargs):
        raise OSError("bad executable")

    monkeypatch.setattr(
        "forgesec_api.workers.nuclei_runtime.subprocess.Popen", cannot_start
    )
    with pytest.raises(WorkerRuntimeError, match="could not start"):
        run_nuclei(job, binary, on_tick=lambda _force=False: None)

    output = tmp_path / "invalid.jsonl"
    output.write_bytes(b"\xff")
    with pytest.raises(WorkerRuntimeError, match="could not be read"):
        parse_findings(output, "http://10.10.1.4:8080")


@pytest.mark.parametrize(
    ("status", "header", "error"),
    [
        (200, "nosniff", None),
        (302, "nosniff", "2xx"),
        (200, None, "lacks the checked header"),
    ],
)
def test_clean_response_verification_is_direct_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    header: str | None,
    error: str | None,
) -> None:
    calls = []

    class FakeConnection:
        def __init__(self, host, port, timeout):
            calls.append((host, port, timeout))

        def request(self, method, path, headers):
            calls.append((method, path, headers))

        def getresponse(self):
            class Response:
                pass

            response = Response()
            response.status = status
            response.getheader = lambda name: header
            return response

        def close(self):
            calls.append("closed")

    monkeypatch.setattr(
        "forgesec_api.workers.nuclei_runtime.HTTPConnection", FakeConnection
    )
    if error:
        with pytest.raises(WorkerRuntimeError, match=error):
            verify_clear_response("http://10.10.1.4:8080")
    else:
        verify_clear_response("http://10.10.1.4:8080")
    assert calls[0] == ("10.10.1.4", 8080, 5)
    assert calls[1][0:2] == ("GET", "/")
    assert calls[-1] == "closed"


def test_unreachable_web_target_is_not_a_clean_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class UnreachableConnection:
        def __init__(self, host, port, timeout):
            pass

        def request(self, method, path, headers):
            raise OSError("No route to host")

        def close(self):
            pass

    monkeypatch.setattr(
        "forgesec_api.workers.nuclei_runtime.HTTPConnection", UnreachableConnection
    )
    with pytest.raises(WorkerRuntimeError, match="could not verify"):
        verify_clear_response("http://10.10.1.4:8080")


@pytest.mark.parametrize("lease_available", [True, False])
def test_nuclei_rechecks_lease_before_starting_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lease_available: bool
) -> None:
    binary = tmp_path / "nuclei.exe"
    binary.write_bytes(b"test")
    events: list[str] = []
    job = {"job_id": str(uuid4()), "lease_id": str(uuid4())}

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

        def renew(self, claimed_job):
            assert claimed_job is job
            events.append("renew")
            if not lease_available:
                raise WorkerRuntimeError("HTTP 409")

        def finish(self, claimed_job, status, summary, evidence):
            assert claimed_job is job
            assert status == "completed"
            events.append("finish")

    def fake_scan(claimed_job, executable, *, on_tick):
        assert claimed_job is job and executable == binary
        events.append("scan")
        on_tick(True)
        return {"findings": []}

    monkeypatch.setattr("forgesec_api.workers.nuclei_runtime.run_nuclei", fake_scan)
    monkeypatch.setattr(
        "forgesec_api.workers.nuclei_runtime.verify_binary", lambda _binary: None
    )
    with pytest.raises(KeyboardInterrupt):
        run_forever(Client(), binary)
    assert events == (
        ["heartbeat", "renew", "scan", "renew", "finish"]
        if lease_available
        else ["heartbeat", "renew"]
    )


def test_nuclei_worker_rejects_wrong_binary_before_heartbeat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binary = tmp_path / "nuclei.exe"
    binary.write_bytes(b"wrong executable")
    monkeypatch.setattr(
        "forgesec_api.workers.nuclei_runtime.subprocess.run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 0, "Unrelated tool v1.0.0", ""
        ),
    )

    class Client:
        def heartbeat(self):
            pytest.fail("Worker advertised readiness before binary validation")

    with pytest.raises(WorkerRuntimeError, match="did not identify Nuclei"):
        run_forever(Client(), binary)
