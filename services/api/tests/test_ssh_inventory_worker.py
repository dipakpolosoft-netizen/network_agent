from __future__ import annotations

import sys
from dataclasses import replace
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from test_nuclei_worker import web_asset

from forgesec_api.main import create_app
from forgesec_api.settings import Settings
from forgesec_api.workers.runtime_client import WorkerLeaseLost, WorkerRuntimeError
from forgesec_api.workers.ssh_inventory_runtime import (
    PACKAGE_COMMAND,
    SshInventorySettings,
    _target,
    open_ssh,
    run_inventory,
)


def _worker(client: TestClient, site_id: str) -> dict:
    worker = client.post(
        "/api/workers",
        json={
            "site_id": site_id,
            "label": "SSH inventory worker",
            "capabilities": ["credentialed_inventory"],
        },
    ).json()
    response = client.post(
        "/worker/heartbeat",
        headers={"Authorization": f"Bearer {worker['credential']}"},
        json={
            "schema_version": "1.0",
            "worker_id": worker["worker_id"],
            "version": "0.1.0-ssh-inventory",
            "available_capabilities": ["credentialed_inventory"],
        },
    )
    assert response.status_code == 200
    return worker


def _request(asset_id: str) -> dict:
    return {"asset_id": asset_id, "authorization_confirmed": True}


def _evidence(ip: str) -> dict:
    return {
        "schema_version": "1.0",
        "engine": "ssh_inventory",
        "inventory_profile": "linux_ssh_readonly",
        "target_ip": ip,
        "hostname": "linux-test",
        "os_name": "Debian GNU/Linux 12",
        "os_version": "12",
        "kernel": "6.1.0",
        "architecture": "x86_64",
        "package_manager": "dpkg",
        "packages": [{"name": "openssh-server", "version": "9.2p1"}],
        "packages_truncated": False,
    }


def test_inventory_requires_scope_and_observed_ssh_and_validates_evidence(
    client: TestClient,
) -> None:
    agent, asset = web_asset(client)
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    path = "/api/worker-jobs/inventory"
    payload = _request(asset["asset_id"])
    assert client.post(path, json=payload).status_code == 409
    assert (
        client.post(
            path, json={**payload, "authorization_confirmed": False}
        ).status_code
        == 422
    )
    worker = _worker(client, site_id)
    scope = client.get(f"/api/sites/{site_id}/scopes").json()[0]
    stored = client.app.state.store.read("approved-scopes", scope["scope_id"])
    stored["scan_profiles"] = ["standard"]
    client.app.state.store.write("approved-scopes", scope["scope_id"], stored)
    assert client.post(path, json=payload).status_code == 409
    stored["scan_profiles"].append("full_tcp")
    client.app.state.store.write("approved-scopes", scope["scope_id"], stored)
    scan = client.app.state.store.read("scans", asset["last_scan_id"])
    original_ports = scan["results"][0]["ports"]
    scan["results"][0]["ports"] = [
        port for port in original_ports if port["port"] != 22
    ]
    client.app.state.store.write("scans", scan["scan_id"], scan)
    assert client.post(path, json=payload).status_code == 409
    scan["results"][0]["ports"] = original_ports
    client.app.state.store.write("scans", scan["scan_id"], scan)
    queued = client.post(path, json=payload)
    assert queued.status_code == 202
    job = queued.json()
    assert job["capability"] == "credentialed_inventory"
    assert job["inventory_profile"] == "linux_ssh_readonly"
    assert job["target_ip"] == asset["last_ip"]
    assert client.post(path, json=payload).status_code == 409
    headers = {"Authorization": f"Bearer {worker['credential']}"}
    claim = client.get("/worker/jobs/next", headers=headers).json()
    result = {
        "schema_version": "1.0",
        "lease_id": claim["lease_id"],
        "status": "completed",
        "summary": "1 Linux package observed",
        "evidence": _evidence(job["target_ip"]),
    }
    result_path = f"/worker/jobs/{job['job_id']}/result"
    assert (
        client.post(
            result_path,
            headers=headers,
            json={**result, "evidence": _evidence("192.168.1.99")},
        ).status_code
        == 409
    )
    duplicate = {
        **result["evidence"],
        "packages": result["evidence"]["packages"] * 2,
    }
    assert (
        client.post(
            result_path, headers=headers, json={**result, "evidence": duplicate}
        ).status_code
        == 409
    )
    assert client.post(result_path, headers=headers, json=result).status_code == 200
    detail = client.get(f"/api/worker-jobs/{job['job_id']}").json()
    assert detail["evidence"]["packages"][0]["name"] == "openssh-server"
    assert "evidence" not in client.get("/api/worker-jobs").json()[0]


def test_inventory_queue_is_admin_only_and_csrf_protected(settings: Settings) -> None:
    app = create_app(replace(settings, auth_required=True))
    with TestClient(app) as client:
        auth = app.state.auth_service
        auth.create_user("operator@example.test", "operator password 123", "operator")
        auth.create_user("admin@example.test", "admin password 123", "admin")
        payload = _request("00000000-0000-0000-0000-000000000001")
        path = "/api/worker-jobs/inventory"
        assert client.post(path, json=payload).status_code == 401
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
                path,
                json=payload,
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
        assert client.post(path, json=payload).status_code == 403
        assert (
            client.post(
                path,
                json=payload,
                headers={"X-CSRF-Token": admin.json()["csrf_token"]},
            ).status_code
            == 409
        )


def test_inventory_cancel_revokes_lease_and_source_change_blocks_claim(
    client: TestClient,
) -> None:
    agent, asset = web_asset(client)
    site_id = client.get(f"/api/agents/{agent['agent_id']}").json()["site_id"]
    worker = _worker(client, site_id)
    headers = {"Authorization": f"Bearer {worker['credential']}"}
    path = "/api/worker-jobs/inventory"
    job = client.post(path, json=_request(asset["asset_id"])).json()
    claim = client.get("/worker/jobs/next", headers=headers).json()
    assert client.post(f"/api/worker-jobs/{job['job_id']}/cancel").status_code == 200
    assert (
        client.post(
            f"/worker/jobs/{job['job_id']}/heartbeat",
            headers=headers,
            json={"lease_id": claim["lease_id"]},
        ).status_code
        == 409
    )
    second = client.post(path, json=_request(asset["asset_id"]))
    assert second.status_code == 202
    saved = client.app.state.store.read("assets", asset["asset_id"])
    saved["last_ip"] = "192.168.1.11"
    client.app.state.store.write("assets", asset["asset_id"], saved)
    assert client.get("/worker/jobs/next", headers=headers).status_code == 204
    assert (
        client.get(f"/api/worker-jobs/{second.json()['job_id']}").json()["status"]
        == "cancelled"
    )


class _Channel:
    def __init__(self, status: int = 0):
        self.status = status
        self.closed = False

    def recv_exit_status(self) -> int:
        return self.status

    def close(self) -> None:
        self.closed = True


class _Output(BytesIO):
    def __init__(self, value: bytes, status: int = 0):
        super().__init__(value)
        self.channel = _Channel(status)


class _Ssh:
    def __init__(self):
        self.commands: list[str] = []
        self.closed = False

    def exec_command(self, command: str, *, timeout: int, get_pty: bool):
        assert timeout == 15
        assert get_pty is False
        self.commands.append(command)
        value = {
            "cat /etc/os-release": (
                b'PRETTY_NAME="Debian GNU/Linux 12"\nVERSION_ID="12"\n'
            ),
            "uname -srm": b"Linux 6.1.0 x86_64\n",
            "hostname": b"linux-test\n",
            PACKAGE_COMMAND: b"dpkg\nopenssh-server\t9.2p1\n",
        }[command]
        return None, _Output(value), _Output(b"")

    def close(self) -> None:
        self.closed = True


def _job() -> dict:
    return {
        "schema_version": "1.0",
        "job_id": str(uuid4()),
        "lease_id": str(uuid4()),
        "source_asset_id": str(uuid4()),
        "source_scan_id": str(uuid4()),
        "capability": "credentialed_inventory",
        "inventory_profile": "linux_ssh_readonly",
        "profile": "full_tcp",
        "target_ip": "192.168.1.10",
    }


def test_ssh_inventory_runs_fixed_read_only_commands_and_closes() -> None:
    fake = _Ssh()
    settings = SshInventorySettings("scan", Path("key"), Path("known_hosts"))
    evidence = run_inventory(
        _job(),
        settings,
        on_tick=lambda _progress, _phase: None,
        ssh_factory=lambda _settings, _target: fake,
    )
    assert evidence["packages"][0] == {"name": "openssh-server", "version": "9.2p1"}
    assert evidence["os_name"] == "Debian GNU/Linux 12"
    assert evidence["target_ip"] == "192.168.1.10"
    assert fake.commands == [
        "cat /etc/os-release",
        "uname -srm",
        "hostname",
        PACKAGE_COMMAND,
    ]
    assert fake.closed


def test_ssh_inventory_closes_when_lease_is_lost() -> None:
    fake = _Ssh()
    settings = SshInventorySettings("scan", Path("key"), Path("known_hosts"))
    with pytest.raises(WorkerLeaseLost):
        run_inventory(
            _job(),
            settings,
            on_tick=lambda progress, _phase: (
                None if progress < 45 else (_ for _ in ()).throw(WorkerLeaseLost())
            ),
            ssh_factory=lambda _settings, _target: fake,
        )
    assert fake.closed


def test_ssh_inventory_rejects_wrong_claim_and_no_extra_fields() -> None:
    with pytest.raises(WorkerRuntimeError):
        _target({**_job(), "target_ip": "not-an-ip"})
    with pytest.raises(WorkerRuntimeError):
        _target({**_job(), "capability": "greenbone_assessment"})


def test_ssh_connection_pins_host_key_and_disables_fallback(monkeypatch) -> None:
    calls: dict = {}

    class FakeClient:
        def load_host_keys(self, path):
            calls["known_hosts"] = path

        def set_missing_host_key_policy(self, policy):
            calls["policy"] = policy

        def connect(self, **kwargs):
            calls["connect"] = kwargs

        def close(self):
            calls["closed"] = True

    class RejectPolicy:
        pass

    monkeypatch.setitem(
        sys.modules,
        "paramiko",
        SimpleNamespace(SSHClient=FakeClient, RejectPolicy=RejectPolicy),
    )
    settings = SshInventorySettings("scan", Path("key"), Path("known_hosts"))
    client = open_ssh(settings, "192.168.1.10")
    assert isinstance(client, FakeClient)
    assert isinstance(calls["policy"], RejectPolicy)
    assert calls["connect"]["hostname"] == "192.168.1.10"
    assert calls["connect"]["port"] == 22
    assert calls["connect"]["look_for_keys"] is False
    assert calls["connect"]["allow_agent"] is False
