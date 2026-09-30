from __future__ import annotations

import os
import stat
import sys
from dataclasses import replace
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
    _command,
    _packages,
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
    multiversion = {
        **result["evidence"],
        "packages": [
            {"name": "kernel.x86_64", "version": "1.0"},
            {"name": "kernel.x86_64", "version": "2.0"},
        ],
    }
    assert (
        client.post(
            result_path, headers=headers, json={**result, "evidence": multiversion}
        ).status_code
        == 200
    )
    detail = client.get(f"/api/worker-jobs/{job['job_id']}").json()
    assert [item["version"] for item in detail["evidence"]["packages"]] == [
        "1.0",
        "2.0",
    ]
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
    def __init__(self, output: bytes, error: bytes = b"", status: int = 0):
        self.output = output
        self.error = error
        self.status = status
        self.closed = False

    def recv_ready(self) -> bool:
        return bool(self.output)

    def recv(self, size: int) -> bytes:
        chunk, self.output = self.output[:size], self.output[size:]
        return chunk

    def recv_stderr_ready(self) -> bool:
        return bool(self.error)

    def recv_stderr(self, size: int) -> bytes:
        chunk, self.error = self.error[:size], self.error[size:]
        return chunk

    def exit_status_ready(self) -> bool:
        return not self.output and not self.error

    def recv_exit_status(self) -> int:
        return self.status

    def close(self) -> None:
        self.closed = True


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
        channel = _Channel(value)
        output = SimpleNamespace(channel=channel)
        return None, output, output

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
    phases = []
    evidence = run_inventory(
        _job(),
        settings,
        on_tick=lambda progress, phase: phases.append((progress, phase)),
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
    assert (55, "Reading host") in phases


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


def test_ssh_inventory_checks_lease_between_kernel_and_hostname() -> None:
    fake = _Ssh()
    with pytest.raises(WorkerLeaseLost):
        run_inventory(
            _job(),
            SshInventorySettings("scan", Path("key"), Path("known_hosts")),
            on_tick=lambda progress, _phase: (
                None if progress < 55 else (_ for _ in ()).throw(WorkerLeaseLost())
            ),
            ssh_factory=lambda _settings, _target: fake,
        )
    assert fake.commands == ["cat /etc/os-release", "uname -srm"]
    assert fake.closed


def test_ssh_inventory_checks_lease_before_connecting() -> None:
    connections = []
    with pytest.raises(WorkerLeaseLost):
        run_inventory(
            _job(),
            SshInventorySettings("scan", Path("key"), Path("known_hosts")),
            on_tick=lambda _progress, _phase: (_ for _ in ()).throw(WorkerLeaseLost()),
            ssh_factory=lambda *_args: connections.append(True),
        )
    assert connections == []


def test_ssh_inventory_rejects_wrong_claim_and_no_extra_fields() -> None:
    with pytest.raises(WorkerRuntimeError):
        _target({**_job(), "target_ip": "not-an-ip"})
    with pytest.raises(WorkerRuntimeError):
        _target({**_job(), "capability": "greenbone_assessment"})
    with pytest.raises(WorkerRuntimeError):
        _target({**_job(), "target_scheme": "http"})


def test_empty_hostname_fails_inventory_and_closes_connection() -> None:
    class NoHostnameSsh(_Ssh):
        def exec_command(self, command: str, **kwargs):
            if command == "hostname":
                stream = SimpleNamespace(channel=_Channel(b""))
                return None, stream, stream
            return super().exec_command(command, **kwargs)

    fake = NoHostnameSsh()
    with pytest.raises(WorkerRuntimeError, match="did not report a hostname"):
        run_inventory(
            _job(),
            SshInventorySettings("scan", Path("key"), Path("known_hosts")),
            on_tick=lambda _progress, _phase: None,
            ssh_factory=lambda _settings, _target: fake,
        )
    assert fake.closed


@pytest.mark.parametrize("release", [b"", b'PRETTY_NAME="broken\n'])
def test_missing_or_malformed_os_release_is_not_invented(release: bytes) -> None:
    class NoReleaseSsh(_Ssh):
        def exec_command(self, command: str, **kwargs):
            if command == "cat /etc/os-release":
                stream = SimpleNamespace(channel=_Channel(release))
                return None, stream, stream
            return super().exec_command(command, **kwargs)

    fake = NoReleaseSsh()
    with pytest.raises(WorkerRuntimeError, match="did not report an OS release"):
        run_inventory(
            _job(),
            SshInventorySettings("scan", Path("key"), Path("known_hosts")),
            on_tick=lambda _progress, _phase: None,
            ssh_factory=lambda _settings, _target: fake,
        )
    assert fake.closed


def test_ssh_command_drains_both_streams_and_checks_exit_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CommandSsh:
        def __init__(self, output: bytes, error: bytes, status: int):
            self.channel = _Channel(output, error, status)

        def exec_command(self, command, **kwargs):
            stream = SimpleNamespace(channel=self.channel)
            return None, stream, stream

    failed = CommandSsh(b"dpkg\n", b"query failed", 1)
    with pytest.raises(WorkerRuntimeError, match="command failed"):
        _command(failed, PACKAGE_COMMAND)
    assert failed.channel.closed

    too_much_error = CommandSsh(b"", b"x" * 4097, 0)
    with pytest.raises(WorkerRuntimeError, match="error output exceeded"):
        _command(too_much_error, PACKAGE_COMMAND)
    assert too_much_error.channel.closed

    too_much_output = CommandSsh(b"x" * (80 * 1024 + 1), b"", 0)
    with pytest.raises(WorkerRuntimeError, match="output exceeded"):
        _command(too_much_output, PACKAGE_COMMAND)
    assert too_much_output.channel.closed

    invalid_utf8 = CommandSsh(b"\xff", b"", 0)
    with pytest.raises(WorkerRuntimeError, match="not valid UTF-8"):
        _command(invalid_utf8, "cat /etc/os-release")
    assert invalid_utf8.channel.closed

    timed_out = CommandSsh(b"", b"", 0)
    timed_out.channel.exit_status_ready = lambda: False
    times = iter([0.0, 16.0])
    monkeypatch.setattr(
        "forgesec_api.workers.ssh_inventory_runtime.time.monotonic",
        lambda: next(times),
    )
    with pytest.raises(WorkerRuntimeError, match="timed out"):
        _command(timed_out, PACKAGE_COMMAND)
    assert timed_out.channel.closed


def test_package_query_failures_and_multiversion_rows_are_explicit() -> None:
    assert "data=$(LC_ALL=C dpkg-query" in PACKAGE_COMMAND
    assert "2>/dev/null) || exit 1" in PACKAGE_COMMAND
    assert "data=$(LC_ALL=C rpm" in PACKAGE_COMMAND
    assert "%{NAME}.%{ARCH}" in PACKAGE_COMMAND
    assert _packages("rpm\nkernel.x86_64\t1.0\nkernel.x86_64\t2.0\n") == (
        "rpm",
        [
            {"name": "kernel.x86_64", "version": "1.0"},
            {"name": "kernel.x86_64", "version": "2.0"},
        ],
        False,
    )
    with pytest.raises(WorkerRuntimeError, match="no installed packages"):
        _packages("dpkg\n")
    with pytest.raises(WorkerRuntimeError, match="malformed"):
        _packages("dpkg\nbad-row\n")


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


def test_ssh_connection_closes_after_host_key_rejection(monkeypatch) -> None:
    closed = []

    class FakeClient:
        def load_host_keys(self, path):
            pass

        def set_missing_host_key_policy(self, policy):
            pass

        def connect(self, **kwargs):
            raise OSError("host key changed")

        def close(self):
            closed.append(True)

    monkeypatch.setitem(
        sys.modules,
        "paramiko",
        SimpleNamespace(
            SSHClient=FakeClient,
            RejectPolicy=type("RejectPolicy", (), {}),
        ),
    )
    with pytest.raises(OSError, match="host key changed"):
        open_ssh(
            SshInventorySettings("scan", Path("key"), Path("known_hosts")),
            "192.168.1.10",
        )
    assert closed == [True]


def test_ssh_settings_require_safe_host_keys_and_non_root_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = tmp_path / "inventory.key"
    known_hosts = tmp_path / "known_hosts"
    key.write_text("test", encoding="utf-8")
    known_hosts.write_text("test", encoding="utf-8")
    key = key.resolve()
    known_hosts = known_hosts.resolve()
    monkeypatch.setenv("FORGESEC_SSH_INVENTORY_KEY_FILE", str(key))
    monkeypatch.setenv("FORGESEC_SSH_INVENTORY_KNOWN_HOSTS", str(known_hosts))
    monkeypatch.setenv("FORGESEC_SSH_INVENTORY_USERNAME", "inventory")
    modes = {key: 0o600, known_hosts: 0o666}
    real_stat = Path.stat

    def file_stat(path: Path, *args, **kwargs):
        result = real_stat(path, *args, **kwargs)
        if path not in modes:
            return result
        return os.stat_result((stat.S_IFREG | modes[path], *result[1:]))

    monkeypatch.setattr(Path, "stat", file_stat)
    with pytest.raises(WorkerRuntimeError, match="known_hosts"):
        SshInventorySettings.from_env()

    modes[known_hosts] = 0o644
    monkeypatch.setenv("FORGESEC_SSH_INVENTORY_USERNAME", "root")
    with pytest.raises(WorkerRuntimeError, match="username"):
        SshInventorySettings.from_env()

    monkeypatch.setenv("FORGESEC_SSH_INVENTORY_USERNAME", "inventory")
    settings = SshInventorySettings.from_env()
    assert settings.key_path == key
    assert settings.known_hosts_path == known_hosts
