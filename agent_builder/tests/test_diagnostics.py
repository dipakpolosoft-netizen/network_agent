from __future__ import annotations

import subprocess
import threading
from dataclasses import replace

import pytest
from approved_policy import approved_policy

from forgesec_agent.command_diagnostics import DeviceDiagnosticHandler
from forgesec_agent.enrollment import AgentIdentity


def identity() -> AgentIdentity:
    return AgentIdentity(
        agent_id="00000000-0000-0000-0000-000000000123",
        server_url="https://forgesec.example.com",
        credential="tes_agent_secret",
        heartbeat_interval_seconds=30,
        enrolled_at="2026-07-23T10:00:00Z",
    )


class DiagnosticClient:
    def __init__(self):
        self.events = []

    def command_event(self, command_id, payload, *, credential):
        assert command_id == "00000000-0000-0000-0000-000000000999"
        assert credential == "tes_agent_secret"
        self.events.append(payload)
        return {"status": "accepted"}


def test_ping_diagnostic_reports_terminal_output(monkeypatch) -> None:
    def fake_run(argv, **kwargs):
        assert argv == ["ping", "-n", "4", "192.168.1.2"]
        assert kwargs["timeout"] == 20
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout="Reply from 192.168.1.2: bytes=32 time=2ms TTL=64",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    client = DiagnosticClient()

    DeviceDiagnosticHandler().handle(
        {
            "command_id": "00000000-0000-0000-0000-000000000999",
            "payload": {
                "diagnostic_type": "ping",
                "target_ip": "192.168.1.2",
                "scope_policy": [approved_policy("192.168.1.0/24")],
            },
        },
        identity(),
        client,
    )

    assert [event["status"] for event in client.events] == ["running", "completed"]
    completed = client.events[-1]
    assert completed["message"] == "Ping completed: host responded"
    assert completed["details"]["command_line"] == "ping -n 4 192.168.1.2"
    assert completed["details"]["output"].startswith("Reply from 192.168.1.2")
    assert completed["details"]["exit_code"] == 0
    assert completed["details"]["reachable"] is True
    assert completed["details"]["ping_result"] == "reply"


@pytest.mark.parametrize(
    ("output", "exit_code", "expected_result", "reachable"),
    [
        (
            "Reply from 192.168.1.248: Destination host unreachable.\n"
            "Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)",
            0,
            "unreachable",
            False,
        ),
        (
            "Request timed out.\nPackets: Sent = 4, Received = 0, Lost = 4",
            1,
            "timeout",
            False,
        ),
        (
            "Reply from 192.168.1.2: bytes=32 time=2ms TTL=64\nRequest timed out.",
            1,
            "reply",
            True,
        ),
        (
            "Reply from 192.168.1.248: bytes=32 time=2ms TTL=64",
            0,
            "no_reply",
            False,
        ),
    ],
)
def test_ping_requires_echo_reply_from_target(
    monkeypatch, output: str, exit_code: int, expected_result: str, reachable: bool
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda argv, **kwargs: subprocess.CompletedProcess(
            argv, exit_code, stdout=output, stderr=""
        ),
    )
    client = DiagnosticClient()

    DeviceDiagnosticHandler().handle(
        {
            "command_id": "00000000-0000-0000-0000-000000000999",
            "payload": {
                "diagnostic_type": "ping",
                "target_ip": "192.168.1.2",
                "scope_policy": [approved_policy("192.168.1.0/24")],
            },
        },
        identity(),
        client,
    )

    completed = client.events[-1]
    assert completed["status"] == "completed"
    assert completed["details"]["exit_code"] == exit_code
    assert completed["details"]["reachable"] is reachable
    assert completed["details"]["ping_result"] == expected_result


def test_inventory_nmap_diagnostic_uses_fast_profile(monkeypatch) -> None:
    commands = []
    monkeypatch.setattr(
        "forgesec_agent.command_diagnostics.find_nmap_executable",
        lambda: "nmap.exe",
    )

    def fake_run(argv, **kwargs):
        commands.append(argv)
        assert kwargs["timeout"] == 120
        return subprocess.CompletedProcess(argv, 0, stdout="<nmaprun />", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    client = DiagnosticClient()

    DeviceDiagnosticHandler().handle(
        {
            "command_id": "00000000-0000-0000-0000-000000000999",
            "payload": {
                "diagnostic_type": "inventory_nmap",
                "target_ip": "192.168.1.2",
                "scope_policy": [approved_policy("192.168.1.0/24")],
            },
        },
        identity(),
        client,
    )

    assert "--top-ports" in commands[0]
    assert "200" in commands[0]
    assert "--max-retries" in commands[0]
    assert client.events[-1]["details"]["command_line"].startswith(
        "nmap -Pn --top-ports 200"
    )


def test_network_services_nmap_diagnostic_uses_udp_profile(monkeypatch) -> None:
    commands = []
    monkeypatch.setattr(
        "forgesec_agent.command_diagnostics.find_nmap_executable",
        lambda: "nmap.exe",
    )

    def fake_run(argv, **kwargs):
        commands.append(argv)
        assert kwargs["timeout"] == 360
        return subprocess.CompletedProcess(argv, 0, stdout="<nmaprun />", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    client = DiagnosticClient()

    DeviceDiagnosticHandler().handle(
        {
            "command_id": "00000000-0000-0000-0000-000000000999",
            "payload": {
                "diagnostic_type": "network_services_nmap",
                "target_ip": "192.168.1.2",
                "scope_policy": [approved_policy("192.168.1.0/24")],
            },
        },
        identity(),
        client,
    )

    assert "-sU" in commands[0]
    assert any(
        "U:53,67,69,123,137,161,500,4500,5353,1900" in item for item in commands[0]
    )
    assert client.events[-1]["details"]["command_line"].startswith("nmap -Pn -sU -sT")


def test_long_diagnostic_keeps_agent_online(monkeypatch) -> None:
    second_heartbeat = threading.Event()
    monkeypatch.setattr(
        "forgesec_agent.command_diagnostics.find_nmap_executable",
        lambda: "nmap.exe",
    )

    class FakeHeartbeat:
        def __init__(self):
            self.calls = []

        def send(self, agent_identity, **kwargs):
            self.calls.append(kwargs)
            if len(self.calls) == 2:
                second_heartbeat.set()

    def fake_run(argv, **kwargs):
        assert "-p-" in argv
        assert kwargs["timeout"] == 1200
        assert second_heartbeat.wait(timeout=2)
        return subprocess.CompletedProcess(argv, 0, stdout="done", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    heartbeat = FakeHeartbeat()
    client = DiagnosticClient()

    DeviceDiagnosticHandler(heartbeat).handle(
        {
            "command_id": "00000000-0000-0000-0000-000000000999",
            "payload": {
                "diagnostic_type": "full_tcp_nmap",
                "target_ip": "192.168.1.2",
                "full_tcp_confirmed": True,
                "scope_policy": [approved_policy("192.168.1.0/24")],
            },
        },
        replace(identity(), heartbeat_interval_seconds=1),
        client,
    )

    assert [event["status"] for event in client.events] == ["running", "completed"]
    assert len(heartbeat.calls) >= 2
    assert all(call["service_status"] == "busy" for call in heartbeat.calls)
    assert all(
        call["current_command_id"] == "00000000-0000-0000-0000-000000000999"
        for call in heartbeat.calls
    )


@pytest.mark.parametrize(
    ("diagnostic_type", "scan_profiles", "confirmed"),
    [
        ("standard_nmap", ["inventory"], False),
        ("network_services_nmap", ["inventory"], False),
        ("full_tcp_nmap", ["full_tcp"], False),
        ("full_tcp_nmap", ["inventory"], True),
    ],
)
def test_probe_rejects_unapproved_or_unconfirmed_nmap_host_check(
    monkeypatch,
    diagnostic_type: str,
    scan_profiles: list[str],
    confirmed: bool,
) -> None:
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *_args, **_kwargs: calls.append(1))
    client = DiagnosticClient()
    DeviceDiagnosticHandler().handle(
        {
            "command_id": "00000000-0000-0000-0000-000000000999",
            "payload": {
                "diagnostic_type": diagnostic_type,
                "target_ip": "192.168.1.2",
                "full_tcp_confirmed": confirmed,
                "scope_policy": [
                    approved_policy(
                        "192.168.1.0/24", scan_profiles=scan_profiles
                    )
                ],
            },
        },
        identity(),
        client,
    )
    assert not calls
    assert client.events[-1]["status"] == "failed"


def test_failed_keepalive_does_not_abort_diagnostic(monkeypatch) -> None:
    class FailingHeartbeat:
        def send(self, agent_identity, **kwargs):
            raise OSError("temporary API failure")

    monkeypatch.setattr(
        subprocess,
        "run",
        lambda argv, **kwargs: subprocess.CompletedProcess(
            argv, 0, stdout="reply", stderr=""
        ),
    )
    client = DiagnosticClient()

    DeviceDiagnosticHandler(FailingHeartbeat()).handle(
        {
            "command_id": "00000000-0000-0000-0000-000000000999",
            "payload": {
                "diagnostic_type": "ping",
                "target_ip": "192.168.1.2",
                "scope_policy": [approved_policy("192.168.1.0/24")],
            },
        },
        identity(),
        client,
    )

    assert client.events[-1]["status"] == "completed"
