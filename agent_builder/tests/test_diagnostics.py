from __future__ import annotations

import subprocess

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
                "scope_policy": [{"cidr": "192.168.1.0/24", "exclusions": []}],
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
                "scope_policy": [{"cidr": "192.168.1.0/24", "exclusions": []}],
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
                "scope_policy": [{"cidr": "192.168.1.0/24", "exclusions": []}],
            },
        },
        identity(),
        client,
    )

    assert "-sU" in commands[0]
    assert any(
        "U:53,67,69,123,137,161,500,4500,5353,1900" in item
        for item in commands[0]
    )
    assert client.events[-1]["details"]["command_line"].startswith(
        "nmap -Pn -sU -sT"
    )
