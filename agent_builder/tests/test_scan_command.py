from __future__ import annotations

import pytest
from approved_policy import approved_policy

from forgesec_agent.enrollment import AgentIdentity
from forgesec_agent.scanning.nmap_runner import scan_profile_plan
from forgesec_agent.scanning.scan import ScanCommandHandler


class FakeScheduler:
    def __init__(self) -> None:
        self.calls = 0

    def run(self, **_kwargs):
        self.calls += 1
        return "completed"


class FakeHeartbeat:
    def send(self, *_args, **_kwargs):
        return None


class FakeClient:
    def __init__(self) -> None:
        self.events = []

    def command_event(self, _command_id, payload, *, credential):
        self.events.append(payload)
        return {}


@pytest.mark.parametrize(
    ("target_count", "confirmed", "accepted"),
    [(1, False, False), (2, True, False), (1, True, True)],
)
def test_probe_enforces_full_tcp_escalation(
    target_count: int, confirmed: bool, accepted: bool
) -> None:
    scheduler = FakeScheduler()
    client = FakeClient()
    identity = AgentIdentity(
        agent_id="00000000-0000-0000-0000-000000000123",
        server_url="https://forgesec.example.com",
        credential="tes_agent_secret",
        heartbeat_interval_seconds=30,
        enrolled_at="2026-07-23T10:00:00Z",
    )
    targets = [
        {"device_id": f"device-{number}", "ip": f"192.168.1.{number + 10}"}
        for number in range(target_count)
    ]
    command = {
        "command_id": "00000000-0000-0000-0000-000000000456",
        "payload": {
            "scan_id": "00000000-0000-0000-0000-000000000789",
            "profile": "full_tcp",
            "profile_plan": scan_profile_plan("full_tcp"),
            "full_tcp_confirmed": confirmed,
            "concurrency": 3,
            "scope_policy": [
                approved_policy("192.168.1.0/24", scan_profiles=["full_tcp"])
            ],
            "targets": targets,
        },
    }

    ScanCommandHandler(scheduler, FakeHeartbeat()).handle(command, identity, client)

    assert scheduler.calls == int(accepted)
    assert client.events[-1]["status"] == ("completed" if accepted else "failed")


@pytest.mark.parametrize("plan", [None, {"tcp_all_ports": False}])
def test_probe_rejects_missing_or_mismatched_profile_plan(plan: dict | None) -> None:
    scheduler = FakeScheduler()
    client = FakeClient()
    identity = AgentIdentity(
        agent_id="00000000-0000-0000-0000-000000000123",
        server_url="https://forgesec.example.com",
        credential="tes_agent_secret",
        heartbeat_interval_seconds=30,
        enrolled_at="2026-07-23T10:00:00Z",
    )
    command = {
        "command_id": "00000000-0000-0000-0000-000000000456",
        "payload": {
            "scan_id": "00000000-0000-0000-0000-000000000789",
            "profile": "inventory",
            "profile_plan": plan,
            "concurrency": 1,
            "scope_policy": [approved_policy("192.168.1.0/24")],
            "targets": [{"device_id": "device-1", "ip": "192.168.1.10"}],
        },
    }

    ScanCommandHandler(scheduler, FakeHeartbeat()).handle(command, identity, client)

    assert scheduler.calls == 0
    assert client.events[-1]["status"] == "failed"
    assert "profile" in client.events[-1]["message"]
