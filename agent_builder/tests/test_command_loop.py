from __future__ import annotations

import threading

from telesec_agent import command_loop
from telesec_agent.command_loop import AgentLoop
from telesec_agent.enrollment import AgentIdentity


def test_agent_reports_offline_when_loop_stops(monkeypatch):
    stop_event = threading.Event()
    identity = AgentIdentity(
        agent_id="00000000-0000-0000-0000-000000000123",
        server_url="https://telesec.example.com",
        credential="tes_agent_secret",
        heartbeat_interval_seconds=30,
        enrolled_at="2026-07-23T10:00:00Z",
    )
    statuses = []

    class Enrollment:
        @staticmethod
        def ensure_enrolled():
            return identity

    class Heartbeat:
        @staticmethod
        def send(_identity, *, service_status="online", client):
            statuses.append(service_status)
            return {"status": "accepted"}

    class Client:
        def __init__(self, _server_url, *, timeout_seconds=15.0):
            self.timeout_seconds = timeout_seconds

        @staticmethod
        def next_command(*, credential):
            assert credential == identity.credential
            stop_event.set()
            return None

    monkeypatch.setattr(command_loop, "TelesecApiClient", Client)
    loop = AgentLoop(Enrollment(), Heartbeat(), object(), stop_event)

    loop.run()

    assert statuses == ["online", "offline"]

