from __future__ import annotations

from pathlib import Path

from telesec_agent.config import AgentPaths
from telesec_agent.enrollment import AgentIdentity
from telesec_agent.heartbeat import HeartbeatSender
from telesec_agent.storage import AgentStorage


class FakeHeartbeatClient:
    def __init__(self):
        self.payload = None
        self.credential = None

    def heartbeat(self, payload: dict, *, credential: str) -> dict:
        self.payload = payload
        self.credential = credential
        return {"status": "accepted", "next_heartbeat_seconds": 30}


def test_heartbeat_writes_acknowledged_local_state(tmp_path: Path) -> None:
    paths = AgentPaths(tmp_path)
    storage = AgentStorage(paths)
    storage.initialize()
    identity = AgentIdentity(
        agent_id="00000000-0000-0000-0000-000000000123",
        server_url="https://telesec.example.com",
        credential="tes_agent_secret",
        heartbeat_interval_seconds=30,
        enrolled_at="2026-07-23T10:00:00Z",
    )
    client = FakeHeartbeatClient()

    HeartbeatSender(storage, paths.state, paths.public_status).send(
        identity,
        client=client,
    )

    assert client.credential == "tes_agent_secret"
    assert client.payload["agent_id"] == identity.agent_id
    state = storage.read_json(paths.state)
    assert state is not None
    assert state["status"] == "online"
    assert state["server_status"] == "accepted"
    public_state = storage.read_json(paths.public_status)
    assert public_state is not None
    assert public_state["dashboard_url"] == "https://telesec.example.com/network-agent"
    assert "credential" not in public_state
