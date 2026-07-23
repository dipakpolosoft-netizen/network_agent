from __future__ import annotations

from pathlib import Path

from telesec_agent.config import AgentPaths, BootstrapConfig
from telesec_agent.enrollment import EnrollmentManager, IdentityStore
from telesec_agent.storage import AgentStorage


class ReversingProtector:
    def protect(self, value: bytes) -> bytes:
        return value[::-1]

    def unprotect(self, value: bytes) -> bytes:
        return value[::-1]


class FakeEnrollmentClient:
    def enroll(self, payload: dict) -> dict:
        assert payload["message_type"] == "agent.enroll.request"
        assert (
            payload["enrollment_token"]
            == "tes_enr_test_token_abcdefghijklmnopqrstuvwxyz"
        )
        return {
            "agent_id": "00000000-0000-0000-0000-000000000123",
            "agent_credential": "tes_agent_secret_credential_value",
            "heartbeat_interval_seconds": 30,
            "issued_at": "2026-07-23T10:00:00Z",
        }


def build_manager(tmp_path: Path):
    paths = AgentPaths(tmp_path)
    storage = AgentStorage(paths)
    storage.initialize()
    identities = IdentityStore(storage, paths, ReversingProtector())
    return paths, storage, identities, EnrollmentManager(storage, paths, identities)


def test_enrollment_protects_credential_and_removes_bootstrap(tmp_path: Path) -> None:
    paths, storage, identities, manager = build_manager(tmp_path)
    storage.write_json(
        paths.bootstrap,
        {
            "server_url": "https://telesec.example.com",
            "enrollment_token": "tes_enr_test_token_abcdefghijklmnopqrstuvwxyz",
        },
    )
    bootstrap = BootstrapConfig.load(paths.bootstrap)
    identity = manager.enroll(bootstrap, FakeEnrollmentClient())

    assert identity.agent_id.endswith("0123")
    assert not paths.bootstrap.exists()
    persisted = paths.identity.read_text(encoding="utf-8")
    assert "tes_agent_secret_credential_value" not in persisted
    assert identities.load() == identity
