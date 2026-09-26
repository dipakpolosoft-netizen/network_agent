from __future__ import annotations

from pathlib import Path

import pytest

from forgesec_agent.api_client import ApiClientError
from forgesec_agent.config import AgentPaths, BootstrapConfig
from forgesec_agent.enrollment import EnrollmentManager, IdentityStore
from forgesec_agent.storage import AgentStorage


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
            "server_url": "https://forgesec.example.com",
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


def test_rotation_recovers_after_lost_response(tmp_path: Path) -> None:
    paths, storage, identities, manager = build_manager(tmp_path)
    identity = manager.enroll(
        BootstrapConfig(
            server_url="https://forgesec.example.com",
            enrollment_token="tes_enr_test_token_abcdefghijklmnopqrstuvwxyz",
        ),
        FakeEnrollmentClient(),
    )

    class Client:
        rotated = False

        def rotate_credential(self, agent_id, *, credential, new_credential):
            assert agent_id == identity.agent_id
            staged = identities.load()
            assert staged.pending_credential == new_credential
            assert new_credential not in paths.identity.read_text(encoding="utf-8")
            if not self.rotated:
                self.rotated = True
                raise ApiClientError("Response lost")
            raise ApiClientError("Old credential invalid", status_code=401)

        def credential_status(self, *, credential):
            assert credential == identities.load().pending_credential
            return {"agent_id": identity.agent_id}

    client = Client()
    with pytest.raises(ApiClientError, match="Response lost"):
        manager.rotate_if_due(identity, client)
    assert identities.load().pending_credential
    updated = manager.rotate_if_due(identities.load(), client)
    assert updated.credential != identity.credential
    assert updated.pending_credential is None
    assert identities.load() == updated
