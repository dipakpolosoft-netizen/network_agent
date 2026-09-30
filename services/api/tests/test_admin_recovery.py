from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from forgesec_api.auth.recover_admin import (
    recover_admin_password,
    require_local_development,
)
from forgesec_api.auth.service import AuthError, AuthService, verify_password
from forgesec_api.settings import Settings
from forgesec_api.storage import JsonStore


def test_local_recovery_revokes_sessions_and_clears_lockout(tmp_path) -> None:
    store = JsonStore(tmp_path)
    store.initialize()
    auth = AuthService(store, 3600)
    user = auth.create_user("ADMIN@example.test", "old password value", "admin")
    _, session, _ = auth.login(user["email"], "old password value")
    attempt_key = hashlib.sha256(user["email"].encode()).hexdigest()
    store.write(
        "auth-attempts", attempt_key, {"count": 5, "until": "2099-01-01T00:00:00Z"}
    )

    recover_admin_password(store, "ADMIN@example.test", "new password value")

    saved = store.read("users", user["user_id"])
    assert saved is not None
    assert verify_password("new password value", saved["password_hash"])
    assert not verify_password("old password value", saved["password_hash"])
    assert auth.session(session) is None
    assert store.read("auth-attempts", attempt_key) is None
    signed_in, _, _ = auth.login(user["email"], "new password value")
    assert signed_in["user_id"] == user["user_id"]


def test_recovery_rejects_non_admin_and_short_password(tmp_path) -> None:
    store = JsonStore(tmp_path)
    store.initialize()
    auth = AuthService(store, 3600)
    auth.create_user("operator@example.test", "initial password", "operator")
    with pytest.raises(AuthError, match="administrator not found"):
        recover_admin_password(store, "operator@example.test", "new password value")
    with pytest.raises(AuthError, match="12 to 256"):
        recover_admin_password(store, "operator@example.test", "short")


def test_recovery_is_local_development_only(settings: Settings) -> None:
    local = replace(settings, environment="development")
    require_local_development(local)
    for unsafe in (
        replace(local, environment="production"),
        replace(local, database_url="postgresql://example"),
        replace(local, api_host="0.0.0.0"),
    ):
        with pytest.raises(AuthError, match="local development"):
            require_local_development(unsafe)
