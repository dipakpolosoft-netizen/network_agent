from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from test_enrollment_flow import enroll_agent

from forgesec_api.auth.service import SESSION_COOKIE
from forgesec_api.main import create_app
from forgesec_api.settings import Settings


def test_password_login_refuses_plain_http_lan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORGESEC_AUTH_REQUIRED", "true")
    monkeypatch.setenv("FORGESEC_WEB_ORIGIN", "http://192.0.2.10:3000")
    with pytest.raises(ValueError, match="requires HTTPS"):
        Settings.from_env()


def test_production_requires_database_and_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORGESEC_ENV", "production")
    monkeypatch.setenv("FORGESEC_WEB_ORIGIN", "https://forgesec.example")
    monkeypatch.delenv("FORGESEC_DATABASE_URL", raising=False)
    with pytest.raises(ValueError, match="requires PostgreSQL"):
        Settings.from_env()
    monkeypatch.setenv("FORGESEC_DATABASE_URL", "postgresql://example")
    monkeypatch.setenv("FORGESEC_AUTH_REQUIRED", "false")
    with pytest.raises(ValueError, match="operator authentication"):
        Settings.from_env()


def test_login_session_csrf_and_roles(settings: Settings) -> None:
    app = create_app(replace(settings, auth_required=True))
    with TestClient(app) as client:
        auth = app.state.auth_service
        auth.create_user("admin@example.test", "correct horse battery", "admin")
        signed_out = client.get("/api/sites")
        assert signed_out.status_code == 401
        assert signed_out.headers["cache-control"] == "private, no-store"
        assert client.get("/health").status_code == 200
        _, probe_token = app.state.enrollment_service.create(
            label="QA Probe", site_name="QA Site"
        )
        assert enroll_agent(client, probe_token)["agent_id"]

        signed_in = client.post(
            "/api/auth/login",
            json={"email": "ADMIN@example.test", "password": "correct horse battery"},
        )
        assert signed_in.status_code == 200
        assert signed_in.json()["user"]["role"] == "admin"
        assert "httponly" in signed_in.headers["set-cookie"].lower()
        csrf = signed_in.json()["csrf_token"]
        assert client.get("/api/auth/me").json()["csrf_token"] == csrf
        assert client.get("/api/sites").headers["cache-control"] == "private, no-store"
        assert client.get("/api/auth/users").json()[0]["email"] == "admin@example.test"
        denied = client.post("/api/sites", json={"name": "Protected"})
        assert denied.status_code == 403
        assert denied.headers["cache-control"] == "private, no-store"
        assert (
            client.post(
                "/api/sites",
                json={"name": "Protected"},
                headers={"X-CSRF-Token": csrf},
            ).status_code
            == 201
        )

        created = client.post(
            "/api/auth/users",
            json={
                "email": "viewer@example.test",
                "password": "another correct password",
                "role": "viewer",
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert created.status_code == 201
        assert "password_hash" not in created.json()
        assert (
            client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf}).status_code
            == 204
        )
        assert client.get("/api/sites").status_code == 401

        viewer = client.post(
            "/api/auth/login",
            json={
                "email": "viewer@example.test",
                "password": "another correct password",
            },
        )
        assert viewer.status_code == 200
        viewer_csrf = viewer.json()["csrf_token"]
        assert client.get("/api/sites").status_code == 200
        assert client.get("/api/auth/users").status_code == 403
        assert (
            client.post(
                "/api/sites",
                json={"name": "Denied"},
                headers={"X-CSRF-Token": viewer_csrf},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/api/auth/password",
                json={
                    "current_password": "another correct password",
                    "new_password": "a newly chosen password",
                },
                headers={"X-CSRF-Token": viewer_csrf},
            ).status_code
            == 204
        )
        assert client.get("/api/sites").status_code == 401
        assert (
            client.post(
                "/api/auth/login",
                json={
                    "email": "viewer@example.test",
                    "password": "a newly chosen password",
                },
            ).status_code
            == 200
        )
        auth.set_active(created.json()["user_id"], False)
        assert client.get("/api/sites").status_code == 401
        auth.set_active(created.json()["user_id"], True)
        assert client.get("/api/sites").status_code == 401


def test_operator_cannot_manage_site_or_enrollment(settings: Settings) -> None:
    app = create_app(replace(settings, auth_required=True))
    with TestClient(app) as client:
        app.state.auth_service.create_user(
            "operator@example.test", "operator password here", "operator"
        )
        signed_in = client.post(
            "/api/auth/login",
            json={
                "email": "operator@example.test",
                "password": "operator password here",
            },
        )
        csrf = signed_in.json()["csrf_token"]
        assert (
            client.post(
                "/api/sites",
                json={"name": "Denied"},
                headers={"X-CSRF-Token": csrf},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/api/enrollments",
                json={"label": "Denied", "site_name": "Denied"},
                headers={"X-CSRF-Token": csrf},
            ).status_code
            == 403
        )
        events = [
            json.loads(line)
            for line in (settings.runtime_data_dir / "activity" / "activity.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        denials = [
            event
            for event in events
            if event["event_type"] == "security.request_denied"
        ]
        assert len(denials) == 2
        assert {event["details"]["route"] for event in denials} == {
            "/api/sites",
            "/api/enrollments",
        }
        assert all(event["actor_type"] == "user" for event in denials)
        assert csrf not in json.dumps(denials)
        assert client.get("/api/sites").json() == []
        assert app.state.store.list("enrollments") == []


def test_denial_audit_does_not_store_untrusted_path_segment(
    client: TestClient, settings: Settings
) -> None:
    marker = "sensitive-path-segment"
    response = client.get(f"/api/sites/{marker}/scopes")
    assert response.status_code == 422
    events = [
        json.loads(line)
        for line in (settings.runtime_data_dir / "activity" / "activity.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    denials = [
        event for event in events if event["event_type"] == "security.request_denied"
    ]
    assert len(denials) == 1
    assert denials[0]["details"]["route"] == "/api/sites/{site_id}/scopes"
    assert marker not in json.dumps(denials[0])


def test_expired_operator_session_is_rejected_and_audited_once(
    settings: Settings,
) -> None:
    app = create_app(replace(settings, auth_required=True))
    with TestClient(app) as client:
        user = app.state.auth_service.create_user(
            "viewer@example.test", "long test password here", "viewer"
        )
        assert client.post(
            "/api/auth/login",
            json={
                "email": "viewer@example.test",
                "password": "long test password here",
            },
        ).status_code == 200
        token = client.cookies.get(SESSION_COOKIE)
        key = hashlib.sha256(token.encode()).hexdigest()
        session = app.state.store.read("sessions", key)
        session["expires_at"] = "2020-01-01T00:00:00Z"
        app.state.store.write("sessions", key, session)
        assert client.get("/api/scans").status_code == 401
        assert client.get("/api/scans").status_code == 401
        events = [
            json.loads(line)
            for line in (settings.runtime_data_dir / "activity" / "activity.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        expired = [
            event for event in events
            if event["event_type"] == "user.session_expired"
        ]
        assert len(expired) == 1
        assert expired[0]["actor_id"] == user["user_id"]
        assert token not in json.dumps(expired[0])


def test_failed_login_is_rate_limited(settings: Settings) -> None:
    app = create_app(replace(settings, auth_required=True))
    with TestClient(app) as client:
        app.state.auth_service.create_user(
            "admin@example.test", "correct horse battery", "admin"
        )
        for _ in range(5):
            assert (
                client.post(
                    "/api/auth/login",
                    json={"email": "admin@example.test", "password": "wrong"},
                ).status_code
                == 401
            )
        response = client.post(
            "/api/auth/login",
            json={"email": "admin@example.test", "password": "correct horse battery"},
        )
        assert response.status_code == 401
        assert "Too many attempts" in response.json()["detail"]


def test_https_cookie_is_secure_and_revoked(settings: Settings) -> None:
    app = create_app(
        replace(settings, auth_required=True, web_origin="https://forgesec.example")
    )
    with TestClient(app, base_url="https://forgesec.example") as client:
        app.state.auth_service.create_user(
            "admin@example.test", "correct horse battery", "admin"
        )
        signed_in = client.post(
            "/api/auth/login",
            json={"email": "admin@example.test", "password": "correct horse battery"},
        )
        assert signed_in.status_code == 200
        assert "__Host-forgesec_session" in signed_in.headers["set-cookie"]
        assert "secure" in signed_in.headers["set-cookie"].lower()
        assert client.get("/api/auth/me").status_code == 200
        signed_out = client.post(
            "/api/auth/logout",
            headers={"X-CSRF-Token": signed_in.json()["csrf_token"]},
        )
        assert signed_out.status_code == 204
        assert client.get("/api/auth/me").status_code == 401
