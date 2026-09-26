"""Opt-in integration test against a disposable PostgreSQL server."""

from __future__ import annotations

import os
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql

from forgesec_api.auth.service import AuthService
from forgesec_api.main import create_app
from forgesec_api.migrate_json import import_json
from forgesec_api.postgres_storage import PostgresStore
from forgesec_api.settings import Settings
from forgesec_api.storage import JsonStore


def test_postgres_import_and_transactions(tmp_path: Path) -> None:
    base_url = os.getenv("FORGESEC_TEST_DATABASE_URL")
    if not base_url:
        pytest.skip("Set FORGESEC_TEST_DATABASE_URL for PostgreSQL integration")
    database = f"forgesec_qa_{uuid4().hex[:12]}"
    parsed = urlsplit(base_url)
    test_url = urlunsplit(parsed._replace(path=f"/{database}"))
    with psycopg.connect(base_url, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
    try:
        source = JsonStore(tmp_path / "json-source")
        source.initialize()
        site = {
            "site_id": str(uuid4()),
            "name": "QA Site",
            "owner": None,
            "description": None,
            "created_at": "2026-09-25T00:00:00Z",
        }
        source.write("sites", site["site_id"], site)
        source.write(
            "assets",
            "asset-qa",
            {
                "asset_id": "asset-qa",
                "site_id": site["site_id"],
                "display_name": "Core 100%",
                "last_seen": "2026-09-25T00:00:00Z",
            },
        )
        source.append_activity(
            {"event_id": str(uuid4()), "occurred_at": "2026-09-25T00:00:00Z"}
        )
        destination = PostgresStore(tmp_path / "cache", test_url)
        destination.initialize()
        try:
            counts = import_json(source.root, destination)
            assert counts["sites"] == 1
            assert destination.contains_data() is True
            assert (
                destination.list_by_field("assets", "site_id", site["site_id"])[0][
                    "asset_id"
                ]
                == "asset-qa"
            )
            assert (
                destination.page_assets(
                    site_id=site["site_id"], query="100%", limit=1, offset=0
                )["total"]
                == 1
            )
            assert counts["activity-events"] == 1
            assert destination.read("sites", site["site_id"]) == site
            with pytest.raises(ValueError, match="empty store"):
                import_json(source.root, destination)
            with pytest.raises(RuntimeError, match="roll back"), destination.locked():
                destination.write("sites", "rollback", {"name": "Discarded"})
                raise RuntimeError("roll back")
            assert destination.read("sites", "rollback") is None
            auth = AuthService(destination, 3600)
            user = auth.create_user(
                "db@example.test", "database password here", "admin"
            )
            assert user["email"] == "db@example.test"
            assert (
                auth.login("db@example.test", "database password here")[0]["role"]
                == "admin"
            )
        finally:
            destination.close()
        settings = replace(
            Settings.from_env(),
            environment="test",
            runtime_data_dir=tmp_path / "cache",
            database_url=test_url,
            auth_required=True,
        )
        with TestClient(create_app(settings)) as client:
            assert client.get("/api/sites").status_code == 401
            signed_in = client.post(
                "/api/auth/login",
                json={"email": "db@example.test", "password": "database password here"},
            )
            assert signed_in.status_code == 200
            assert client.get("/api/sites").json()[0]["name"] == "QA Site"
            csrf = {"X-CSRF-Token": signed_in.json()["csrf_token"]}
            scope = client.post(
                f"/api/sites/{site['site_id']}/scopes",
                headers=csrf,
                json={"cidr": "10.50.0.0/24", "label": "QA LAN"},
            )
            assert scope.status_code == 201
            worker = client.post(
                "/api/workers",
                headers=csrf,
                json={
                    "site_id": site["site_id"],
                    "label": "QA worker",
                    "capabilities": ["network_inventory"],
                },
            )
            assert worker.status_code == 201
            machine = {"Authorization": f"Bearer {worker.json()['credential']}"}
            assert (
                client.post(
                    "/worker/heartbeat",
                    headers=machine,
                    json={
                        "schema_version": "1.0",
                        "worker_id": worker.json()["worker_id"],
                        "version": "0.1.0",
                        "available_capabilities": ["network_inventory"],
                    },
                ).status_code
                == 200
            )
            queued = client.app.state.worker_service.enqueue(
                site_id=site["site_id"],
                capability="network_inventory",
                target_ip="10.50.0.10",
                profile="inventory",
            )
            claim = client.get("/worker/jobs/next", headers=machine)
            assert claim.status_code == 200
            assert (
                client.delete(
                    f"/api/sites/{site['site_id']}/scopes/{scope.json()['scope_id']}",
                    headers=csrf,
                ).status_code
                == 204
            )
            denied = client.post(
                f"/worker/jobs/{queued['job_id']}/result",
                headers=machine,
                json={
                    "schema_version": "1.0",
                    "lease_id": claim.json()["lease_id"],
                    "status": "completed",
                    "summary": "Stale result",
                },
            )
            assert denied.status_code == 409
            assert (
                client.app.state.store.read("scanner-worker-jobs", queued["job_id"])[
                    "status"
                ]
                == "cancelled"
            )
    finally:
        with psycopg.connect(base_url, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(database)))
