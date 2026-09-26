from __future__ import annotations

from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from forgesec_api.customer_binding import bind_customer
from forgesec_api.main import create_app
from forgesec_api.settings import Settings
from forgesec_api.storage import JsonStore


def test_empty_store_binds_once_and_refuses_wrong_customer(settings: Settings) -> None:
    bound = replace(settings, customer_id="customer-one")
    with TestClient(create_app(bound)) as client:
        assert client.get("/health").status_code == 200
        assert (
            client.app.state.store.read("deployment", "customer")["customer_id"]
            == "customer-one"
        )
    with TestClient(create_app(bound)) as client:
        assert client.get("/health").status_code == 200
    with (
        pytest.raises(RuntimeError, match="does not match"),
        TestClient(create_app(replace(bound, customer_id="customer-two"))),
    ):
        pass
    with (
        pytest.raises(RuntimeError, match="does not match"),
        TestClient(create_app(settings)),
    ):
        pass


def test_existing_data_needs_explicit_one_time_adoption(settings: Settings) -> None:
    store = JsonStore(settings.runtime_data_dir)
    store.initialize()
    store.write("sites", "site-1", {"site_id": "site-1", "name": "Existing"})
    with pytest.raises(RuntimeError, match="Existing unbound data"):
        bind_customer(store, "customer-one")
    assert store.read("deployment", "customer") is None
    bind_customer(store, "customer-one", adopt_legacy_data=True)
    assert store.read("deployment", "customer")["adopted_legacy_data"] is True
    bind_customer(store, "customer-one")
    assert store.read("sites", "site-1")["name"] == "Existing"


def test_activity_and_production_guard_are_not_bypassed(settings: Settings) -> None:
    store = JsonStore(settings.runtime_data_dir)
    store.initialize()
    store.append_activity({"event_id": "test", "occurred_at": "2026-01-01T00:00:00Z"})
    assert store.contains_data(exclude=("deployment",)) is True
    with pytest.raises(RuntimeError, match="Production requires"):
        bind_customer(store, None, required=True)
    with pytest.raises(RuntimeError, match="Existing unbound data"):
        bind_customer(store, "customer-one")


def test_production_settings_require_customer_slug(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FORGESEC_ENV", "production")
    monkeypatch.setenv("FORGESEC_DATABASE_URL", "postgresql://example/test")
    monkeypatch.setenv("FORGESEC_AUTH_REQUIRED", "true")
    monkeypatch.delenv("FORGESEC_CUSTOMER_ID", raising=False)
    with pytest.raises(ValueError, match="FORGESEC_CUSTOMER_ID"):
        Settings.from_env()
    monkeypatch.setenv("FORGESEC_CUSTOMER_ID", "Customer One")
    with pytest.raises(ValueError, match="lowercase slug"):
        Settings.from_env()
