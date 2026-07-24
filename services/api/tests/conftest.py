from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from telesec_api.main import create_app
from telesec_api.settings import Settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        environment="test",
        api_host="127.0.0.1",
        api_port=8000,
        runtime_data_dir=tmp_path / "runtime-data",
        web_origin="http://localhost:3000",
        enrollment_ttl_seconds=900,
        heartbeat_interval_seconds=30,
        agent_offline_after_seconds=90,
        command_ttl_seconds=900,
        max_scan_targets=4096,
        scan_concurrency=3,
        allow_public_scopes=False,
        nvd_api_key=None,
        nvd_cache_ttl_seconds=86400,
        nvd_timeout_seconds=5,
    )


@pytest.fixture
def client(settings: Settings) -> Iterator[TestClient]:
    with TestClient(create_app(settings)) as test_client:
        yield test_client
