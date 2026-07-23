"""Environment-backed API settings."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _as_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True, slots=True)
class Settings:
    environment: str
    api_host: str
    api_port: int
    runtime_data_dir: Path
    web_origin: str
    enrollment_ttl_seconds: int
    heartbeat_interval_seconds: int
    agent_offline_after_seconds: int
    command_ttl_seconds: int
    max_scan_targets: int
    scan_concurrency: int
    allow_public_scopes: bool
    nvd_api_key: str | None = None
    nvd_cache_ttl_seconds: int = 86400
    nvd_timeout_seconds: int = 20

    @classmethod
    def from_env(cls) -> Settings:
        api_root = Path(__file__).resolve().parents[2]
        runtime_default = api_root / "runtime-data"
        return cls(
            environment=os.getenv("TELESEC_ENV", "development"),
            api_host=os.getenv("TELESEC_API_HOST", "127.0.0.1"),
            api_port=int(os.getenv("TELESEC_API_PORT", "8000")),
            runtime_data_dir=Path(
                os.getenv("TELESEC_RUNTIME_DATA_DIR", str(runtime_default))
            ).resolve(),
            web_origin=os.getenv("TELESEC_WEB_ORIGIN", "http://localhost:3000"),
            enrollment_ttl_seconds=int(
                os.getenv("TELESEC_ENROLLMENT_TTL_SECONDS", "900")
            ),
            heartbeat_interval_seconds=int(
                os.getenv("TELESEC_HEARTBEAT_INTERVAL_SECONDS", "30")
            ),
            agent_offline_after_seconds=int(
                os.getenv("TELESEC_AGENT_OFFLINE_AFTER_SECONDS", "90")
            ),
            command_ttl_seconds=int(os.getenv("TELESEC_COMMAND_TTL_SECONDS", "900")),
            max_scan_targets=int(os.getenv("TELESEC_MAX_SCAN_TARGETS", "10")),
            scan_concurrency=int(os.getenv("TELESEC_SCAN_CONCURRENCY", "3")),
            allow_public_scopes=_as_bool(
                os.getenv("TELESEC_ALLOW_PUBLIC_SCOPES", "false")
            ),
            nvd_api_key=os.getenv("TELESEC_NVD_API_KEY") or None,
            nvd_cache_ttl_seconds=int(
                os.getenv("TELESEC_NVD_CACHE_TTL_SECONDS", "86400")
            ),
            nvd_timeout_seconds=int(os.getenv("TELESEC_NVD_TIMEOUT_SECONDS", "20")),
        )
