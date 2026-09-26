"""Environment-backed API settings."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


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
    database_url: str | None = None
    auth_required: bool = False
    session_ttl_seconds: int = 43200
    customer_id: str | None = None
    adopt_legacy_customer_data: bool = False

    @classmethod
    def from_env(cls) -> Settings:
        api_root = Path(__file__).resolve().parents[2]
        runtime_default = api_root / "runtime-data"
        environment = os.getenv("FORGESEC_ENV", "development")
        database_url = os.getenv("FORGESEC_DATABASE_URL") or None
        web_origin = os.getenv("FORGESEC_WEB_ORIGIN", "http://localhost:3000")
        auth_required = _as_bool(os.getenv("FORGESEC_AUTH_REQUIRED", "true"))
        customer_id = os.getenv("FORGESEC_CUSTOMER_ID", "").strip() or None
        if customer_id and not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,63}", customer_id):
            raise ValueError(
                "FORGESEC_CUSTOMER_ID must be a 3-64 character lowercase slug"
            )
        if environment == "production" and (not database_url or not auth_required):
            raise ValueError(
                "Production requires PostgreSQL and operator authentication"
            )
        if environment == "production" and not customer_id:
            raise ValueError("Production requires FORGESEC_CUSTOMER_ID")
        origin = urlsplit(web_origin)
        if (
            auth_required
            and origin.scheme != "https"
            and origin.hostname
            not in {
                "localhost",
                "127.0.0.1",
                "::1",
            }
        ):
            raise ValueError("Operator access on a non-loopback origin requires HTTPS")
        return cls(
            environment=environment,
            api_host=os.getenv("FORGESEC_API_HOST", "127.0.0.1"),
            api_port=int(os.getenv("FORGESEC_API_PORT", "8000")),
            runtime_data_dir=Path(
                os.getenv("FORGESEC_RUNTIME_DATA_DIR", str(runtime_default))
            ).resolve(),
            web_origin=web_origin,
            enrollment_ttl_seconds=int(
                os.getenv("FORGESEC_ENROLLMENT_TTL_SECONDS", "900")
            ),
            heartbeat_interval_seconds=int(
                os.getenv("FORGESEC_HEARTBEAT_INTERVAL_SECONDS", "30")
            ),
            agent_offline_after_seconds=int(
                os.getenv("FORGESEC_AGENT_OFFLINE_AFTER_SECONDS", "90")
            ),
            command_ttl_seconds=int(os.getenv("FORGESEC_COMMAND_TTL_SECONDS", "900")),
            max_scan_targets=int(os.getenv("FORGESEC_MAX_SCAN_TARGETS", "4096")),
            scan_concurrency=int(os.getenv("FORGESEC_SCAN_CONCURRENCY", "3")),
            allow_public_scopes=_as_bool(
                os.getenv("FORGESEC_ALLOW_PUBLIC_SCOPES", "false")
            ),
            nvd_api_key=os.getenv("FORGESEC_NVD_API_KEY") or None,
            nvd_cache_ttl_seconds=int(
                os.getenv("FORGESEC_NVD_CACHE_TTL_SECONDS", "86400")
            ),
            nvd_timeout_seconds=int(os.getenv("FORGESEC_NVD_TIMEOUT_SECONDS", "20")),
            database_url=database_url,
            auth_required=auth_required,
            session_ttl_seconds=int(os.getenv("FORGESEC_SESSION_TTL_SECONDS", "43200")),
            customer_id=customer_id,
            adopt_legacy_customer_data=_as_bool(
                os.getenv("FORGESEC_ADOPT_LEGACY_CUSTOMER_DATA", "false")
            ),
        )
