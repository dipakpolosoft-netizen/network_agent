"""Agent paths and installer-provided bootstrap configuration."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


class ConfigurationError(RuntimeError):
    pass


def default_data_directory() -> Path:
    program_data = os.getenv("PROGRAMDATA")
    base = Path(program_data) if program_data else Path.home() / ".telesec"
    return base / "Telesec" / "NetworkAgent"


def validate_server_url(value: str) -> str:
    candidate = value.strip().rstrip("/")
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConfigurationError("Server URL must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConfigurationError(
            "Server URL cannot include credentials, query, or fragment"
        )
    local_hosts = {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and parsed.hostname not in local_hosts:
        raise ConfigurationError("HTTPS is required for non-local Telesec servers")
    return candidate


def dashboard_url_for_server(server_url: str) -> str:
    parsed = urlsplit(validate_server_url(server_url))
    hostname = parsed.hostname or "localhost"
    if hostname in {"localhost", "127.0.0.1", "::1"} and parsed.port == 8000:
        display_host = f"[{hostname}]" if ":" in hostname else hostname
        netloc = f"{display_host}:3000"
    else:
        netloc = parsed.netloc
    return urlunsplit((parsed.scheme, netloc, "/network-agent", "", ""))


@dataclass(frozen=True, slots=True)
class BootstrapConfig:
    server_url: str
    enrollment_token: str

    @classmethod
    def load(cls, path: Path) -> BootstrapConfig:
        if not path.is_file():
            raise ConfigurationError(f"Bootstrap file not found: {path}")
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigurationError("Bootstrap file is not valid JSON") from exc
        token = str(document.get("enrollment_token", "")).strip()
        if len(token) < 32:
            raise ConfigurationError("Enrollment token is missing or invalid")
        return cls(
            server_url=validate_server_url(str(document.get("server_url", ""))),
            enrollment_token=token,
        )


@dataclass(frozen=True, slots=True)
class AgentPaths:
    root: Path

    @property
    def bootstrap(self) -> Path:
        return self.root / "config" / "bootstrap.json"

    @property
    def identity(self) -> Path:
        return self.root / "identity" / "identity.json"

    @property
    def state(self) -> Path:
        return self.root / "state" / "status.json"

    @property
    def public_status(self) -> Path:
        return self.root / "public" / "status.json"

    @property
    def log(self) -> Path:
        return self.root / "logs" / "agent.log"
