from __future__ import annotations

import json

import pytest

from telesec_agent.config import (
    BootstrapConfig,
    ConfigurationError,
    validate_server_url,
    write_bootstrap_config,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://telesec.example.com/", "https://telesec.example.com"),
        ("http://127.0.0.1:8000", "http://127.0.0.1:8000"),
        ("http://localhost:8000", "http://localhost:8000"),
    ],
)
def test_server_url_accepts_https_and_local_http(value: str, expected: str) -> None:
    assert validate_server_url(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "http://192.168.1.10:8000",
        "ftp://telesec.example.com",
        "https://user:pass@telesec.example.com",
        "https://telesec.example.com?token=secret",
    ],
)
def test_server_url_rejects_insecure_or_credentialed_values(value: str) -> None:
    with pytest.raises(ConfigurationError):
        validate_server_url(value)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "utf-16-le"])
def test_bootstrap_loads_installer_written_encodings(tmp_path, encoding):
    document = {
        "server_url": "http://127.0.0.1:8000",
        "enrollment_token": "tes_enr_test_token_abcdefghijklmnopqrstuvwxyz",
    }
    bootstrap = tmp_path / "bootstrap.json"
    bootstrap.write_bytes(json.dumps(document).encode(encoding))

    loaded = BootstrapConfig.load(bootstrap)

    assert loaded.server_url == "http://127.0.0.1:8000"
    assert loaded.enrollment_token == document["enrollment_token"]


def test_bootstrap_writer_creates_utf8_json(tmp_path):
    bootstrap = tmp_path / "config" / "bootstrap.json"
    token = "tes_enr_test_token_abcdefghijklmnopqrstuvwxyz"

    write_bootstrap_config(
        bootstrap,
        server_url="http://127.0.0.1:8000",
        enrollment_token=token,
    )

    assert b"\x00" not in bootstrap.read_bytes()
    assert BootstrapConfig.load(bootstrap).enrollment_token == token
