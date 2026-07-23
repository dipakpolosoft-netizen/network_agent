from __future__ import annotations

import pytest

from telesec_agent.config import ConfigurationError, validate_server_url


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
