"""Public production smoke-check regression tests."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from smoke_production import check


class FakeResponse:
    def __init__(self, url: str, status: int, body: bytes = b"") -> None:
        self.url = url
        self.status = status
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self) -> bytes:
        return self.body


class ProductionSmokeTests(unittest.TestCase):
    def test_rejects_non_https_and_malformed_urls(self) -> None:
        for url in ("http://scan.company.com", "https://scan.company.com:bad", "https://scan.company.com/path"):
            with self.subTest(url=url):
                self.assertTrue(check(url))

    def test_checks_public_routes_without_credentials(self) -> None:
        seen = []

        def fake_open(request, timeout):
            seen.append((request.full_url, request.get_method(), request.get_header("Authorization")))
            if request.full_url.endswith("/health"):
                return FakeResponse(request.full_url, 200, json.dumps({
                    "service": "forgesec-api", "environment": "production"
                }).encode())
            if request.full_url.endswith("/login"):
                return FakeResponse(request.full_url, 200)
            raise HTTPError(request.full_url, 401, "Unauthorized", {}, None)

        with patch("smoke_production.urlopen", side_effect=fake_open):
            self.assertEqual(check("https://scan.company.com"), [])
        self.assertEqual(len(seen), 4)
        self.assertEqual(seen[-1][1], "POST")
        self.assertTrue(all(auth is None for _, _, auth in seen))

    def test_reports_unreachable_endpoint_without_leaking_url(self) -> None:
        with patch("smoke_production.urlopen", side_effect=URLError("secret query")):
            issues = check("https://scan.company.com")
        self.assertEqual(len(issues), 4)
        self.assertNotIn("secret query", " ".join(issues))


if __name__ == "__main__":
    unittest.main()
