"""Public production smoke-check regression tests."""

from __future__ import annotations

import json
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

from smoke_production import check, check_login


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
        for url in (
            "http://scan.company.com",
            "https://scan.company.com:bad",
            "https://scan.company.com/path",
        ):
            with self.subTest(url=url):
                self.assertTrue(check(url))

    def test_checks_public_routes_without_credentials(self) -> None:
        seen = []

        def fake_open(request, timeout):
            seen.append(
                (
                    request.full_url,
                    request.get_method(),
                    request.get_header("Authorization"),
                )
            )
            if request.full_url.endswith("/health"):
                return FakeResponse(
                    request.full_url,
                    200,
                    json.dumps(
                        {"service": "forgesec-api", "environment": "production"}
                    ).encode(),
                )
            if request.full_url.endswith("/ready"):
                return FakeResponse(request.full_url, 200, b'{"status":"ready"}')
            if request.full_url.endswith("/login"):
                return FakeResponse(request.full_url, 200)
            raise HTTPError(request.full_url, 401, "Unauthorized", {}, None)

        with patch(
            "smoke_production.build_opener",
            return_value=SimpleNamespace(open=fake_open),
        ):
            self.assertEqual(check("https://scan.company.com"), [])
        self.assertEqual(len(seen), 5)
        self.assertEqual(seen[-1][1], "POST")
        self.assertTrue(all(auth is None for _, _, auth in seen))

    def test_reports_unreachable_endpoint_without_leaking_url(self) -> None:
        with patch(
            "smoke_production.build_opener",
            return_value=SimpleNamespace(open=MagicMock(side_effect=URLError("secret query"))),
        ):
            issues = check("https://scan.company.com")
        self.assertEqual(len(issues), 5)
        self.assertNotIn("secret query", " ".join(issues))

    def test_reports_unavailable_storage(self) -> None:
        def fake_open(request, timeout):
            if request.full_url.endswith("/ready"):
                raise HTTPError(request.full_url, 503, "Unavailable", {}, None)
            if request.full_url.endswith("/health"):
                return FakeResponse(
                    request.full_url,
                    200,
                    b'{"service":"forgesec-api","environment":"production"}',
                )
            if request.full_url.endswith("/login"):
                return FakeResponse(request.full_url, 200)
            raise HTTPError(request.full_url, 401, "Unauthorized", {}, None)

        with patch(
            "smoke_production.build_opener",
            return_value=SimpleNamespace(open=fake_open),
        ):
            issues = check("https://scan.company.com")
        self.assertTrue(any("/ready" in issue for issue in issues))

    def test_rejects_redirect_without_following_it(self) -> None:
        seen = []

        def fake_open(request, timeout):
            seen.append(request.full_url)
            raise HTTPError(request.full_url, 302, "Moved", {}, None)

        with patch(
            "smoke_production.build_opener",
            return_value=SimpleNamespace(open=fake_open),
        ) as build:
            issues = check("https://scan.company.com")
        self.assertEqual(len(seen), 5)
        self.assertEqual(type(build.call_args.args[0]).__name__, "NoRedirect")
        self.assertTrue(any("expected HTTP 200, received 302" in issue for issue in issues))

    def test_operator_login_checks_session_and_signs_out(self) -> None:
        seen = []

        class FakeOpener:
            def open(self, request, timeout):
                seen.append(request)
                url = request if isinstance(request, str) else request.full_url
                if url.endswith("/login"):
                    return FakeResponse(
                        url,
                        200,
                        json.dumps(
                            {
                                "user": {
                                    "user_id": "user-1",
                                    "email": "admin@example.test",
                                },
                                "csrf_token": "request-token",
                            }
                        ).encode(),
                    )
                if url.endswith("/me"):
                    return FakeResponse(url, 200, b'{"user":{"user_id":"user-1"}}')
                return FakeResponse(url, 204)

        cookies = MagicMock()
        cookies.__iter__.return_value = iter(
            [SimpleNamespace(
                name="__Host-forgesec_session", secure=True, path="/",
                domain_specified=False,
                _rest={"HttpOnly": None, "SameSite": "strict"},
            )]
        )
        with (
            patch("smoke_production.CookieJar", return_value=cookies),
            patch("smoke_production.build_opener", return_value=FakeOpener()),
        ):
            self.assertEqual(
                check_login(
                    "https://scan.company.com", "admin@example.test", "test-secret"
                ),
                [],
            )
        self.assertEqual(len(seen), 3)
        self.assertEqual(seen[0].get_header("Origin"), "https://scan.company.com")
        self.assertEqual(seen[-1].get_header("X-csrf-token"), "request-token")

    def test_operator_login_requires_https_before_sending_password(self) -> None:
        with patch("smoke_production.build_opener") as opener:
            self.assertTrue(
                check_login(
                    "http://scan.company.com", "admin@example.test", "test-secret"
                )
            )
        opener.assert_not_called()

    def test_operator_login_rejects_cookie_without_browser_protections(self) -> None:
        for attributes, domain_specified, expected in (
            ({}, False, "HttpOnly"),
            ({"HttpOnly": None, "SameSite": "strict"}, True, "secure session cookie"),
        ):
            with self.subTest(expected=expected):
                seen = []

                def fake_open(request, timeout):
                    seen.append(request.full_url)
                    if request.full_url.endswith("/login"):
                        return FakeResponse(
                            request.full_url,
                            200,
                            b'{"user":{"email":"admin@example.test"},"csrf_token":"token"}',
                        )
                    return FakeResponse(request.full_url, 204)

                cookies = MagicMock()
                cookies.__iter__.return_value = iter(
                    [SimpleNamespace(
                        name="__Host-forgesec_session", secure=True, path="/",
                        domain_specified=domain_specified, _rest=attributes,
                    )]
                )
                with (
                    patch("smoke_production.CookieJar", return_value=cookies),
                    patch(
                        "smoke_production.build_opener",
                        return_value=SimpleNamespace(open=fake_open),
                    ),
                ):
                    issues = check_login(
                        "https://scan.company.com", "admin@example.test", "test-secret"
                    )
                self.assertTrue(any(expected in issue for issue in issues))
                self.assertTrue(seen[-1].endswith("/logout"))

    def test_operator_role_cannot_read_admin_users(self) -> None:
        seen = []

        class FakeOpener:
            def open(self, request, timeout):
                url = request if isinstance(request, str) else request.full_url
                seen.append(url)
                if url.endswith("/login"):
                    return FakeResponse(
                        url,
                        200,
                        json.dumps(
                            {
                                "user": {
                                    "user_id": "user-1",
                                    "email": "operator@example.test",
                                    "role": "operator",
                                },
                                "csrf_token": "request-token",
                            }
                        ).encode(),
                    )
                if url.endswith("/me"):
                    return FakeResponse(
                        url, 200, b'{"user":{"user_id":"user-1","role":"operator"}}'
                    )
                if url.endswith("/users"):
                    raise HTTPError(url, 403, "Forbidden", {}, None)
                return FakeResponse(url, 204)

        cookies = MagicMock()
        cookies.__iter__.return_value = iter(
            [SimpleNamespace(
                name="__Host-forgesec_session", secure=True, path="/",
                domain_specified=False,
                _rest={"HttpOnly": None, "SameSite": "strict"},
            )]
        )
        with (
            patch("smoke_production.CookieJar", return_value=cookies),
            patch("smoke_production.build_opener", return_value=FakeOpener()),
        ):
            self.assertEqual(
                check_login(
                    "https://scan.company.com",
                    "operator@example.test",
                    "test-secret",
                    "operator",
                ),
                [],
            )
        self.assertTrue(any(url.endswith("/users") for url in seen))
        self.assertTrue(seen[-1].endswith("/logout"))

    def test_admin_role_can_read_admin_users(self) -> None:
        seen = []

        class FakeOpener:
            def open(self, request, timeout):
                url = request if isinstance(request, str) else request.full_url
                seen.append(url)
                if url.endswith("/login"):
                    return FakeResponse(
                        url,
                        200,
                        json.dumps(
                            {
                                "user": {
                                    "user_id": "admin-1",
                                    "email": "admin@example.test",
                                    "role": "admin",
                                },
                                "csrf_token": "request-token",
                            }
                        ).encode(),
                    )
                if url.endswith("/me"):
                    return FakeResponse(
                        url, 200, b'{"user":{"user_id":"admin-1","role":"admin"}}'
                    )
                if url.endswith("/users"):
                    return FakeResponse(url, 200, b"[]")
                return FakeResponse(url, 204)

        cookies = MagicMock()
        cookies.__iter__.return_value = iter(
            [SimpleNamespace(
                name="__Host-forgesec_session", secure=True, path="/",
                domain_specified=False,
                _rest={"HttpOnly": None, "SameSite": "strict"},
            )]
        )
        with (
            patch("smoke_production.CookieJar", return_value=cookies),
            patch("smoke_production.build_opener", return_value=FakeOpener()),
        ):
            self.assertEqual(
                check_login(
                    "https://scan.company.com",
                    "admin@example.test",
                    "test-secret",
                    "admin",
                ),
                [],
            )
        self.assertTrue(any(url.endswith("/users") for url in seen))
        self.assertTrue(seen[-1].endswith("/logout"))

    def test_malformed_operator_response_still_signs_out(self) -> None:
        seen = []

        class FakeOpener:
            def open(self, request, timeout):
                seen.append(request.full_url)
                if request.full_url.endswith("/login"):
                    return FakeResponse(
                        request.full_url,
                        200,
                        b'{"user":null,"csrf_token":"request-token"}',
                    )
                return FakeResponse(request.full_url, 204)

        with patch("smoke_production.build_opener", return_value=FakeOpener()):
            issues = check_login(
                "https://scan.company.com", "admin@example.test", "test-secret"
            )
        self.assertTrue(any("wrong account" in issue for issue in issues))
        self.assertEqual(seen[-1], "https://scan.company.com/api/auth/logout")


if __name__ == "__main__":
    unittest.main()
