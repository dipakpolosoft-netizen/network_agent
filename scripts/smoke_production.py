"""Check the public HTTPS routes of a deployed ForgeSec control plane."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from http.cookiejar import CookieJar
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    Request,
    build_opener,
)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def valid_origin(base_url: str) -> bool:
    try:
        parsed = urlsplit(base_url)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and bool(parsed.hostname)
        and port in (None, 443)
        and parsed.path in ("", "/")
        and not parsed.query
        and not parsed.fragment
        and not parsed.username
        and not parsed.password
    )


def check(base_url: str) -> list[str]:
    if not valid_origin(base_url):
        return ["URL must be an HTTPS origin on port 443, without a path."]
    parsed = urlsplit(base_url)
    origin = base_url.rstrip("/")
    opener = build_opener(NoRedirect())
    issues: list[str] = []
    for path, method, expected in (
        ("/health", "GET", 200),
        ("/ready", "GET", 200),
        ("/login", "GET", 200),
        ("/api/auth/me", "GET", 401),
        ("/agent/heartbeat", "POST", 401),
    ):
        request = Request(
            origin + path,
            data=b"{}" if method == "POST" else None,
            headers={"Content-Type": "application/json"} if method == "POST" else {},
            method=method,
        )
        try:
            with opener.open(request, timeout=10) as response:
                status = response.status
                body = response.read() if path in {"/health", "/ready"} else b""
                final_url = response.url
        except HTTPError as error:
            status = error.code
            body = b""
            final_url = error.url
            error.close()
        except (URLError, TimeoutError, OSError) as error:
            issues.append(f"{path}: HTTPS request failed ({type(error).__name__}).")
            continue
        if (
            urlsplit(final_url).netloc != parsed.netloc
            or urlsplit(final_url).scheme != "https"
        ):
            issues.append(f"{path}: redirected outside the expected HTTPS origin.")
        if status != expected:
            issues.append(f"{path}: expected HTTP {expected}, received {status}.")
        elif path == "/health":
            try:
                health = json.loads(body)
                if (
                    health.get("service") != "forgesec-api"
                    or health.get("environment") != "production"
                ):
                    issues.append(
                        "/health: API identity or production environment mismatch."
                    )
            except (ValueError, AttributeError):
                issues.append("/health: invalid JSON response.")
        elif path == "/ready":
            try:
                if json.loads(body).get("status") != "ready":
                    issues.append("/ready: storage is not ready.")
            except (ValueError, AttributeError):
                issues.append("/ready: invalid JSON response.")
    return issues


def check_login(
    base_url: str, email: str, password: str, expected_role: str | None = None
) -> list[str]:
    if not valid_origin(base_url):
        return ["URL must be an HTTPS origin on port 443, without a path."]
    origin = base_url.rstrip("/")
    cookies = CookieJar()
    opener = build_opener(HTTPCookieProcessor(cookies), NoRedirect())
    request = Request(
        origin + "/api/auth/login",
        data=json.dumps({"email": email, "password": password}).encode(),
        headers={"Content-Type": "application/json", "Origin": origin},
        method="POST",
    )
    try:
        with opener.open(request, timeout=10) as response:
            if response.status != 200 or response.url != origin + "/api/auth/login":
                return [
                    "Operator sign-in did not return HTTP 200 on the HTTPS origin."
                ]
            login = json.load(response)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, TypeError):
        return ["Operator HTTPS sign-in check failed."]

    issues: list[str] = []
    token = login.get("csrf_token") if isinstance(login, dict) else None
    try:
        user = login.get("user") if isinstance(login, dict) else None
        if not isinstance(user, dict) or user.get("email", "").lower() != email.lower():
            issues.append("Operator sign-in returned the wrong account.")
        elif expected_role and user.get("role") != expected_role:
            issues.append("Operator sign-in returned the wrong role.")
        if not isinstance(token, str) or not token:
            issues.append("Operator sign-in omitted the request token.")
        session = next(
            (cookie for cookie in cookies if cookie.name == "__Host-forgesec_session"),
            None,
        )
        if (
            session is None
            or not session.secure
            or session.path != "/"
            or session.domain_specified
        ):
            issues.append("Operator sign-in omitted the secure session cookie.")
        else:
            attributes = {name.lower(): value for name, value in session._rest.items()}
            if (
                "httponly" not in attributes
                or str(attributes.get("samesite", "")).lower() != "strict"
            ):
                issues.append("Operator session cookie lacks HttpOnly or SameSite=Strict.")
        if not issues:
            with opener.open(origin + "/api/auth/me", timeout=10) as response:
                me = json.load(response) if response.status == 200 else {}
            me_user = me.get("user") if isinstance(me, dict) else None
            if not isinstance(me_user, dict) or me_user.get("user_id") != user.get(
                "user_id"
            ):
                issues.append(
                    "Authenticated session could not read the signed-in account."
                )
            elif expected_role and me_user.get("role") != expected_role:
                issues.append("Authenticated session returned the wrong role.")
        if not issues and expected_role:
            expected_status = 200 if expected_role == "admin" else 403
            try:
                with opener.open(origin + "/api/auth/users", timeout=10) as response:
                    status = response.status
            except HTTPError as error:
                status = error.code
                error.close()
            if status != expected_status:
                issues.append(
                    "User-management role boundary did not match the expected role."
                )
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, TypeError):
        issues.append("Authenticated session check failed.")
    finally:
        if isinstance(token, str) and token:
            logout = Request(
                origin + "/api/auth/logout",
                data=b"",
                headers={"X-CSRF-Token": token},
                method="POST",
            )
            try:
                with opener.open(logout, timeout=10) as response:
                    if response.status != 204:
                        issues.append(
                            "Operator session could not be revoked after the check."
                        )
            except (HTTPError, URLError, TimeoutError, OSError):
                issues.append("Operator session could not be revoked after the check.")
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="Production HTTPS origin")
    parser.add_argument(
        "--operator-email",
        help="Prompt for a password and verify sign-in, session, and sign-out",
    )
    parser.add_argument("--expected-role", choices=("admin", "operator", "viewer"))
    args = parser.parse_args()
    if args.expected_role and not args.operator_email:
        parser.error("--expected-role requires --operator-email")
    issues = check(args.base_url)
    if not issues and args.operator_email:
        issues.extend(
            check_login(
                args.base_url,
                args.operator_email,
                getpass.getpass("Operator password: "),
                args.expected_role,
            )
        )
    if issues:
        for issue in issues:
            print(f"- {issue}", file=sys.stderr)
        return 1
    print("HTTPS smoke passed: API readiness, login page, operator auth, agent auth.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
