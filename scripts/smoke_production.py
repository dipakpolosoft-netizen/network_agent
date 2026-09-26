"""Check the public HTTPS routes of a deployed ForgeSec control plane."""

from __future__ import annotations

import argparse
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


def check(base_url: str) -> list[str]:
    try:
        parsed = urlsplit(base_url)
        port = parsed.port
    except ValueError:
        return ["URL must be an HTTPS origin on port 443, without a path."]
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or port not in (None, 443)
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or parsed.username
    ):
        return ["URL must be an HTTPS origin on port 443, without a path."]
    origin = base_url.rstrip("/")
    issues: list[str] = []
    for path, method, expected in (
        ("/health", "GET", 200),
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
            with urlopen(request, timeout=10) as response:
                status = response.status
                body = response.read() if path == "/health" else b""
                final_url = response.url
        except HTTPError as error:
            status = error.code
            body = b""
            final_url = error.url
            error.close()
        except (URLError, TimeoutError, OSError) as error:
            issues.append(f"{path}: HTTPS request failed ({type(error).__name__}).")
            continue
        if urlsplit(final_url).netloc != parsed.netloc or urlsplit(final_url).scheme != "https":
            issues.append(f"{path}: redirected outside the expected HTTPS origin.")
        if status != expected:
            issues.append(f"{path}: expected HTTP {expected}, received {status}.")
        elif path == "/health":
            try:
                health = json.loads(body)
                if health.get("service") != "forgesec-api" or health.get("environment") != "production":
                    issues.append("/health: API identity or production environment mismatch.")
            except (ValueError, AttributeError):
                issues.append("/health: invalid JSON response.")
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="Production HTTPS origin")
    args = parser.parse_args()
    issues = check(args.base_url)
    if issues:
        for issue in issues:
            print(f"- {issue}", file=sys.stderr)
        return 1
    print("HTTPS smoke passed: API health, login page, operator auth, agent auth.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
