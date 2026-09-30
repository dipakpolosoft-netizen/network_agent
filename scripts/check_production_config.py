"""Validate the resolved production Compose configuration without starting services."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]


def parse_url(value: str):
    try:
        parsed = urlsplit(value)
        parsed.port
        return parsed
    except ValueError:
        return urlsplit("")


def validate(config: dict) -> list[str]:
    issues: list[str] = []
    project = config.get("name", "")
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{2,63}", project) or project == "forgesec":
        issues.append("FORGESEC_COMPOSE_PROJECT must be a unique non-default customer slug.")
    services = config.get("services", {})
    try:
        api = services["api"]
        web = services["web"]
        postgres = services["postgres"]
        caddy = services["caddy"]
    except KeyError as exc:
        return [f"Missing production service: {exc.args[0]}"]

    api_env = api.get("environment", {})
    db_env = postgres.get("environment", {})
    web_args = web.get("build", {}).get("args", {})
    host = caddy.get("environment", {}).get("FORGESEC_PUBLIC_HOST", "")
    origin = api_env.get("FORGESEC_WEB_ORIGIN", "")
    agent_url = web_args.get("NEXT_PUBLIC_FORGESEC_AGENT_SERVER_URL", "")
    parsed_origin = parse_url(origin)
    parsed_agent = parse_url(agent_url)

    try:
        ipaddress.ip_address(host)
        is_ip_address = True
    except ValueError:
        is_ip_address = False
    if (
        not host
        or len(host) > 253
        or is_ip_address
        or not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+",
            host,
        )
        or host.endswith(
            (
                ".example", ".example.com", ".invalid", ".test", ".local",
                ".localhost", ".your-real-domain.com",
            )
        )
    ):
        issues.append("FORGESEC_PUBLIC_HOST must be a real DNS hostname.")
    for label, value, parsed in (
        ("FORGESEC_WEB_ORIGIN", origin, parsed_origin),
        ("NEXT_PUBLIC_FORGESEC_AGENT_SERVER_URL", agent_url, parsed_agent),
    ):
        if (
            parsed.scheme != "https"
            or parsed.hostname != host
            or parsed.port not in (None, 443)
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or parsed.username
        ):
            issues.append(f"{label} must be https://{host} with no path or alternate port.")
    if origin.rstrip("/") != agent_url.rstrip("/"):
        issues.append("Browser and probe URLs must use the same HTTPS origin.")

    if api_env.get("FORGESEC_ENV") != "production":
        issues.append("API must run with FORGESEC_ENV=production.")
    customer_id = api_env.get("FORGESEC_CUSTOMER_ID", "")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,63}", customer_id):
        issues.append("FORGESEC_CUSTOMER_ID must be a unique 3-64 character lowercase slug.")
    if api_env.get("FORGESEC_AUTH_REQUIRED") != "true":
        issues.append("Operator authentication must be enabled.")
    if api_env.get("FORGESEC_ALLOW_PUBLIC_SCOPES") != "false":
        issues.append("Public discovery scopes must remain disabled.")
    if api_env.get("FORGESEC_ADOPT_LEGACY_CUSTOMER_DATA", "false") != "false":
        issues.append("Legacy customer-data adoption must be disabled for normal production startup.")
    if web_args.get("FORGESEC_API_PROXY_URL") != "http://api:8000":
        issues.append("Browser /api proxy must target the internal API service.")

    db_url = parse_url(api_env.get("FORGESEC_DATABASE_URL", ""))
    password = db_env.get("POSTGRES_PASSWORD") or ""
    if (
        db_url.scheme != "postgresql"
        or db_url.hostname != "postgres"
        or db_url.port != 5432
        or db_url.path != "/forgesec"
        or db_url.username != "forgesec"
        or not password
        or len(password) < 16
        or any(word in password.lower() for word in ("changeme", "password", "placeholder"))
        or unquote(db_url.password or "") != password
    ):
        issues.append(
            "FORGESEC_DATABASE_URL must use postgres:5432/forgesec with the "
            "URL-encoded FORGESEC_POSTGRES_PASSWORD (16+ characters, not a placeholder)."
        )

    for name, service in (("postgres", postgres), ("api", api), ("web", web)):
        for port in service.get("ports", []):
            if name == "postgres" or port.get("host_ip") != "127.0.0.1":
                issues.append(f"{name} must not publish a non-loopback port.")
                break
    published = {str(port.get("published")) for port in caddy.get("ports", [])}
    if published != {"80", "443"}:
        issues.append("HTTPS ingress must publish ports 80 and 443.")
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, default=ROOT / ".env")
    args = parser.parse_args()
    if not args.env_file.is_file():
        print(f"Missing environment file: {args.env_file}", file=sys.stderr)
        return 2
    command = [
        "docker", "compose", "--env-file", str(args.env_file),
        "-f", "docker-compose.yml", "-f", "docker-compose.production.yml",
        "config", "--format", "json",
    ]
    try:
        result = subprocess.run(
            command, cwd=ROOT, capture_output=True, text=True, check=False
        )
    except FileNotFoundError:
        print("Docker Compose is not installed.", file=sys.stderr)
        return 2
    if result.returncode:
        required = (
            "FORGESEC_PUBLIC_HOST",
            "FORGESEC_POSTGRES_PASSWORD",
            "FORGESEC_DATABASE_URL",
            "FORGESEC_CUSTOMER_ID",
        )
        named = [name for name in required if name in result.stderr]
        print(
            "Docker Compose could not resolve production settings. "
            + (
                "Check: " + ", ".join(named) + "."
                if named else "Check .env and the Compose files."
            ),
            file=sys.stderr,
        )
        return 2
    issues = validate(json.loads(result.stdout))
    if issues:
        for issue in issues:
            print(f"- {issue}", file=sys.stderr)
        return 1
    print("Production Compose preflight passed. No containers were started.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
