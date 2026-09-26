"""Validate a Step 14 pilot baseline without contacting the network."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit

ALLOWED_PROFILES = {"inventory", "standard"}


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _network(value: object, label: str, errors: list[str]):
    try:
        network = ipaddress.ip_network(_text(value), strict=True)
    except ValueError:
        errors.append(f"{label} must be a canonical IPv4 CIDR")
        return None
    if network.version != 4 or network.is_loopback or network.is_link_local or network.is_multicast:
        errors.append(f"{label} must be a usable IPv4 network")
        return None
    return network


def _address(value: object, label: str, errors: list[str]):
    try:
        address = ipaddress.ip_address(_text(value))
    except ValueError:
        errors.append(f"{label} must be an IPv4 address")
        return None
    if address.version != 4:
        errors.append(f"{label} must be an IPv4 address")
        return None
    return address


def _url(value: object, label: str, *, remote: bool, errors: list[str]) -> None:
    raw = _text(value)
    try:
        parsed = urlsplit(raw)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        errors.append(f"{label} is not a valid URL")
        return
    if not host or port == 0 or parsed.username or parsed.password or parsed.query or parsed.fragment:
        errors.append(f"{label} must be an absolute base URL without credentials or query")
        return
    if parsed.path not in ("", "/"):
        errors.append(f"{label} must be a base URL without a path")
    loopback = host.lower() == "localhost"
    try:
        loopback = loopback or ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    if remote and loopback:
        errors.append(f"{label} cannot use localhost for a separate pilot machine")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback and not remote):
        errors.append(f"{label} must use HTTPS unless it is same-machine loopback")


def validate(plan: object, *, today: date | None = None) -> list[str]:
    """Return all preparation errors; no network or filesystem writes occur."""
    if not isinstance(plan, dict):
        return ["Plan must be a JSON object"]
    errors: list[str] = []
    site = plan.get("site") if isinstance(plan.get("site"), dict) else {}
    approval = plan.get("approval") if isinstance(plan.get("approval"), dict) else {}
    probe = plan.get("probe") if isinstance(plan.get("probe"), dict) else {}
    server = plan.get("server") if isinstance(plan.get("server"), dict) else {}

    for label, value in (
        ("site.name", site.get("name")),
        ("site.owner", site.get("owner")),
        ("approval.reference", approval.get("reference")),
        ("approval.approved_by", approval.get("approved_by")),
        ("probe.machine_name", probe.get("machine_name")),
    ):
        if not _text(value):
            errors.append(f"{label} is required")
    if approval.get("confirmed") is not True:
        errors.append("approval.confirmed must be true after written authorization")
    try:
        expires = date.fromisoformat(_text(approval.get("expires_on")))
        if expires < (today or date.today()):
            errors.append("approval.expires_on has passed")
    except ValueError:
        errors.append("approval.expires_on must be YYYY-MM-DD")

    approved = _network(approval.get("approved_cidr"), "approval.approved_cidr", errors)
    discovery = _network(approval.get("discovery_cidr"), "approval.discovery_cidr", errors)
    if approved and not approved.is_private and approval.get("public_range_authorized") is not True:
        errors.append("Public/nonprivate approved CIDR needs explicit public_range_authorized")
    if discovery:
        if discovery.num_addresses > 256:
            errors.append("approval.discovery_cidr must contain at most 256 addresses")
        if approved and not discovery.subnet_of(approved):
            errors.append("approval.discovery_cidr must be inside approval.approved_cidr")
    exclusions = approval.get("exclusions")
    if not isinstance(exclusions, list):
        errors.append("approval.exclusions must be a list")
        exclusions = []
    excluded = []
    for index, value in enumerate(exclusions):
        item = _network(value, f"approval.exclusions[{index}]", errors)
        if item:
            if approved and not item.subnet_of(approved):
                errors.append(f"approval.exclusions[{index}] must be inside the approved CIDR")
            excluded.append(item)
    if discovery and any(discovery.overlaps(item) for item in excluded):
        errors.append("An exclusion overlaps the first discovery segment")

    profiles = approval.get("profiles")
    if not isinstance(profiles, list) or not profiles or any(profile not in ALLOWED_PROFILES for profile in profiles):
        errors.append("approval.profiles must contain only inventory and/or standard for the first pilot")

    placement = _text(probe.get("placement"))
    if placement not in {"same_machine", "separate_windows_pc_or_vm"}:
        errors.append("probe.placement must be same_machine or separate_windows_pc_or_vm")
    probe_ip = _address(probe.get("ipv4"), "probe.ipv4", errors)
    if probe_ip and discovery and probe_ip not in discovery:
        errors.append("probe.ipv4 must be inside the first discovery segment")
    if probe_ip and any(probe_ip in item for item in excluded):
        errors.append("probe.ipv4 is excluded from the pilot scope")
    remote = placement == "separate_windows_pc_or_vm"
    _url(server.get("dashboard_url"), "server.dashboard_url", remote=False, errors=errors)
    _url(server.get("agent_api_url"), "server.agent_api_url", remote=remote, errors=errors)

    devices = plan.get("known_devices")
    if not isinstance(devices, list) or not 2 <= len(devices) <= 3:
        errors.append("known_devices must contain 2 or 3 baseline devices")
        devices = []
    seen = set()
    for index, device in enumerate(devices):
        label = f"known_devices[{index}]"
        if not isinstance(device, dict):
            errors.append(f"{label} must be an object")
            continue
        if not _text(device.get("name")) or not _text(device.get("device_type")):
            errors.append(f"{label} needs a name and expected device_type")
        ip = _address(device.get("ipv4"), f"{label}.ipv4", errors)
        if ip:
            if ip in seen or ip == probe_ip:
                errors.append(f"{label}.ipv4 duplicates another baseline IP or the probe")
            seen.add(ip)
            if discovery and ip not in discovery:
                errors.append(f"{label}.ipv4 must be inside the first discovery segment")
            if any(ip in item for item in excluded):
                errors.append(f"{label}.ipv4 is excluded from scanning")
        ports = device.get("expected_tcp_ports")
        if not isinstance(ports, list) or any(type(port) is not int or not 1 <= port <= 65535 for port in ports):
            errors.append(f"{label}.expected_tcp_ports must be a list of TCP ports 1-65535")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path, help="Local pilot-plan JSON file; never include tokens")
    args = parser.parse_args()
    try:
        plan = json.loads(args.plan.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"Cannot read pilot plan: {exc}", file=sys.stderr)
        return 2
    errors = validate(plan)
    if errors:
        for error in errors:
            print(f"NOT READY: {error}")
        return 1
    print("Pilot plan fields are valid. No site, token, or scan was created.")
    print("Confirm approval, package hash, probe-reported segment, and server reachability before Step 15.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
