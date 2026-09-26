"""Compare saved ForgeSec discovery/scan JSON with an approved pilot baseline."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from dataclasses import dataclass
from pathlib import Path

from check_pilot_plan import validate as validate_plan


@dataclass(frozen=True)
class Finding:
    level: str
    message: str


def evaluate(discovery: dict, scan: dict, plan: dict | None = None) -> list[Finding]:
    findings: list[Finding] = []

    def fail(message: str) -> None:
        findings.append(Finding("FAIL", message))

    def review(message: str) -> None:
        findings.append(Finding("REVIEW", message))

    if not isinstance(discovery, dict) or not isinstance(scan, dict):
        return [Finding("FAIL", "Discovery and scan must be JSON objects")]
    if plan is not None:
        for error in validate_plan(plan):
            fail(f"Pilot plan: {error}")
        if not isinstance(plan, dict) or any(item.level == "FAIL" for item in findings):
            return findings

    discovery_id = discovery.get("discovery_id")
    if not discovery_id or scan.get("discovery_id") != discovery_id:
        fail("Scan does not belong to this discovery")
    if not discovery.get("agent_id") or scan.get("agent_id") != discovery.get("agent_id"):
        fail("Discovery and scan agent IDs differ")
    if discovery.get("status") != "completed":
        (fail if plan else review)(f"Discovery status is {discovery.get('status')}, not completed")
    if scan.get("status") != "completed":
        (fail if plan else review)(f"Scan status is {scan.get('status')}, not completed")

    devices = discovery.get("devices")
    targets = scan.get("targets")
    results = scan.get("results")
    if not all(isinstance(value, list) for value in (devices, targets, results)):
        return findings + [Finding("FAIL", "Devices, targets, and results must be arrays")]
    if any(not isinstance(value, dict) for value in devices + targets + results):
        return findings + [Finding("FAIL", "Device, target, and result entries must be objects")]

    try:
        network = ipaddress.ip_network(discovery["network"], strict=True)
    except (KeyError, ValueError, TypeError):
        fail("Discovery network is not a canonical CIDR")
        network = None
    discovered = {}
    discovered_ips = set()
    for device in devices:
        device_id, ip = device.get("device_id"), device.get("ip")
        if not device_id or device_id in discovered:
            fail("Discovery has a missing or duplicate device ID")
        else:
            discovered[device_id] = device
        if ip in discovered_ips:
            review(f"Duplicate discovered IP {ip}; inspect device identity")
        discovered_ips.add(ip)
        try:
            if network and ipaddress.ip_address(ip) not in network:
                fail(f"Discovered IP {ip} is outside {network}")
        except (ValueError, TypeError):
            fail(f"Discovered device has invalid IP {ip}")

    if scan.get("total") != len(targets):
        fail("Scan total does not equal its target count")
    counts = [scan.get(key) for key in ("queued", "running", "completed", "failed", "cancelled")]
    if all(type(value) is int for value in counts):
        if sum(counts) != scan.get("total"):
            fail("Scan progress counters do not add up to its target count")
        if scan.get("status") == "completed" and counts != [0, 0, len(targets), 0, 0]:
            fail("Completed scan still has queued, running, failed, or cancelled targets")
    if len(results) > len(targets):
        fail("Scan has more results than targets")
    target_by_id = {}
    for target in targets:
        device_id, ip = target.get("device_id"), target.get("ip")
        if not device_id or device_id in target_by_id:
            fail("Scan has a missing or duplicate target device ID")
        else:
            target_by_id[device_id] = target
        source = discovered.get(device_id)
        if not source or source.get("ip") != ip or source.get("is_agent"):
            fail(f"Scan target {ip} is not the matching non-probe discovered device")
    result_ids = set()
    for result in results:
        device_id, ip = result.get("device_id"), result.get("ip")
        if not device_id or device_id in result_ids:
            fail("Scan has a missing or duplicate result device ID")
        result_ids.add(device_id)
        target = target_by_id.get(device_id)
        if not target or target.get("ip") != ip:
            fail(f"Scan result {ip} does not match a selected target")
        ports = result.get("ports")
        if not isinstance(ports, list):
            fail(f"Scan result {ip} has no port array")
            continue
        seen_ports = set()
        for port in ports:
            if not isinstance(port, dict):
                fail(f"Scan result {ip} contains an invalid port")
                continue
            key = (port.get("protocol"), port.get("port"))
            if key in seen_ports:
                fail(f"Scan result {ip} duplicates {key[1]}/{key[0]}")
            seen_ports.add(key)

    if scan.get("status") == "completed":
        if result_ids != set(target_by_id):
            fail("Completed scan does not contain one result for every selected target")
        if any(result.get("status") != "completed" for result in results):
            fail("Completed scan contains a non-completed host result")

    if plan is None:
        return findings

    scope = plan["approval"]["discovery_cidr"]
    if discovery.get("mode") != "selected" or discovery.get("network") != scope:
        fail("Discovery is not the single approved pilot segment")
    if discovery.get("requested_scopes") != [scope] or scope not in discovery.get("completed_scopes", []):
        fail("Requested/completed discovery scopes do not match the pilot segment")
    if scan.get("profile") not in plan["approval"]["profiles"]:
        fail("Scan profile is not in the pilot approval")
    if len(targets) != 1:
        fail("First pilot scan must select exactly one known target")

    expected = {item["ipv4"]: item for item in plan["known_devices"]}
    by_ip = {item.get("ip"): item for item in devices}
    for ip, baseline in expected.items():
        observed = by_ip.get(ip)
        if not observed:
            fail(f"Expected device {baseline['name']} ({ip}) was not discovered")
            continue
        if observed.get("is_agent"):
            fail(f"Expected device {ip} was identified as the probe")
        actual_type = observed.get("device_type")
        if actual_type and actual_type.casefold() != baseline["device_type"].casefold():
            review(f"Device {ip} type is {actual_type}, expected {baseline['device_type']}")
        if not observed.get("hostname"):
            review(f"Device {ip} did not report a hostname")

    for result in results:
        ip = result.get("ip")
        if ip not in expected:
            fail(f"Pilot scan targeted unplanned device {ip}")
            continue
        if result.get("status") != "completed":
            fail(f"Selected host {ip} scan status is {result.get('status')}")
            continue
        observed_ports = {
            port.get("port")
            for port in result.get("ports", [])
            if isinstance(port, dict) and port.get("protocol") == "tcp" and port.get("state") == "open"
        }
        for port in expected[ip]["expected_tcp_ports"]:
            if port not in observed_ports:
                fail(f"Expected open TCP port {port} was not observed on {ip}; check profile and firewall")
        if not result.get("ports"):
            review(f"Selected host {ip} has no port evidence")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--discovery", required=True, type=Path)
    parser.add_argument("--scan", required=True, type=Path)
    parser.add_argument("--plan", type=Path, help="Validated Step 14 plan; required for an accuracy verdict")
    args = parser.parse_args()
    try:
        discovery = json.loads(args.discovery.read_text(encoding="utf-8"))
        scan = json.loads(args.scan.read_text(encoding="utf-8"))
        plan = json.loads(args.plan.read_text(encoding="utf-8")) if args.plan else None
    except (OSError, ValueError) as exc:
        print(f"Cannot read evidence: {exc}", file=sys.stderr)
        return 2
    findings = evaluate(discovery, scan, plan)
    print(f"Discovery {discovery.get('status')}: {len(discovery.get('devices', []))} devices")
    print(f"Scan {scan.get('status')}: {len(scan.get('results', []))} results")
    for finding in findings:
        print(f"{finding.level}: {finding.message}")
    if not args.plan:
        print("STRUCTURAL AUDIT ONLY: no authorized baseline; accuracy cannot be established.")
    elif not findings:
        print("BASELINE CHECK PASSED: confirm report/tray UI and source-of-truth devices manually.")
    else:
        print("BASELINE NEEDS REVIEW: resolve every FAIL and REVIEW before accepting Step 16.")
    return 1 if any(item.level == "FAIL" or (args.plan and item.level == "REVIEW") for item in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
