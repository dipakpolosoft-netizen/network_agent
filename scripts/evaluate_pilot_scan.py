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
        for error in validate_plan(plan, mode="accuracy"):
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

    summary = scan.get("summary")
    if not isinstance(summary, dict):
        fail("Scan summary is missing; use a report from the updated API")
    else:
        port_counts = {
            "open_ports": 0,
            "open_filtered_ports": 0,
            "filtered_ports": 0,
            "tcp_ports": 0,
            "udp_ports": 0,
        }
        for result in results:
            for port in result.get("ports") or []:
                if not isinstance(port, dict):
                    continue
                state = port.get("state")
                if state == "open":
                    port_counts["open_ports"] += 1
                    if port.get("protocol") == "tcp":
                        port_counts["tcp_ports"] += 1
                    elif port.get("protocol") == "udp":
                        port_counts["udp_ports"] += 1
                elif state == "open|filtered":
                    port_counts["open_filtered_ports"] += 1
                elif state == "filtered":
                    port_counts["filtered_ports"] += 1
        for key, expected_count in port_counts.items():
            if summary.get(key) != expected_count:
                fail(f"Scan summary {key} does not match saved port states")

    if plan is None:
        return findings

    scope = plan["approval"]["discovery_cidr"]
    if discovery.get("authorization_confirmed") is not True:
        fail("Discovery does not record operator authorization")
    if not ipaddress.ip_network(scope).is_private and discovery.get("public_scope_authorized") is not True:
        fail("Discovery does not record public-range authorization")
    if discovery.get("mode") != "selected" or discovery.get("network") != scope:
        fail("Discovery is not the single approved pilot segment")
    if discovery.get("requested_scopes") != [scope] or discovery.get("completed_scopes") != [scope]:
        fail("Requested/completed discovery scopes do not match the pilot segment")
    if discovery.get("failed_scopes"):
        fail("Discovery reports failed scopes")
    if discovery.get("total_scopes") not in (None, 1):
        fail("Discovery attempted more than one scope")
    if discovery.get("site_id") and scan.get("site_id") and discovery["site_id"] != scan["site_id"]:
        fail("Discovery and scan site IDs differ")
    if scan.get("profile") not in plan["approval"]["profiles"]:
        fail("Scan profile is not in the pilot approval")
    expected_top_ports = {"inventory": 200, "standard": 1000}.get(scan.get("profile"))
    profile_plan = scan.get("profile_plan")
    if not isinstance(profile_plan, dict) or (
        profile_plan.get("tcp_top_ports") != expected_top_ports
        or profile_plan.get("tcp_all_ports") is not False
        or profile_plan.get("udp_ports") != []
        or profile_plan.get("open_only_output") is not True
    ):
        fail("Saved scan port plan does not match the first-pilot profile")
    if len(targets) != 1:
        fail("First pilot scan must select exactly one known target")

    expected = {item["ipv4"]: item for item in plan["known_devices"]}
    known_targets = discovery.get("known_targets") or []
    if len(known_targets) != len(expected) or set(known_targets) != set(expected):
        fail("Known-host checks do not cover the pilot baseline IPs")
    checks = discovery.get("follow_up_checks") or []
    checks_by_ip = {item.get("ip"): item for item in checks if isinstance(item, dict)}
    if len(checks_by_ip) != len(checks):
        fail("Known-host checks contain duplicate or invalid entries")
    if set(checks_by_ip) != set(expected):
        fail("Saved known-host results do not match the pilot baseline IPs")
    for ip in expected:
        check = checks_by_ip.get(ip)
        if not check:
            fail(f"Known host {ip} has no saved check result")
        elif check.get("status") == "responsive":
            review(f"Initial discovery missed {ip}; targeted check recovered it")
        elif check.get("status") == "error":
            fail(f"Known-host check failed for {ip}")
        elif check.get("status") == "no_response":
            review(f"Known host {ip} gave no response; this is not proof it is offline")
        elif check.get("status") != "already_discovered":
            fail(f"Known host {ip} has an unrecognized check status")
    if len(targets) == 1:
        target_baseline = expected.get(targets[0].get("ip"))
        if target_baseline and not target_baseline["expected_tcp_ports"]:
            fail("Selected pilot target needs a known expected open TCP port")
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
        if any(port.get("protocol") == "udp" for port in result.get("ports", []) if isinstance(port, dict)):
            fail(f"First-pilot {scan.get('profile')} scan unexpectedly includes UDP evidence on {ip}")
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
    if discovery.get("known_targets"):
        checks = discovery.get("follow_up_checks") or []
        outcomes = ", ".join(
            f"{item.get('ip')}: {item.get('status')}"
            for item in checks if isinstance(item, dict)
        )
        print(f"Known-host checks: {outcomes or 'none reported'}")
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
