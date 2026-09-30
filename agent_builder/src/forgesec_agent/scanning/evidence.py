"""Compare a saved host result with the probe's exact Nmap XML bytes."""

from __future__ import annotations

import hashlib
import ipaddress
from typing import Any

from forgesec_agent.scanning.classifier import classify, exposure_flags
from forgesec_agent.scanning.parser import NmapParseError, parse_host_scan_xml


def verify_host_evidence(
    raw_xml: bytes, scan: dict[str, Any], device_id: str
) -> list[str]:
    issues: list[str] = []
    selected_targets = scan.get("targets")
    saved_results = scan.get("results")
    if not isinstance(selected_targets, list) or not isinstance(saved_results, list):
        return ["Scan targets and results must be lists"]
    targets = [
        item for item in selected_targets
        if isinstance(item, dict) and item.get("device_id") == device_id
    ]
    results = [
        item for item in saved_results
        if isinstance(item, dict) and item.get("device_id") == device_id
    ]
    if len(targets) != 1 or len(results) != 1:
        return ["Exactly one selected target and saved result are required"]
    target, result = targets[0], results[0]
    target_ip = target.get("ip")
    try:
        ipaddress.IPv4Address(target_ip)
    except (ipaddress.AddressValueError, TypeError):
        return ["Selected target needs a valid IPv4 address"]
    if not scan.get("scan_id") or not scan.get("agent_id"):
        issues.append("Scan identity is missing")
    if (
        result.get("scan_id") != scan.get("scan_id")
        or result.get("agent_id") != scan.get("agent_id")
    ):
        issues.append("Saved host identity differs from scan identity")
    if result.get("status") != "completed":
        issues.append("Saved host result is not completed")
    if result.get("ip") != target_ip:
        issues.append("Saved result IP differs from selected target")
    if result.get("raw_xml_sha256") != hashlib.sha256(raw_xml).hexdigest():
        issues.append("Raw XML SHA-256 differs from saved result or is missing")
    try:
        parsed = parse_host_scan_xml(
            raw_xml.decode("utf-8"), expected_ip=target_ip
        )
    except (UnicodeDecodeError, NmapParseError) as exc:
        return [*issues, f"Raw XML cannot be matched to target: {exc}"]

    hostname = parsed["hostname"] or target.get("hostname") or target.get("snmp_name")
    hostname_source = (
        "nmap" if parsed["hostname"] else
        "discovery" if target.get("hostname") else
        "snmp" if target.get("snmp_name") else None
    )
    if (
        result.get("hostname") != hostname
        or result.get("hostname_source") != hostname_source
    ):
        issues.append("Hostname or its evidence source differs from XML/selection")

    parsed_ports = parsed["ports"]
    saved_ports = result.get("ports") or []
    if len(saved_ports) != len(parsed_ports):
        issues.append("Saved port count differs from raw XML")
    else:
        for expected, saved in zip(parsed_ports, saved_ports, strict=True):
            if (
                not isinstance(saved, dict)
                or any(saved.get(key) != value for key, value in expected.items())
                or saved.get("evidence_source") != "nmap"
                or saved.get("recorded_at") != result.get("completed_at")
            ):
                issues.append(
                    f"Saved port evidence differs from XML at "
                    f"{expected['port']}/{expected['protocol']}"
                )
    if result.get("os_matches") != parsed["os_matches"]:
        issues.append("Saved OS estimates differ from raw XML")
    if result.get("exposure_flags") != exposure_flags(parsed_ports):
        issues.append("Saved exposure observations differ from raw port states")

    if len(selected_targets) == len(saved_results) == 1:
        expected_counts = {
            "scanned_hosts": 1,
            "open_ports": sum(port["state"] == "open" for port in parsed_ports),
            "open_filtered_ports": sum(
                port["state"] == "open|filtered" for port in parsed_ports
            ),
            "filtered_ports": sum(
                port["state"] == "filtered" for port in parsed_ports
            ),
            "tcp_ports": sum(
                port["state"] == "open" and port["protocol"] == "tcp"
                for port in parsed_ports
            ),
            "udp_ports": sum(
                port["state"] == "open" and port["protocol"] == "udp"
                for port in parsed_ports
            ),
        }
        summary = scan.get("summary")
        if not isinstance(summary, dict):
            issues.append("Scan summary is missing from the export")
        else:
            for key, expected in expected_counts.items():
                if summary.get(key) != expected:
                    issues.append(f"Scan summary {key} differs from raw XML")

    role, confidence = classify(parsed_ports, parsed["os_matches"], target)
    prior_type = target.get("device_type")
    prior_confidence = target.get("classification_confidence") or 0.0
    if prior_type not in {None, "unknown"} and prior_confidence >= confidence:
        role, confidence = prior_type, prior_confidence
    if (
        result.get("device_type") != role
        or result.get("classification_confidence") != confidence
    ):
        issues.append("Saved role estimate differs from the parsed evidence")
    return issues
