from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from forgesec_agent.scanning.classifier import classify, exposure_flags
from forgesec_agent.scanning.evidence import verify_host_evidence
from forgesec_agent.scanning.parser import parse_host_scan_xml


def saved_evidence() -> tuple[bytes, dict]:
    raw_xml = (
        b'<nmaprun><host><status state="up"/>'
        b'<address addr="192.168.1.10" addrtype="ipv4"/>'
        b'<hostnames><hostname name="server.local"/></hostnames>'
        b'<ports><port protocol="tcp" portid="22">'
        b'<state state="open" reason="syn-ack"/>'
        b'<service name="ssh" product="OpenSSH" version="9.0" '
        b'method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:9.0</cpe>'
        b'</service></port></ports><os><osmatch name="Linux" accuracy="95"/>'
        b'</os></host></nmaprun>'
    )
    parsed = parse_host_scan_xml(raw_xml.decode(), expected_ip="192.168.1.10")
    target = {"device_id": "device-1", "ip": "192.168.1.10"}
    role, confidence = classify(parsed["ports"], parsed["os_matches"], target)
    completed_at = "2026-09-29T10:00:00Z"
    ports = [
        {**port, "evidence_source": "nmap", "recorded_at": completed_at}
        for port in parsed["ports"]
    ]
    scan = {
        "scan_id": "scan-1",
        "agent_id": "probe-1",
        "targets": [target],
        "summary": {
            "scanned_hosts": 1,
            "open_ports": 1,
            "open_filtered_ports": 0,
            "filtered_ports": 0,
            "tcp_ports": 1,
            "udp_ports": 0,
        },
        "results": [{
            "scan_id": "scan-1",
            "agent_id": "probe-1",
            "device_id": "device-1",
            "ip": "192.168.1.10",
            "status": "completed",
            "hostname": parsed["hostname"],
            "hostname_source": "nmap",
            "device_type": role,
            "classification_confidence": confidence,
            "ports": ports,
            "os_matches": parsed["os_matches"],
            "exposure_flags": exposure_flags(parsed["ports"]),
            "completed_at": completed_at,
            "raw_xml_sha256": hashlib.sha256(raw_xml).hexdigest(),
        }],
    }
    return raw_xml, scan


def test_exact_raw_xml_matches_exported_host_result() -> None:
    raw_xml, scan = saved_evidence()
    assert verify_host_evidence(raw_xml, scan, "device-1") == []


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (
            lambda scan: scan["results"][0]["ports"][0].update(version="8.0"),
            "port evidence",
        ),
        (lambda scan: scan["results"][0].update(os_matches=[]), "OS estimates"),
        (
            lambda scan: scan["results"][0].update(hostname_source="discovery"),
            "Hostname",
        ),
        (lambda scan: scan["results"][0].update(raw_xml_sha256=None), "SHA-256"),
        (
            lambda scan: scan["results"][0].update(device_type="firewall"),
            "role estimate",
        ),
    ],
)
def test_changed_evidence_is_reported(change, message: str) -> None:
    raw_xml, scan = saved_evidence()
    changed = deepcopy(scan)
    change(changed)
    assert any(
        message in issue
        for issue in verify_host_evidence(raw_xml, changed, "device-1")
    )


def test_wrong_raw_host_cannot_be_attributed_to_selected_target() -> None:
    raw_xml, scan = saved_evidence()
    wrong_host = raw_xml.replace(b"192.168.1.10", b"192.168.1.11")
    assert any(
        "cannot be matched" in issue
        for issue in verify_host_evidence(wrong_host, scan, "device-1")
    )


def test_single_target_summary_must_match_raw_port_states() -> None:
    raw_xml, scan = saved_evidence()
    changed = deepcopy(scan)
    changed["summary"]["open_ports"] = 0
    assert "Scan summary open_ports differs from raw XML" in verify_host_evidence(
        raw_xml, changed, "device-1"
    )


def test_incomplete_export_reports_an_issue_instead_of_crashing() -> None:
    raw_xml, scan = saved_evidence()
    changed = deepcopy(scan)
    changed["results"] = None
    assert verify_host_evidence(raw_xml, changed, "device-1") == [
        "Scan targets and results must be lists"
    ]


def test_missing_target_ip_cannot_bypass_raw_host_check() -> None:
    raw_xml, scan = saved_evidence()
    changed = deepcopy(scan)
    changed["targets"][0]["ip"] = None
    changed["results"][0]["ip"] = None
    assert verify_host_evidence(raw_xml, changed, "device-1") == [
        "Selected target needs a valid IPv4 address"
    ]


def test_single_target_export_requires_summary() -> None:
    raw_xml, scan = saved_evidence()
    changed = deepcopy(scan)
    del changed["summary"]
    assert "Scan summary is missing from the export" in verify_host_evidence(
        raw_xml, changed, "device-1"
    )


def test_offline_verifier_command_reports_match(tmp_path: Path) -> None:
    raw_xml, scan = saved_evidence()
    scan_path = tmp_path / "scan.json"
    xml_path = tmp_path / "host.xml"
    scan_path.write_text(json.dumps(scan), encoding="utf-8")
    xml_path.write_bytes(raw_xml)
    script = Path(__file__).resolve().parents[1] / "scripts/verify-host-evidence.py"

    completed = subprocess.run(
        [
            sys.executable, str(script), "--scan", str(scan_path),
            "--xml", str(xml_path), "--device-id", "device-1",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert "PASS: Raw Nmap XML matches" in completed.stdout


def test_offline_verifier_command_rejects_wrong_report_totals(
    tmp_path: Path,
) -> None:
    raw_xml, scan = saved_evidence()
    scan["summary"]["tcp_ports"] = 0
    scan_path = tmp_path / "scan.json"
    xml_path = tmp_path / "host.xml"
    scan_path.write_text(json.dumps(scan), encoding="utf-8")
    xml_path.write_bytes(raw_xml)
    script = Path(__file__).resolve().parents[1] / "scripts/verify-host-evidence.py"

    completed = subprocess.run(
        [
            sys.executable, str(script), "--scan", str(scan_path),
            "--xml", str(xml_path), "--device-id", "device-1",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 1
    assert "FAIL: Scan summary tcp_ports differs from raw XML" in completed.stdout
