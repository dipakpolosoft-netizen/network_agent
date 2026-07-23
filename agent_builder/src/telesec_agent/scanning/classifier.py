"""Evidence-based device classification and non-vulnerability exposure flags."""

from __future__ import annotations

from typing import Any


def classify(
    ports: list[dict[str, Any]], os_matches: list[dict[str, Any]]
) -> tuple[str, float]:
    open_ports = {item["port"] for item in ports if item["state"] == "open"}
    os_name = os_matches[0]["name"].lower() if os_matches else ""
    if open_ports & {515, 631, 9100}:
        return "printer", 0.9
    if 554 in open_ports:
        return "camera", 0.75
    if "router" in os_name or "firewall" in os_name:
        return "network-device", 0.85
    if open_ports & {22, 25, 53, 80, 443, 445, 1433, 3306, 5432}:
        return "server", 0.7
    if "windows" in os_name or "linux" in os_name or "mac os" in os_name:
        return "workstation", 0.6
    return "unknown", 0.25


def exposure_flags(ports: list[dict[str, Any]]) -> list[dict[str, str]]:
    open_ports = {item["port"] for item in ports if item["state"] == "open"}
    rules = (
        (23, "cleartext-telnet", "high", "Telnet service exposed", "TCP 23 is open"),
        (21, "cleartext-ftp", "medium", "FTP service exposed", "TCP 21 is open"),
        (445, "smb-exposed", "medium", "SMB service exposed", "TCP 445 is open"),
        (3389, "rdp-exposed", "medium", "Remote Desktop exposed", "TCP 3389 is open"),
        (5900, "vnc-exposed", "medium", "VNC service exposed", "TCP 5900 is open"),
    )
    flags = [
        {"code": code, "severity": severity, "title": title, "evidence": evidence}
        for port, code, severity, title, evidence in rules
        if port in open_ports
    ]
    database_ports = sorted(open_ports & {1433, 1521, 27017, 3306, 5432, 6379})
    if database_ports:
        flags.append(
            {
                "code": "database-service-exposed",
                "severity": "medium",
                "title": "Database service exposed",
                "evidence": f"Open TCP ports: {', '.join(map(str, database_ports))}",
            }
        )
    return flags
