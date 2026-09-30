"""Evidence-based device classification and non-vulnerability exposure flags."""

from __future__ import annotations

from typing import Any


def classify(
    ports: list[dict[str, Any]],
    os_matches: list[dict[str, Any]],
    identity: dict[str, Any] | None = None,
) -> tuple[str, float]:
    open_ports = {
        (item.get("protocol", "tcp"), item["port"])
        for item in ports
        if item.get("state") == "open"
    }
    strong_evidence = _evidence_text(ports, os_matches, identity)
    name_evidence = (
        " ".join(
            str(identity.get(key) or "") for key in ("hostname", "snmp_name")
        ).lower()
        if identity
        else ""
    )

    roles = (
        (
            "firewall",
            (
                "fortigate",
                "palo alto",
                "pan-os",
                "checkpoint",
                "check point",
                "sonicwall",
                "watchguard",
                "sophos firewall",
                "pfsense",
                "opnsense",
                "firepower",
                "firewall appliance",
                "next-generation firewall",
                "vpn gateway",
            ),
        ),
        (
            "switch",
            (
                "catalyst",
                "procurve",
                "arubaos-switch",
                "ethernet switch",
                "managed switch",
                "switch",
            ),
        ),
        (
            "access-point",
            (
                "unifi ap",
                "uap-",
                "access point",
                "wireless ap",
                "wlan",
                "aironet",
                "ruckus",
                "meraki mr",
            ),
        ),
        (
            "router",
            (
                "routeros",
                "mikrotik",
                "edgeos",
                "openwrt",
                "ios-xe",
                "ios xr",
                "router",
            ),
        ),
        (
            "voip-phone",
            (
                "voip",
                "sip phone",
                "ip phone",
                "polycom",
                "yealink",
                "grandstream",
            ),
        ),
        (
            "printer",
            (
                "printer",
                "laserjet",
                "brother",
                "canon",
                "epson",
                "xerox",
                "jetdirect",
            ),
        ),
        ("camera", ("webcam", "hikvision", "dahua", "ip camera", "nvr", "dvr")),
        ("nas", ("synology", "qnap", "truenas", "freenas", "network attached storage")),
    )
    for role, markers in roles:
        if _contains(strong_evidence, *markers):
            return role, 0.9
    for role, markers in roles:
        if _contains(name_evidence, *markers):
            return role, 0.65
    if "firewall" in name_evidence:
        return "firewall", 0.65

    system_description = str((identity or {}).get("snmp_description") or "").lower()
    best_os = (
        str(os_matches[0].get("name") or "").lower()
        if os_matches and os_matches[0].get("accuracy", 0) >= 85
        else ""
    )
    if _contains(
        system_description,
        "poweredge",
        "proliant",
        "windows server",
        "linux server",
    ) or _contains(best_os, "windows server"):
        return "server", 0.8
    if _contains(
        system_description,
        "workstation",
        "desktop pc",
        "windows 11",
        "windows 10",
        "macbook",
    ) or _contains(best_os, "windows 11", "windows 10", "mac os"):
        return "workstation", 0.75

    tcp_ports = {port for protocol, port in open_ports if protocol == "tcp"}
    if tcp_ports & {88, 389, 636, 3268, 3269} and 445 in tcp_ports:
        return "domain-controller", 0.82

    if tcp_ports & {1433, 1521, 27017, 3306, 5432, 6379}:
        return "database-server", 0.78
    if 9100 in tcp_ports:
        return "printer", 0.7
    return "unknown", 0.0


def classify_discovered_device(device: dict[str, Any]) -> tuple[str, float]:
    return classify([], [], device)


def exposure_flags(ports: list[dict[str, Any]]) -> list[dict[str, str]]:
    open_ports = {
        item["port"]
        for item in ports
        if item["state"] == "open" and item.get("protocol", "tcp") == "tcp"
    }
    open_udp_ports = {
        item["port"]
        for item in ports
        if item["state"] == "open" and item.get("protocol") == "udp"
    }
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
    udp_rules = (
        (69, "tftp-exposed", "high", "TFTP service exposed", "UDP 69 is open"),
        (161, "snmp-exposed", "medium", "SNMP service exposed", "UDP 161 is open"),
        (1900, "ssdp-exposed", "low", "SSDP service exposed", "UDP 1900 is open"),
    )
    flags.extend(
        {"code": code, "severity": severity, "title": title, "evidence": evidence}
        for port, code, severity, title, evidence in udp_rules
        if port in open_udp_ports
    )
    vpn_ports = sorted(open_udp_ports & {500, 4500})
    if vpn_ports:
        flags.append(
            {
                "code": "vpn-ike-service",
                "severity": "info",
                "title": "IKE/IPsec service detected",
                "evidence": f"Open UDP ports: {', '.join(map(str, vpn_ports))}",
            }
        )
    return flags


def _evidence_text(
    ports: list[dict[str, Any]],
    os_matches: list[dict[str, Any]],
    identity: dict[str, Any] | None,
) -> str:
    values: list[str] = []
    port_keys = (
        "product",
        "ostype",
        "devicetype",
        "cpe",
    )
    for item in ports:
        if item.get("state") != "open":
            continue
        values.extend(str(item.get(key) or "") for key in port_keys)
        values.extend(str(cpe or "") for cpe in item.get("cpes") or [])
    for item in os_matches:
        if item.get("accuracy", 0) >= 85:
            values.append(str(item.get("name") or ""))
    if identity:
        values.append(str(identity.get("snmp_description") or ""))
    return " ".join(value for value in values if value).lower()


def _contains(text: str, *needles: str) -> bool:
    return any(needle in text for needle in needles)
