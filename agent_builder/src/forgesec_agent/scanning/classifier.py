"""Evidence-based device classification and non-vulnerability exposure flags."""

from __future__ import annotations

from typing import Any


def classify(
    ports: list[dict[str, Any]],
    os_matches: list[dict[str, Any]],
    identity: dict[str, Any] | None = None,
) -> tuple[str, float]:
    open_ports = {item["port"] for item in ports if item["state"] == "open"}
    service_names = {
        str(item.get("service") or "").lower()
        for item in ports
        if item.get("service")
    }
    os_name = os_matches[0]["name"].lower() if os_matches else ""
    evidence = _evidence_text(ports, os_matches, identity)

    if _contains(
        evidence,
        "fortinet",
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
        "firewall",
        "vpn gateway",
    ) or open_ports & {500, 4500}:
        return "firewall", 0.9

    if _contains(
        evidence,
        "catalyst",
        "procurve",
        "arubaos-switch",
        "ethernet switch",
        "managed switch",
        "switch",
    ):
        return "switch", 0.9

    if _contains(
        evidence,
        "unifi ap",
        "uap-",
        "access point",
        "wireless ap",
        "wlan",
        "aironet",
        "ruckus",
        "meraki mr",
    ):
        return "access-point", 0.88

    if _contains(
        evidence,
        "routeros",
        "mikrotik",
        "edgeos",
        "openwrt",
        "ios-xe",
        "ios xr",
        "router",
        "gateway",
    ) or "router" in os_name:
        return "router", 0.88

    if _contains(
        evidence,
        "voip",
        "sip phone",
        "ip phone",
        "polycom",
        "yealink",
        "grandstream",
    ) or 5060 in open_ports:
        return "voip-phone", 0.78

    if open_ports & {515, 631, 9100}:
        return "printer", 0.9
    if _contains(
        evidence,
        "printer",
        "laserjet",
        "brother",
        "canon",
        "epson",
        "xerox",
        "jetdirect",
    ):
        return "printer", 0.88

    if 554 in open_ports or "rtsp" in service_names or "webcam" in evidence:
        return "camera", 0.82
    if _contains(evidence, "hikvision", "dahua", "axis", "ip camera", "nvr", "dvr"):
        return "camera", 0.86

    if open_ports & {111, 548, 873, 2049, 5000, 5001} or _contains(
        evidence, "synology", "qnap", "truenas", "freenas", "nas", "storage"
    ):
        return "nas", 0.82

    if open_ports & {88, 389, 636, 3268, 3269} and 445 in open_ports:
        return "domain-controller", 0.82

    database_ports = open_ports & {1433, 1521, 27017, 3306, 5432, 6379}
    if database_ports:
        return "database-server", 0.78

    if 161 in open_ports or _contains(evidence, "snmp", "enterprise oid"):
        return "network-device", 0.7

    if open_ports & {22, 25, 53, 80, 443, 445, 8080, 8443}:
        return "server", 0.7
    if "windows" in os_name or "linux" in os_name or "mac os" in os_name:
        return "workstation", 0.6
    return "unknown", 0.25


def classify_discovered_device(device: dict[str, Any]) -> tuple[str, float]:
    return classify([], [], device)


def exposure_flags(ports: list[dict[str, Any]]) -> list[dict[str, str]]:
    open_ports = {item["port"] for item in ports if item["state"] == "open"}
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
        "service",
        "product",
        "version",
        "extrainfo",
        "ostype",
        "devicetype",
        "method",
        "cpe",
    )
    for item in ports:
        values.extend(str(item.get(key) or "") for key in port_keys)
        values.extend(str(cpe or "") for cpe in item.get("cpes") or [])
    for item in os_matches:
        values.append(str(item.get("name") or ""))
    if identity:
        values.extend(
            str(identity.get(key) or "")
            for key in (
                "hostname",
                "vendor",
                "snmp_name",
                "snmp_description",
                "snmp_object_id",
                "device_type",
            )
        )
    return " ".join(value for value in values if value).lower()


def _contains(text: str, *needles: str) -> bool:
    return any(needle in text for needle in needles)
