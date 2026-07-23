"""Parse Nmap XML without depending on human-readable output."""

from __future__ import annotations

import hashlib
import ipaddress
import xml.etree.ElementTree as ET
from typing import Any


class NmapParseError(RuntimeError):
    pass


def stable_device_id(ip: str, mac: str | None) -> str:
    identity = f"mac:{mac.lower()}" if mac else f"ip:{ip}"
    return hashlib.sha256(identity.encode("ascii")).hexdigest()[:32]


def parse_discovery_xml(
    xml_output: str,
    *,
    local_ip: str,
    observed_at: str,
) -> list[dict[str, Any]]:
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        raise NmapParseError("Nmap returned malformed XML") from exc
    devices: list[dict[str, Any]] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = None
        mac = None
        vendor = None
        for address in host.findall("address"):
            address_type = address.get("addrtype")
            if address_type == "ipv4":
                ip = address.get("addr")
            elif address_type == "mac":
                mac = address.get("addr")
                vendor = address.get("vendor")
        if not ip:
            continue
        try:
            ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            continue
        hostname_node = host.find("./hostnames/hostname")
        hostname = hostname_node.get("name") if hostname_node is not None else None
        times = host.find("times")
        latency_ms = None
        if times is not None and times.get("srtt", "").isdigit():
            latency_ms = int(times.get("srtt", "0")) / 1000
        devices.append(
            {
                "device_id": stable_device_id(ip, mac),
                "ip": ip,
                "hostname": hostname,
                "mac": mac,
                "vendor": vendor,
                "status": "up",
                "discovery_reason": status.get("reason") or "response",
                "latency_ms": latency_ms,
                "is_agent": ip == local_ip,
                "first_seen": observed_at,
                "last_seen": observed_at,
            }
        )
    devices.sort(key=lambda device: int(ipaddress.ip_address(device["ip"])))
    return devices


def parse_host_scan_xml(xml_output: str) -> dict[str, Any]:
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        raise NmapParseError("Nmap returned malformed XML") from exc
    host = root.find("host")
    if host is None:
        return {"hostname": None, "ports": [], "os_matches": []}
    hostname_node = host.find("./hostnames/hostname")
    hostname = hostname_node.get("name") if hostname_node is not None else None
    ports: list[dict[str, Any]] = []
    for port_node in host.findall("./ports/port"):
        state_node = port_node.find("state")
        if state_node is None:
            continue
        state = state_node.get("state")
        if state not in {"open", "open|filtered", "filtered"}:
            continue
        service_node = port_node.find("service")
        cpe_node = service_node.find("cpe") if service_node is not None else None
        ports.append(
            {
                "protocol": port_node.get("protocol", "tcp"),
                "port": int(port_node.get("portid", "0")),
                "state": state,
                "service": service_node.get("name")
                if service_node is not None
                else None,
                "product": service_node.get("product")
                if service_node is not None
                else None,
                "version": service_node.get("version")
                if service_node is not None
                else None,
                "cpe": cpe_node.text if cpe_node is not None else None,
            }
        )
    ports.sort(key=lambda item: (item["protocol"], item["port"]))
    os_matches = [
        {
            "name": node.get("name", "Unknown"),
            "accuracy": int(node.get("accuracy", "0")),
        }
        for node in host.findall("./os/osmatch")
    ]
    os_matches.sort(key=lambda item: item["accuracy"], reverse=True)
    return {"hostname": hostname, "ports": ports, "os_matches": os_matches[:32]}
