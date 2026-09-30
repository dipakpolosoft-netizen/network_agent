"""Parse Nmap XML without depending on human-readable output."""

from __future__ import annotations

import hashlib
import ipaddress
import xml.etree.ElementTree as ET
from typing import Any


class NmapParseError(RuntimeError):
    pass


def _optional_attr(node: ET.Element | None, name: str) -> str | None:
    if node is None:
        return None
    return (node.get(name) or "").strip() or None


def _bounded_attr(node: ET.Element | None, name: str, limit: int) -> str | None:
    value = _optional_attr(node, name)
    return value[:limit] if value else None


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
                mac = _optional_attr(address, "addr")
                vendor = _bounded_attr(address, "vendor", 255)
        if not ip:
            continue
        try:
            ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            continue
        hostname_node = host.find("./hostnames/hostname")
        hostname = _bounded_attr(hostname_node, "name", 255)
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
                "discovery_reason": _bounded_attr(status, "reason", 128) or "response",
                "latency_ms": latency_ms,
                "is_agent": ip == local_ip,
                "first_seen": observed_at,
                "last_seen": observed_at,
            }
        )
    devices.sort(key=lambda device: int(ipaddress.ip_address(device["ip"])))
    return devices


def parse_host_scan_xml(
    xml_output: str, *, expected_ip: str | None = None
) -> dict[str, Any]:
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        raise NmapParseError("Nmap returned malformed XML") from exc
    hosts = root.findall("host")
    if expected_ip is not None:
        if len(hosts) != 1:
            raise NmapParseError("Nmap host result must contain exactly one target")
        addresses = {
            address.get("addr")
            for address in hosts[0].findall("address")
            if address.get("addrtype") == "ipv4"
        }
        if addresses != {expected_ip}:
            raise NmapParseError("Nmap host address differs from selected target")
        status = hosts[0].find("status")
        if status is None or status.get("state") != "up":
            raise NmapParseError("Nmap did not report the selected host as up")
    host = hosts[0] if hosts else None
    if host is None:
        return {"hostname": None, "ports": [], "os_matches": []}
    hostname_node = host.find("./hostnames/hostname")
    hostname = _optional_attr(hostname_node, "name")
    ports: list[dict[str, Any]] = []
    seen_ports: set[tuple[str, int]] = set()
    for port_node in host.findall("./ports/port"):
        protocol = port_node.get("protocol")
        port_id = port_node.get("portid", "")
        if protocol not in {"tcp", "udp"} or not port_id.isdigit():
            continue
        port_number = int(port_id)
        if not 1 <= port_number <= 65535:
            continue
        state_node = port_node.find("state")
        if state_node is None:
            continue
        state = _optional_attr(state_node, "state")
        if state not in {"open", "open|filtered", "filtered"}:
            continue
        key = (protocol, port_number)
        if key in seen_ports:
            raise NmapParseError(f"Nmap returned duplicate {port_number}/{protocol}")
        seen_ports.add(key)
        service_node = port_node.find("service")
        cpes = [
            node.text.strip()
            for node in service_node.findall("cpe")
            if service_node is not None and node.text and node.text.strip()
        ] if service_node is not None else []
        ports.append(
            {
                "protocol": protocol,
                "port": port_number,
                "state": state,
                "reason": _optional_attr(state_node, "reason"),
                "service": _optional_attr(service_node, "name"),
                "product": _optional_attr(service_node, "product"),
                "version": _optional_attr(service_node, "version"),
                "extrainfo": _optional_attr(service_node, "extrainfo"),
                "ostype": _optional_attr(service_node, "ostype"),
                "devicetype": _optional_attr(service_node, "devicetype"),
                "method": _optional_attr(service_node, "method"),
                "confidence": int(service_node.get("conf", "0"))
                if service_node is not None
                and service_node.get("conf", "").isdigit()
                else None,
                "cpe": cpes[0] if cpes else None,
                "cpes": cpes,
            }
        )
    ports.sort(key=lambda item: (item["protocol"], item["port"]))
    os_matches = [
        {"name": name, "accuracy": int(accuracy)}
        for node in host.findall("./os/osmatch")
        if (name := _optional_attr(node, "name"))
        and (accuracy := _optional_attr(node, "accuracy"))
        and accuracy.isdigit()
        and int(accuracy) <= 100
    ]
    os_matches.sort(key=lambda item: item["accuracy"], reverse=True)
    return {"hostname": hostname, "ports": ports, "os_matches": os_matches[:32]}
