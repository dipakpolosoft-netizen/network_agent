"""Best-effort identity enrichment for discovered network devices."""

from __future__ import annotations

import os
import random
import socket
import subprocess
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any

from forgesec_agent.scanning.classifier import classify_discovered_device

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_UP_TIME = "1.3.6.1.2.1.1.3.0"
SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
IF_NUMBER = "1.3.6.1.2.1.2.1.0"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"
IF_ALIAS = "1.3.6.1.2.1.31.1.1.1.18"
LLDP_LOC_CHASSIS_SUBTYPE = "1.0.8802.1.1.2.1.3.1.0"
LLDP_LOC_CHASSIS_ID = "1.0.8802.1.1.2.1.3.2.0"
LLDP_LOC_PORT_ID = "1.0.8802.1.1.2.1.3.7.1.3"
LLDP_REM_CHASSIS_SUBTYPE = "1.0.8802.1.1.2.1.4.1.1.4"
LLDP_REM_CHASSIS_ID = "1.0.8802.1.1.2.1.4.1.1.5"
LLDP_REM_PORT_SUBTYPE = "1.0.8802.1.1.2.1.4.1.1.6"
LLDP_REM_PORT_ID = "1.0.8802.1.1.2.1.4.1.1.7"
LLDP_REM_SYS_NAME = "1.0.8802.1.1.2.1.4.1.1.9"


@dataclass(frozen=True, slots=True)
class LldpNeighbor:
    local_port: str
    remote_chassis_subtype: int
    remote_chassis_id: str
    remote_port: str | None = None
    remote_system_name: str | None = None


@dataclass(frozen=True, slots=True)
class SnmpInterface:
    index: int
    name: str | None = None
    description: str | None = None
    interface_type: str | None = None
    admin_status: str | None = None
    oper_status: str | None = None
    speed_mbps: float | None = None
    alias: str | None = None


@dataclass(frozen=True, slots=True)
class SnmpIdentity:
    name: str | None = None
    description: str | None = None
    object_id: str | None = None
    contact: str | None = None
    location: str | None = None
    uptime_seconds: int | None = None
    interface_count: int | None = None
    interfaces: tuple[SnmpInterface, ...] = ()
    lldp_chassis_subtype: int | None = None
    lldp_chassis_id: str | None = None
    lldp_collected: bool = False
    lldp_neighbors: tuple[LldpNeighbor, ...] = ()


class DeviceEnricher:
    def __init__(
        self,
        *,
        reverse_lookup: Callable[[str], str | None] = lambda ip: reverse_dns_name(ip),
        netbios_lookup: Callable[[str], str | None] = lambda ip: netbios_name(ip),
        snmp_lookup: Callable[[str], SnmpIdentity | None] = lambda ip: snmp_identity(
            ip
        ),
        workers: int | None = None,
    ):
        self.reverse_lookup = reverse_lookup
        self.netbios_lookup = netbios_lookup
        self.snmp_lookup = snmp_lookup
        self.workers = workers or _env_int("FORGESEC_ENRICHMENT_WORKERS", 16)

    def enrich(self, devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not devices:
            return devices
        workers = max(1, min(self.workers, len(devices), 32))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(self._enrich_one, dict(device)): index
                for index, device in enumerate(devices)
            }
            enriched = [dict(device) for device in devices]
            for future in as_completed(futures):
                enriched[futures[future]] = future.result()
        return enriched

    def _enrich_one(self, device: dict[str, Any]) -> dict[str, Any]:
        ip = str(device.get("ip") or "")
        if not ip:
            return device
        if not _clean(device.get("hostname")):
            hostname = _clean(self.reverse_lookup(ip)) or _clean(
                self.netbios_lookup(ip)
            )
            if hostname:
                device["hostname"] = hostname
        snmp = self.snmp_lookup(ip)
        if snmp:
            device["snmp_name"] = _clean(snmp.name)
            device["snmp_description"] = _clean(snmp.description, max_length=512)
            device["snmp_object_id"] = _clean(snmp.object_id)
            device["snmp_contact"] = _clean(snmp.contact, max_length=255)
            device["snmp_location"] = _clean(snmp.location, max_length=255)
            device["snmp_uptime_seconds"] = snmp.uptime_seconds
            device["snmp_interface_count"] = snmp.interface_count
            device["snmp_interfaces"] = [
                {
                    "index": interface.index,
                    "name": _clean(interface.name),
                    "description": _clean(interface.description),
                    "interface_type": _clean(interface.interface_type),
                    "admin_status": _clean(interface.admin_status),
                    "oper_status": _clean(interface.oper_status),
                    "speed_mbps": interface.speed_mbps,
                    "alias": _clean(interface.alias),
                }
                for interface in snmp.interfaces
            ]
            device["lldp_chassis_subtype"] = snmp.lldp_chassis_subtype
            device["lldp_chassis_id"] = snmp.lldp_chassis_id
            device["lldp_collected"] = snmp.lldp_collected
            device["lldp_neighbors"] = [
                {
                    "local_port": neighbor.local_port,
                    "remote_chassis_subtype": neighbor.remote_chassis_subtype,
                    "remote_chassis_id": neighbor.remote_chassis_id,
                    "remote_port": neighbor.remote_port,
                    "remote_system_name": neighbor.remote_system_name,
                }
                for neighbor in snmp.lldp_neighbors
            ]
            if not _clean(device.get("hostname")) and device["snmp_name"]:
                device["hostname"] = device["snmp_name"]
            if not _clean(device.get("vendor")) and snmp.description:
                device["vendor"] = _vendor_from_description(snmp.description)
        device_type, confidence = classify_discovered_device(device)
        device["device_type"] = device_type
        device["classification_confidence"] = confidence
        return device


def reverse_dns_name(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return None


def netbios_name(ip: str) -> str | None:
    try:
        result = subprocess.run(
            ["nbtstat", "-A", ip],
            capture_output=True,
            text=True,
            timeout=_env_float("FORGESEC_HOSTNAME_LOOKUP_TIMEOUT_SECONDS", 1.2),
            creationflags=NO_WINDOW,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "<00>" and parts[2].upper() == "UNIQUE":
            return parts[0]
    return None


def snmp_identity(ip: str) -> SnmpIdentity | None:
    timeout = _env_float("FORGESEC_SNMP_TIMEOUT_SECONDS", 0.7)
    interface_limit = _env_int("FORGESEC_SNMP_INTERFACE_LIMIT", 24)
    communities = _snmp_communities()
    for community in communities:
        values = _snmp_get(
            ip,
            community,
            [
                SYS_NAME,
                SYS_DESCR,
                SYS_OBJECT_ID,
                SYS_UP_TIME,
                SYS_CONTACT,
                SYS_LOCATION,
                IF_NUMBER,
            ],
            timeout,
        )
        if values:
            chassis_subtype, chassis_id, collected, neighbors = _lldp_identity(
                ip, community, timeout
            )
            return SnmpIdentity(
                name=_clean(values.get(SYS_NAME)),
                description=_clean(values.get(SYS_DESCR), max_length=512),
                object_id=_clean(values.get(SYS_OBJECT_ID)),
                contact=_clean(values.get(SYS_CONTACT)),
                location=_clean(values.get(SYS_LOCATION)),
                uptime_seconds=_timeticks_to_seconds(values.get(SYS_UP_TIME)),
                interface_count=_int_or_none(values.get(IF_NUMBER)),
                interfaces=tuple(
                    _snmp_interfaces(ip, community, timeout, interface_limit)
                ),
                lldp_chassis_subtype=chassis_subtype,
                lldp_chassis_id=chassis_id,
                lldp_collected=collected,
                lldp_neighbors=neighbors,
            )
    return None


def _snmp_get(
    ip: str,
    community: str,
    oids: list[str],
    timeout: float,
) -> dict[str, str]:
    return {
        oid: decoded
        for oid, (tag, value) in _snmp_get_raw(ip, community, oids, timeout).items()
        if (decoded := _decode_value(tag, value)) is not None
    }


def _snmp_get_raw(
    ip: str, community: str, oids: list[str], timeout: float
) -> dict[str, tuple[int, bytes]]:
    packet = _snmp_get_request(community, oids)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (ip, 161))
            data, address = sock.recvfrom(65535)
        except OSError:
            return {}
    if address[:2] != (ip, 161):
        return {}
    return _parse_snmp_response_raw(data)


def _snmp_get_request(community: str, oids: list[str]) -> bytes:
    return _snmp_request(0xA0, community, oids)


def _snmp_get_next_request(community: str, oid: str) -> bytes:
    return _snmp_request(0xA1, community, [oid])


def _snmp_request(pdu_tag: int, community: str, oids: list[str]) -> bytes:
    request_id = random.randint(1, 2_147_483_647)
    varbinds = b"".join(_seq(_oid(oid) + _null()) for oid in oids)
    pdu = _tlv(
        pdu_tag,
        _integer(request_id) + _integer(0) + _integer(0) + _seq(varbinds),
    )
    return _seq(_integer(1) + _octet(community.encode("ascii", "ignore")) + pdu)


def _snmp_walk(
    ip: str,
    community: str,
    base_oid: str,
    timeout: float,
    limit: int,
) -> dict[str, str]:
    raw = _snmp_walk_raw(ip, community, base_oid, timeout, limit)
    return {
        oid: decoded
        for oid, (tag, value) in (raw or {}).items()
        if (decoded := _decode_value(tag, value)) is not None
    }


def _snmp_walk_raw(
    ip: str,
    community: str,
    base_oid: str,
    timeout: float,
    limit: int,
    *,
    require_complete: bool = False,
) -> dict[str, tuple[int, bytes]] | None:
    values: dict[str, tuple[int, bytes]] = {}
    current_oid = base_oid
    for _ in range(max(0, limit)):
        packet = _snmp_get_next_request(community, current_oid)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            try:
                sock.sendto(packet, (ip, 161))
                data, address = sock.recvfrom(65535)
            except OSError:
                return None if require_complete else (values if values else None)
        if address[:2] != (ip, 161):
            return None if require_complete else (values if values else None)
        response = _parse_snmp_response_raw(data)
        if not response:
            return None if require_complete else (values if values else None)
        next_oid, value = next(iter(response.items()))
        if not _in_oid_tree(next_oid, base_oid):
            break
        values[next_oid] = value
        current_oid = next_oid
    return values


def _lldp_identity(
    ip: str, community: str, timeout: float
) -> tuple[int | None, str | None, bool, tuple[LldpNeighbor, ...]]:
    local = _snmp_get_raw(
        ip, community, [LLDP_LOC_CHASSIS_SUBTYPE, LLDP_LOC_CHASSIS_ID], timeout
    )
    subtype = _raw_int(local.get(LLDP_LOC_CHASSIS_SUBTYPE))
    chassis = local.get(LLDP_LOC_CHASSIS_ID)
    if subtype not in range(1, 8) or not chassis or chassis[0] != 0x04:
        return None, None, False, ()
    chassis_id = chassis[1].hex()
    if not chassis_id or len(chassis_id) > 510:
        return None, None, False, ()
    limit = max(1, min(_env_int("FORGESEC_LLDP_NEIGHBOR_LIMIT", 32), 64))
    subtypes = _snmp_walk_raw(
        ip,
        community,
        LLDP_REM_CHASSIS_SUBTYPE,
        timeout,
        limit,
        require_complete=True,
    )
    chassis_ids = _snmp_walk_raw(
        ip,
        community,
        LLDP_REM_CHASSIS_ID,
        timeout,
        limit,
        require_complete=True,
    )
    if subtypes is None or chassis_ids is None:
        return subtype, chassis_id, False, ()
    remote_ports = _snmp_walk_raw(ip, community, LLDP_REM_PORT_ID, timeout, limit) or {}
    remote_port_subtypes = (
        _snmp_walk_raw(ip, community, LLDP_REM_PORT_SUBTYPE, timeout, limit) or {}
    )
    remote_names = (
        _snmp_walk_raw(ip, community, LLDP_REM_SYS_NAME, timeout, limit) or {}
    )
    local_ports = _snmp_walk_raw(ip, community, LLDP_LOC_PORT_ID, timeout, limit) or {}
    neighbors: list[LldpNeighbor] = []
    seen: set[tuple[int, str, str]] = set()
    for oid, remote_chassis in chassis_ids.items():
        suffix = oid.removeprefix(f"{LLDP_REM_CHASSIS_ID}.")
        parts = suffix.split(".")
        if len(parts) != 3 or not all(part.isdigit() for part in parts):
            continue
        local_number = int(parts[1])
        if local_number < 1 or local_number > 4096 or remote_chassis[0] != 0x04:
            continue
        remote_subtype = _raw_int(subtypes.get(f"{LLDP_REM_CHASSIS_SUBTYPE}.{suffix}"))
        remote_id = remote_chassis[1].hex()
        if remote_subtype not in range(1, 8) or not remote_id or len(remote_id) > 510:
            continue
        port = _display_lldp_id(local_ports.get(f"{LLDP_LOC_PORT_ID}.{local_number}"))
        local_port = port or f"Port {local_number}"
        key = (local_number, remote_id, suffix)
        if key in seen:
            continue
        seen.add(key)
        remote_port_subtype = _raw_int(
            remote_port_subtypes.get(f"{LLDP_REM_PORT_SUBTYPE}.{suffix}")
        )
        neighbors.append(
            LldpNeighbor(
                local_port=local_port,
                remote_chassis_subtype=remote_subtype,
                remote_chassis_id=remote_id,
                remote_port=_display_lldp_id(
                    remote_ports.get(f"{LLDP_REM_PORT_ID}.{suffix}"),
                    mac=remote_port_subtype == 3,
                ),
                remote_system_name=_display_lldp_id(
                    remote_names.get(f"{LLDP_REM_SYS_NAME}.{suffix}")
                ),
            )
        )
    return subtype, chassis_id, True, tuple(neighbors)


def _raw_int(value: tuple[int, bytes] | None) -> int | None:
    if value is None or value[0] != 0x02:
        return None
    return int.from_bytes(value[1], "big")


def _display_lldp_id(
    value: tuple[int, bytes] | None, *, mac: bool = False
) -> str | None:
    if value is None or value[0] != 0x04 or not value[1]:
        return None
    raw = value[1]
    if mac and len(raw) == 6:
        return ":".join(f"{byte:02x}" for byte in raw)
    try:
        label = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        label = ""
    if label and all(character.isprintable() for character in label):
        return label[:255]
    return raw.hex()[:255]


def _snmp_interfaces(
    ip: str,
    community: str,
    timeout: float,
    limit: int,
) -> list[SnmpInterface]:
    if limit <= 0:
        return []
    names = _snmp_walk(ip, community, IF_NAME, timeout, limit)
    descriptions = _snmp_walk(ip, community, IF_DESCR, timeout, limit)
    types = _snmp_walk(ip, community, IF_TYPE, timeout, limit)
    admin_statuses = _snmp_walk(ip, community, IF_ADMIN_STATUS, timeout, limit)
    oper_statuses = _snmp_walk(ip, community, IF_OPER_STATUS, timeout, limit)
    speeds = _snmp_walk(ip, community, IF_SPEED, timeout, limit)
    high_speeds = _snmp_walk(ip, community, IF_HIGH_SPEED, timeout, limit)
    aliases = _snmp_walk(ip, community, IF_ALIAS, timeout, limit)
    indexes = sorted(
        {
            index
            for mapping, base in (
                (names, IF_NAME),
                (descriptions, IF_DESCR),
                (types, IF_TYPE),
                (admin_statuses, IF_ADMIN_STATUS),
                (oper_statuses, IF_OPER_STATUS),
                (speeds, IF_SPEED),
                (high_speeds, IF_HIGH_SPEED),
                (aliases, IF_ALIAS),
            )
            for oid in mapping
            if (index := _index_from_oid(oid, base)) is not None
        }
    )
    return [
        SnmpInterface(
            index=index,
            name=_clean(_value_for_index(names, IF_NAME, index)),
            description=_clean(_value_for_index(descriptions, IF_DESCR, index)),
            interface_type=_interface_type(_value_for_index(types, IF_TYPE, index)),
            admin_status=_interface_status(
                _value_for_index(admin_statuses, IF_ADMIN_STATUS, index)
            ),
            oper_status=_interface_status(
                _value_for_index(oper_statuses, IF_OPER_STATUS, index)
            ),
            speed_mbps=_interface_speed_mbps(
                _value_for_index(speeds, IF_SPEED, index),
                _value_for_index(high_speeds, IF_HIGH_SPEED, index),
            ),
            alias=_clean(_value_for_index(aliases, IF_ALIAS, index)),
        )
        for index in indexes[:limit]
    ]


def _parse_snmp_response(data: bytes) -> dict[str, str]:
    return {
        oid: decoded
        for oid, (tag, value) in _parse_snmp_response_raw(data).items()
        if (decoded := _decode_value(tag, value)) is not None
    }


def _parse_snmp_response_raw(data: bytes) -> dict[str, tuple[int, bytes]]:
    try:
        tag, payload, _offset = _read_tlv(data, 0)
        if tag != 0x30:
            return {}
        fields = _read_all(payload)
        if len(fields) < 3:
            return {}
        pdu_tag, pdu_payload = fields[2]
        if pdu_tag != 0xA2:
            return {}
        pdu_fields = _read_all(pdu_payload)
        if len(pdu_fields) < 4:
            return {}
        if pdu_fields[1][0] != 0x02 or int.from_bytes(pdu_fields[1][1], "big"):
            return {}
        varbinds_tag, varbinds_payload = pdu_fields[3]
        if varbinds_tag != 0x30:
            return {}
        values: dict[str, tuple[int, bytes]] = {}
        for varbind_tag, varbind_payload in _read_all(varbinds_payload):
            if varbind_tag != 0x30:
                continue
            parts = _read_all(varbind_payload)
            if len(parts) != 2 or parts[0][0] != 0x06:
                continue
            oid = _decode_oid(parts[0][1])
            values[oid] = parts[1]
        return values
    except (IndexError, ValueError):
        return {}


def _decode_value(tag: int, payload: bytes) -> str | None:
    if tag == 0x04:
        return payload.decode("utf-8", errors="replace").strip("\x00\r\n\t ")
    if tag == 0x06:
        return _decode_oid(payload)
    if tag in {0x02, 0x41, 0x42, 0x43, 0x46, 0x47}:
        return str(int.from_bytes(payload, "big", signed=False))
    return None


def _read_all(payload: bytes) -> list[tuple[int, bytes]]:
    values: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(payload):
        tag, value, offset = _read_tlv(payload, offset)
        values.append((tag, value))
    return values


def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    tag = data[offset]
    offset += 1
    length = data[offset]
    offset += 1
    if length & 0x80:
        width = length & 0x7F
        if width == 0:
            raise ValueError("indefinite length is not supported")
        length = int.from_bytes(data[offset : offset + width], "big")
        offset += width
    return tag, data[offset : offset + length], offset + length


def _tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _length(len(payload)) + payload


def _seq(payload: bytes) -> bytes:
    return _tlv(0x30, payload)


def _integer(value: int) -> bytes:
    payload = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if payload[0] & 0x80:
        payload = b"\x00" + payload
    return _tlv(0x02, payload)


def _octet(payload: bytes) -> bytes:
    return _tlv(0x04, payload)


def _null() -> bytes:
    return b"\x05\x00"


def _oid(value: str) -> bytes:
    parts = [int(part) for part in value.split(".")]
    if len(parts) < 2:
        raise ValueError("OID must have at least two parts")
    payload = bytes([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        payload += _base128(part)
    return _tlv(0x06, payload)


def _decode_oid(payload: bytes) -> str:
    if not payload:
        return ""
    first = payload[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in payload[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _base128(value: int) -> bytes:
    chunks = [value & 0x7F]
    value >>= 7
    while value:
        chunks.append((value & 0x7F) | 0x80)
        value >>= 7
    return bytes(reversed(chunks))


def _length(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    payload = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(payload)]) + payload


def _snmp_communities() -> list[str]:
    raw = os.getenv("FORGESEC_SNMP_COMMUNITIES", "public")
    communities = [_clean(item, max_length=64) for item in raw.split(",")]
    return [item for item in communities if item][:3]


def _in_oid_tree(oid: str, base_oid: str) -> bool:
    return oid == base_oid or oid.startswith(f"{base_oid}.")


def _index_from_oid(oid: str, base_oid: str) -> int | None:
    if not _in_oid_tree(oid, base_oid):
        return None
    suffix = oid.removeprefix(f"{base_oid}.")
    try:
        return int(suffix.split(".", 1)[0])
    except ValueError:
        return None


def _value_for_index(values: dict[str, str], base_oid: str, index: int) -> str | None:
    return values.get(f"{base_oid}.{index}")


def _int_or_none(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _timeticks_to_seconds(value: Any) -> int | None:
    ticks = _int_or_none(value)
    return ticks // 100 if ticks is not None else None


def _interface_status(value: str | None) -> str | None:
    statuses = {
        "1": "up",
        "2": "down",
        "3": "testing",
        "4": "unknown",
        "5": "dormant",
        "6": "not-present",
        "7": "lower-layer-down",
    }
    return statuses.get(str(value or ""))


def _interface_type(value: str | None) -> str | None:
    types = {
        "1": "other",
        "6": "ethernet",
        "24": "loopback",
        "53": "virtual",
        "71": "wireless",
        "131": "tunnel",
        "135": "l2-vlan",
        "136": "l3-vlan",
        "161": "link-aggregate",
    }
    return types.get(str(value or ""), value)


def _interface_speed_mbps(speed: str | None, high_speed: str | None) -> float | None:
    high_speed_mbps = _int_or_none(high_speed)
    if high_speed_mbps and high_speed_mbps > 0:
        return float(high_speed_mbps)
    bits_per_second = _int_or_none(speed)
    if bits_per_second and bits_per_second > 0:
        return round(bits_per_second / 1_000_000, 3)
    return None


def _vendor_from_description(description: str) -> str | None:
    lowered = description.lower()
    vendors = {
        "cisco": "Cisco",
        "fortinet": "Fortinet",
        "juniper": "Juniper",
        "mikrotik": "MikroTik",
        "ubiquiti": "Ubiquiti",
        "tp-link": "TP-Link",
        "hewlett packard": "Hewlett Packard",
        "aruba": "Aruba",
        "dell": "Dell",
        "netgear": "Netgear",
        "palo alto": "Palo Alto Networks",
    }
    for marker, vendor in vendors.items():
        if marker in lowered:
            return vendor
    return None


def _clean(value: Any, *, max_length: int = 255) -> str | None:
    text = str(value or "").strip()
    return text[:max_length] if text else None


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default
