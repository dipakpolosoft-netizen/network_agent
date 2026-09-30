from __future__ import annotations

from approved_policy import approved_policy

from forgesec_agent.enrollment import AgentIdentity
from forgesec_agent.scanning import enrichment
from forgesec_agent.scanning.discovery import DiscoveryCommandHandler
from forgesec_agent.scanning.enrichment import (
    DeviceEnricher,
    LldpNeighbor,
    SnmpIdentity,
    SnmpInterface,
)
from forgesec_agent.scanning.interfaces import InterfaceScope, ResolvedDiscoveryPlan
from forgesec_agent.scanning.nmap_runner import (
    DiscoveryProgress,
    ScanCancelled,
    ScanTimedOut,
)
from forgesec_agent.scanning.parser import parse_discovery_xml

DISCOVERY_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up" reason="arp-response" />
    <address addr="192.168.1.1" addrtype="ipv4" />
    <address addr="00:11:22:33:44:55" addrtype="mac" vendor="Router Vendor" />
    <hostnames><hostname name="gateway.local" type="PTR" /></hostnames>
    <times srtt="1200" rttvar="200" to="100000" />
  </host>
  <host>
    <status state="down" reason="no-response" />
    <address addr="192.168.1.2" addrtype="ipv4" />
  </host>
  <host>
    <status state="up" reason="localhost-response" />
    <address addr="192.168.1.25" addrtype="ipv4" />
  </host>
</nmaprun>
"""


def test_parser_returns_only_up_hosts_and_marks_agent() -> None:
    devices = parse_discovery_xml(
        DISCOVERY_XML,
        local_ip="192.168.1.25",
        observed_at="2026-07-23T10:00:00Z",
    )

    assert [device["ip"] for device in devices] == [
        "192.168.1.1",
        "192.168.1.25",
    ]
    assert devices[0]["vendor"] == "Router Vendor"
    assert devices[0]["hostname"] == "gateway.local"
    assert devices[0]["latency_ms"] == 1.2
    assert devices[1]["is_agent"] is True
    assert len(devices[0]["device_id"]) == 32


class FakeNmap:
    def __init__(self):
        self.networks: list[str] = []
        self.exclusions: list[list[str]] = []

    def discover(self, network, *, exclusions, cancel_requested, progress_callback):
        self.networks.append(network)
        self.exclusions.append(exclusions)
        progress_callback(DiscoveryProgress(50.0, 1, 1.0))
        third = network.split(".")[2]
        return f"""<?xml version="1.0"?>
<nmaprun><host><status state="up" reason="arp-response" />
<address addr="172.168.{third}.10" addrtype="ipv4" /></host></nmaprun>"""


class FollowUpNmap(FakeNmap):
    def __init__(self):
        super().__init__()
        self.checked: list[str] = []

    def verify_known_host(self, ip, *, cancel_requested, activity_callback):
        self.checked.append(ip)
        if activity_callback:
            activity_callback()
        state = "up" if ip.endswith(".20") else "down"
        return (
            '<nmaprun><host><status state="'
            f'{state}" reason="{"syn-ack" if state == "up" else "no-response"}" />'
            f'<address addr="{ip}" addrtype="ipv4" /></host></nmaprun>'
        )


class FakeDiscoveryClient:
    def __init__(self):
        self.events: list[dict] = []
        self.upload: dict | None = None

    def command_event(self, _command_id, payload, *, credential):
        self.events.append(payload)
        return {}

    def upload_discovery(self, _discovery_id, payload, *, credential):
        self.upload = payload
        return {}

    def discovery_control(self, _discovery_id, *, credential):
        return {"cancel_requested": False}


class NoopEnricher:
    def enrich(self, devices):
        return devices


def test_device_enricher_adds_hostname_and_snmp_identity() -> None:
    enricher = DeviceEnricher(
        reverse_lookup=lambda _ip: None,
        netbios_lookup=lambda _ip: None,
        snmp_lookup=lambda _ip: SnmpIdentity(
            name="core-switch",
            description="Cisco IOS managed switch",
            object_id="1.3.6.1.4.1.9.1.123",
            contact="netops@example.com",
            location="MDF rack",
            uptime_seconds=86400,
            interface_count=48,
            interfaces=(
                SnmpInterface(
                    index=1,
                    name="Gi1/0/1",
                    description="GigabitEthernet1/0/1",
                    interface_type="ethernet",
                    admin_status="up",
                    oper_status="up",
                    speed_mbps=1000,
                    alias="uplink",
                ),
            ),
            lldp_chassis_subtype=4,
            lldp_chassis_id="001122334455",
            lldp_collected=True,
            lldp_neighbors=(
                LldpNeighbor("Gi1/0/1", 4, "aabbccddeeff", "Gi0/1", "edge"),
            ),
        ),
        workers=1,
    )

    devices = enricher.enrich(
        [
            {
                "device_id": "selected-device-0001",
                "ip": "192.168.1.2",
                "hostname": None,
                "vendor": None,
            }
        ]
    )

    assert devices[0]["hostname"] == "core-switch"
    assert devices[0]["snmp_name"] == "core-switch"
    assert devices[0]["snmp_description"] == "Cisco IOS managed switch"
    assert devices[0]["snmp_object_id"] == "1.3.6.1.4.1.9.1.123"
    assert devices[0]["snmp_contact"] == "netops@example.com"
    assert devices[0]["snmp_location"] == "MDF rack"
    assert devices[0]["snmp_uptime_seconds"] == 86400
    assert devices[0]["snmp_interface_count"] == 48
    assert devices[0]["snmp_interfaces"][0]["name"] == "Gi1/0/1"
    assert devices[0]["lldp_chassis_id"] == "001122334455"
    assert devices[0]["lldp_neighbors"][0]["remote_port"] == "Gi0/1"
    assert devices[0]["vendor"] == "Cisco"
    assert devices[0]["device_type"] == "switch"
    assert devices[0]["classification_confidence"] >= 0.9


def test_failed_identity_lookups_preserve_discovered_hosts() -> None:
    def broken_lookup(_ip: str):
        raise RuntimeError("lookup unavailable")

    enricher = DeviceEnricher(
        reverse_lookup=broken_lookup,
        netbios_lookup=lambda ip: "test-pc" if ip.endswith(".20") else None,
        snmp_lookup=lambda ip: (
            SnmpIdentity(description="Cisco Catalyst managed switch")
            if ip.endswith(".21") else broken_lookup(ip)
        ),
        workers=2,
    )
    devices = enricher.enrich([
        {"ip": "192.168.1.20", "hostname": None},
        {"ip": "192.168.1.21", "hostname": None},
    ])
    assert [device["ip"] for device in devices] == ["192.168.1.20", "192.168.1.21"]
    assert devices[0]["hostname"] == "test-pc"
    assert devices[0]["device_type"] == "unknown"
    assert devices[1]["device_type"] == "switch"


def test_one_enrichment_failure_does_not_abort_other_hosts(monkeypatch) -> None:
    enricher = DeviceEnricher(
        reverse_lookup=lambda _ip: None,
        netbios_lookup=lambda _ip: None,
        snmp_lookup=lambda _ip: None,
        workers=2,
    )
    original = enricher._enrich_one

    def enrich_one(device: dict) -> dict:
        if device["ip"] in {"192.168.1.20", "192.168.1.22"}:
            raise ValueError("bad identity data")
        return original(device)

    monkeypatch.setattr(enricher, "_enrich_one", enrich_one)
    devices = enricher.enrich([
        {"ip": "192.168.1.20", "hostname": "first"},
        {"ip": "192.168.1.21", "hostname": "second"},
        {
            "ip": "192.168.1.22", "hostname": "third",
            "device_type": "switch", "classification_confidence": 0.9,
        },
    ])
    assert [device["hostname"] for device in devices] == ["first", "second", "third"]
    assert [device["device_type"] for device in devices] == [
        "unknown", "unknown", "switch"
    ]
    assert [device["classification_confidence"] for device in devices] == [
        0.0, 0.0, 0.9
    ]


def test_lldp_identity_keeps_binary_chassis_and_correlates_rows(monkeypatch) -> None:
    monkeypatch.setattr(
        enrichment,
        "_snmp_get_raw",
        lambda *_args: {
            enrichment.LLDP_LOC_CHASSIS_SUBTYPE: (0x02, b"\x04"),
            enrichment.LLDP_LOC_CHASSIS_ID: (0x04, bytes.fromhex("001122334455")),
        },
    )
    suffix = "0.7.1"
    columns = {
        enrichment.LLDP_REM_CHASSIS_SUBTYPE: {
            f"{enrichment.LLDP_REM_CHASSIS_SUBTYPE}.{suffix}": (0x02, b"\x04")
        },
        enrichment.LLDP_REM_CHASSIS_ID: {
            f"{enrichment.LLDP_REM_CHASSIS_ID}.{suffix}": (
                0x04,
                bytes.fromhex("aabbccddeeff"),
            )
        },
        enrichment.LLDP_REM_PORT_SUBTYPE: {
            f"{enrichment.LLDP_REM_PORT_SUBTYPE}.{suffix}": (0x02, b"\x05")
        },
        enrichment.LLDP_REM_PORT_ID: {
            f"{enrichment.LLDP_REM_PORT_ID}.{suffix}": (0x04, b"Gi0/1")
        },
        enrichment.LLDP_REM_SYS_NAME: {
            f"{enrichment.LLDP_REM_SYS_NAME}.{suffix}": (0x04, b"edge-switch")
        },
        enrichment.LLDP_LOC_PORT_ID: {
            f"{enrichment.LLDP_LOC_PORT_ID}.7": (0x04, b"Gi1/0/7")
        },
    }
    monkeypatch.setattr(
        enrichment,
        "_snmp_walk_raw",
        lambda _ip, _community, base, _timeout, _limit, **_kwargs: columns[base],
    )
    subtype, chassis_id, collected, neighbors = enrichment._lldp_identity(
        "192.168.1.10", "public", 0.1
    )
    assert (subtype, chassis_id, collected) == (4, "001122334455", True)
    assert neighbors == (
        LldpNeighbor("Gi1/0/7", 4, "aabbccddeeff", "Gi0/1", "edge-switch"),
    )


def test_lldp_timeout_does_not_clear_previous_evidence(monkeypatch) -> None:
    monkeypatch.setattr(
        enrichment,
        "_snmp_get_raw",
        lambda *_args: {
            enrichment.LLDP_LOC_CHASSIS_SUBTYPE: (0x02, b"\x04"),
            enrichment.LLDP_LOC_CHASSIS_ID: (0x04, bytes.fromhex("001122334455")),
        },
    )
    monkeypatch.setattr(enrichment, "_snmp_walk_raw", lambda *_args, **_kwargs: None)
    assert enrichment._lldp_identity("192.168.1.10", "public", 0.1) == (
        4,
        "001122334455",
        False,
        (),
    )


def test_lldp_mismatched_required_columns_do_not_replace_snapshot(monkeypatch) -> None:
    monkeypatch.setattr(
        enrichment,
        "_snmp_get_raw",
        lambda *_args: {
            enrichment.LLDP_LOC_CHASSIS_SUBTYPE: (0x02, b"\x04"),
            enrichment.LLDP_LOC_CHASSIS_ID: (0x04, bytes.fromhex("001122334455")),
        },
    )
    monkeypatch.setattr(
        enrichment,
        "_snmp_walk_raw",
        lambda _ip, _community, base, _timeout, _limit, **_kwargs: (
            {f"{base}.0.7.1": (0x02, b"\x04")}
            if base == enrichment.LLDP_REM_CHASSIS_SUBTYPE
            else {}
        ),
    )
    assert enrichment._lldp_identity("192.168.1.10", "public", 0.1) == (
        4,
        "001122334455",
        False,
        (),
    )


def test_lldp_walk_at_limit_must_confirm_end_of_table(monkeypatch) -> None:
    base = enrichment.LLDP_REM_CHASSIS_ID
    rows = [f"{base}.0.7.1", f"{base}.0.7.2"]
    calls = 0

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def settimeout(self, _timeout):
            return None

        def sendto(self, _packet, _target):
            return None

        def recvfrom(self, _limit):
            nonlocal calls
            oid = rows[min(calls, len(rows) - 1)]
            calls += 1
            return oid.encode(), ("192.168.1.10", 161)

    monkeypatch.setattr(enrichment.socket, "socket", lambda *_args: FakeSocket())
    monkeypatch.setattr(
        enrichment,
        "_parse_snmp_response_raw",
        lambda data: {data.decode(): (0x04, b"row")},
    )
    assert (
        enrichment._snmp_walk_raw(
            "192.168.1.10", "public", base, 0.1, 1, require_complete=True
        )
        is None
    )
    rows[1] = "1.3.6.1.2.1.1.1.0"
    calls = 0
    assert enrichment._snmp_walk_raw(
        "192.168.1.10", "public", base, 0.1, 1, require_complete=True
    ) == {rows[0]: (0x04, b"row")}
    rows[1] = rows[0]
    calls = 0
    assert (
        enrichment._snmp_walk_raw(
            "192.168.1.10", "public", base, 0.1, 1, require_complete=True
        )
        is None
    )


def test_lldp_walk_requires_complete_binary_response(monkeypatch) -> None:
    base = enrichment.LLDP_REM_CHASSIS_ID
    oid = f"{base}.0.7.1"
    value = bytes.fromhex("aabbccddeeff")
    varbind = enrichment._seq(enrichment._oid(oid) + enrichment._octet(value))
    response = enrichment._seq(
        enrichment._integer(1)
        + enrichment._octet(b"public")
        + enrichment._tlv(
            0xA2,
            enrichment._integer(1)
            + enrichment._integer(0)
            + enrichment._integer(0)
            + enrichment._seq(varbind),
        )
    )
    error_response = enrichment._seq(
        enrichment._integer(1)
        + enrichment._octet(b"public")
        + enrichment._tlv(
            0xA2,
            enrichment._integer(1)
            + enrichment._integer(2)
            + enrichment._integer(1)
            + enrichment._seq(varbind),
        )
    )
    assert enrichment._parse_snmp_response_raw(error_response) == {}
    calls = 0

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def settimeout(self, _timeout):
            return None

        def sendto(self, _packet, _target):
            return None

        def recvfrom(self, _limit):
            nonlocal calls
            calls += 1
            if calls % 2:
                return response, ("192.168.1.10", 161)
            raise TimeoutError

    monkeypatch.setattr(enrichment.socket, "socket", lambda *_args: FakeSocket())
    assert (
        enrichment._snmp_walk_raw(
            "192.168.1.10", "public", base, 0.1, 3, require_complete=True
        )
        is None
    )
    assert enrichment._snmp_walk_raw("192.168.1.10", "public", base, 0.1, 3) == {
        oid: (0x04, value)
    }


def test_handler_aggregates_sequential_segments() -> None:
    nmap = FakeNmap()
    parent = InterfaceScope("Ethernet", "172.168.1.248", "172.168.0.0/22", False)
    handler = DiscoveryCommandHandler(
        nmap,  # type: ignore[arg-type]
        scope_resolver=lambda *_args, **_kwargs: ResolvedDiscoveryPlan(
            parent, ("172.168.0.0/24", "172.168.1.0/24")
        ),
        enricher=NoopEnricher(),  # type: ignore[arg-type]
    )
    client = FakeDiscoveryClient()
    identity = AgentIdentity(
        agent_id="00000000-0000-0000-0000-000000000123",
        server_url="https://forgesec.example.com",
        credential="secret",
        heartbeat_interval_seconds=30,
        enrolled_at="2026-07-24T00:00:00Z",
    )

    handler.handle(
        {
            "command_id": "00000000-0000-0000-0000-000000000456",
            "payload": {
                "discovery_id": "00000000-0000-0000-0000-000000000789",
                "connected_network": "172.168.0.0/22",
                "interface_name": "Ethernet",
                "scopes": ["172.168.0.0/24", "172.168.1.0/24"],
                "mode": "all",
                "authorization_confirmed": True,
                "scope_policy": [approved_policy("172.168.0.0/22")],
            },
        },
        identity,
        client,  # type: ignore[arg-type]
    )

    assert nmap.networks == ["172.168.0.0/24", "172.168.1.0/24"]
    assert client.upload is not None
    assert client.upload["network"] == "172.168.0.0/22"
    assert client.upload["completed_scopes"] == nmap.networks
    assert [
        item["discovery_scope"] for item in client.upload["devices"]
    ] == nmap.networks
    assert client.events[-1]["status"] == "completed"


def test_handler_excludes_host_before_enrichment_or_upload() -> None:
    nmap = FakeNmap()
    parent = InterfaceScope("Ethernet", "172.168.1.248", "172.168.1.0/24", False)
    handler = DiscoveryCommandHandler(
        nmap,  # type: ignore[arg-type]
        scope_resolver=lambda *_args, **_kwargs: ResolvedDiscoveryPlan(
            parent, ("172.168.1.0/24",)
        ),
        enricher=NoopEnricher(),  # type: ignore[arg-type]
    )
    client = FakeDiscoveryClient()
    identity = AgentIdentity(
        agent_id="00000000-0000-0000-0000-000000000123",
        server_url="https://forgesec.example.com",
        credential="secret",
        heartbeat_interval_seconds=30,
        enrolled_at="2026-07-24T00:00:00Z",
    )
    handler.handle(
        {
            "command_id": "00000000-0000-0000-0000-000000000456",
            "payload": {
                "discovery_id": "00000000-0000-0000-0000-000000000789",
                "connected_network": "172.168.1.0/24",
                "interface_name": "Ethernet",
                "scopes": ["172.168.1.0/24"],
                "mode": "selected",
                "authorization_confirmed": True,
                "scope_policy": [
                    approved_policy("172.168.1.0/24", exclusions=["172.168.1.10/32"])
                ],
            },
        },
        identity,
        client,  # type: ignore[arg-type]
    )
    assert nmap.exclusions == [["172.168.1.10/32"]]
    assert client.upload is not None
    assert client.upload["devices"] == []


def test_discovery_stops_when_control_cannot_be_verified() -> None:
    class UnavailableControl:
        def discovery_control(self, *_args, **_kwargs):
            raise RuntimeError("Control plane unavailable")

    identity = AgentIdentity(
        agent_id="00000000-0000-0000-0000-000000000123",
        server_url="https://forgesec.example.com",
        credential="secret",
        heartbeat_interval_seconds=30,
        enrolled_at="2026-07-24T00:00:00Z",
    )
    assert (
        DiscoveryCommandHandler._cancel_requested(
            UnavailableControl(),  # type: ignore[arg-type]
            identity,
            "00000000-0000-0000-0000-000000000789",
        )
        is True
    )


def test_known_hosts_get_bounded_follow_up_without_offline_devices() -> None:
    nmap = FollowUpNmap()
    parent = InterfaceScope("Ethernet", "172.168.1.248", "172.168.0.0/22", False)
    handler = DiscoveryCommandHandler(
        nmap,  # type: ignore[arg-type]
        scope_resolver=lambda *_args, **_kwargs: ResolvedDiscoveryPlan(
            parent, ("172.168.1.0/24",)
        ),
        enricher=NoopEnricher(),  # type: ignore[arg-type]
    )
    client = FakeDiscoveryClient()
    identity = AgentIdentity(
        agent_id="00000000-0000-0000-0000-000000000123",
        server_url="https://forgesec.example.com",
        credential="secret",
        heartbeat_interval_seconds=30,
        enrolled_at="2026-07-24T00:00:00Z",
    )
    command = {
        "command_id": "00000000-0000-0000-0000-000000000456",
        "payload": {
            "discovery_id": "00000000-0000-0000-0000-000000000789",
            "connected_network": "172.168.0.0/22",
            "scopes": ["172.168.1.0/24"],
            "mode": "selected",
            "authorization_confirmed": True,
            "scope_policy": [approved_policy("172.168.1.0/24")],
            "known_targets": ["172.168.1.10", "172.168.1.20", "172.168.1.30"],
        },
    }
    handler.handle(command, identity, client)  # type: ignore[arg-type]
    assert nmap.networks == ["172.168.1.0/24"]
    assert nmap.checked == ["172.168.1.20", "172.168.1.30"]
    assert client.upload is not None
    assert client.upload["status"] == "completed"
    assert [item["status"] for item in client.upload["follow_up_checks"]] == [
        "already_discovered",
        "responsive",
        "no_response",
    ]
    assert [item["ip"] for item in client.upload["devices"]] == [
        "172.168.1.10",
        "172.168.1.20",
    ]
    assert client.upload["devices"][1]["discovery_reason"] == "targeted-syn-ack"
    assert client.upload["devices"][1]["last_seen"]

    client.upload = None
    nmap.networks.clear()
    command["payload"]["known_targets"] = ["172.168.2.20"]
    handler.handle(command, identity, client)  # type: ignore[arg-type]
    assert client.upload is None
    assert nmap.networks == []
    assert client.events[-1]["status"] == "failed"

    def timed_out(*_args, **_kwargs):
        raise ScanTimedOut("Known-host check timed out")

    nmap.verify_known_host = timed_out  # type: ignore[method-assign]
    command["payload"]["known_targets"] = ["172.168.1.40"]
    handler.handle(command, identity, client)  # type: ignore[arg-type]
    assert client.upload is not None
    assert client.upload["status"] == "partial"
    assert client.upload["follow_up_checks"][0]["status"] == "error"
    assert all(item["ip"] != "172.168.1.40" for item in client.upload["devices"])


def test_segment_timeout_preserves_only_approved_hosts_as_partial_evidence() -> None:
    class PartialNmap(FakeNmap):
        def discover(self, network, *, exclusions, cancel_requested, progress_callback):
            self.networks.append(network)
            raise ScanTimedOut(
                "Nmap discovery timed out",
                partial_xml=(
                    '<nmaprun><host><status state="up" reason="arp-response" />'
                    '<address addr="172.168.1.20" addrtype="ipv4" /></host>'
                    '<host><status state="up" reason="arp-response" />'
                    '<address addr="172.168.2.20" addrtype="ipv4" /></host></nmaprun>'
                ),
            )

    nmap = PartialNmap()
    parent = InterfaceScope("Ethernet", "172.168.1.248", "172.168.1.0/24", False)
    handler = DiscoveryCommandHandler(
        nmap,  # type: ignore[arg-type]
        scope_resolver=lambda *_args, **_kwargs: ResolvedDiscoveryPlan(
            parent, ("172.168.1.0/24",)
        ),
        enricher=NoopEnricher(),  # type: ignore[arg-type]
    )
    client = FakeDiscoveryClient()
    identity = AgentIdentity(
        agent_id="00000000-0000-0000-0000-000000000123",
        server_url="https://forgesec.example.com",
        credential="secret",
        heartbeat_interval_seconds=30,
        enrolled_at="2026-07-24T00:00:00Z",
    )
    handler.handle(
        {
            "command_id": "00000000-0000-0000-0000-000000000456",
            "payload": {
                "discovery_id": "00000000-0000-0000-0000-000000000789",
                "connected_network": "172.168.1.0/24",
                "scopes": ["172.168.1.0/24"],
                "mode": "selected",
                "authorization_confirmed": True,
                "scope_policy": [approved_policy("172.168.0.0/22")],
            },
        },
        identity,
        client,  # type: ignore[arg-type]
    )
    assert client.upload is not None
    assert client.upload["status"] == "partial"
    assert client.upload["completed_scopes"] == []
    assert client.upload["failed_scopes"] == ["172.168.1.0/24"]
    assert [item["ip"] for item in client.upload["devices"]] == ["172.168.1.20"]
    assert any(
        "partial host(s) retained" in event["message"] for event in client.events
    )


def test_cancelled_segment_discards_partial_hosts_outside_selected_scope() -> None:
    class CancelledNmap(FakeNmap):
        def discover(self, network, *, exclusions, cancel_requested, progress_callback):
            raise ScanCancelled(
                "Discovery cancelled",
                partial_xml=(
                    '<nmaprun><host><status state="up" reason="arp-response" />'
                    '<address addr="172.168.1.20" addrtype="ipv4" /></host>'
                    '<host><status state="up" reason="arp-response" />'
                    '<address addr="172.168.2.20" addrtype="ipv4" /></host></nmaprun>'
                ),
            )

    handler = DiscoveryCommandHandler(
        CancelledNmap(),  # type: ignore[arg-type]
        scope_resolver=lambda *_args, **_kwargs: ResolvedDiscoveryPlan(
            InterfaceScope("Ethernet", "172.168.1.248", "172.168.0.0/22", False),
            ("172.168.1.0/24",),
        ),
        enricher=NoopEnricher(),  # type: ignore[arg-type]
    )
    client = FakeDiscoveryClient()
    handler.handle(
        {
            "command_id": "00000000-0000-0000-0000-000000000456",
            "payload": {
                "discovery_id": "00000000-0000-0000-0000-000000000789",
                "connected_network": "172.168.0.0/22",
                "scopes": ["172.168.1.0/24"],
                "mode": "selected",
                "authorization_confirmed": True,
                "scope_policy": [approved_policy("172.168.0.0/22")],
            },
        },
        AgentIdentity(
            agent_id="00000000-0000-0000-0000-000000000123",
            server_url="https://forgesec.example.com",
            credential="secret",
            heartbeat_interval_seconds=30,
            enrolled_at="2026-07-24T00:00:00Z",
        ),
        client,  # type: ignore[arg-type]
    )

    assert client.upload is not None
    assert client.upload["status"] == "partial"
    assert [item["ip"] for item in client.upload["devices"]] == ["172.168.1.20"]
    assert client.upload["completed_scopes"] == []
    assert client.events[-1]["status"] == "cancelled"
