from __future__ import annotations

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
from forgesec_agent.scanning.nmap_runner import DiscoveryProgress
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

    def discover(self, network, *, cancel_requested, progress_callback):
        self.networks.append(network)
        progress_callback(DiscoveryProgress(50.0, 1, 1.0))
        third = network.split(".")[2]
        return f"""<?xml version="1.0"?>
<nmaprun><host><status state="up" reason="arp-response" />
<address addr="172.168.{third}.10" addrtype="ipv4" /></host></nmaprun>"""


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
                "scope_policy": [{"cidr": "172.168.0.0/22", "exclusions": []}],
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
