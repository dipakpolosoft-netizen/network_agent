from __future__ import annotations

from telesec_agent.enrollment import AgentIdentity
from telesec_agent.scanning.discovery import DiscoveryCommandHandler
from telesec_agent.scanning.interfaces import InterfaceScope, ResolvedDiscoveryPlan
from telesec_agent.scanning.nmap_runner import DiscoveryProgress
from telesec_agent.scanning.parser import parse_discovery_xml

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


def test_handler_aggregates_sequential_segments() -> None:
    nmap = FakeNmap()
    parent = InterfaceScope(
        "Ethernet", "172.168.1.248", "172.168.0.0/22", False
    )
    handler = DiscoveryCommandHandler(
        nmap,  # type: ignore[arg-type]
        scope_resolver=lambda *_args, **_kwargs: ResolvedDiscoveryPlan(
            parent, ("172.168.0.0/24", "172.168.1.0/24")
        ),
    )
    client = FakeDiscoveryClient()
    identity = AgentIdentity(
        agent_id="00000000-0000-0000-0000-000000000123",
        server_url="https://telesec.example.com",
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
