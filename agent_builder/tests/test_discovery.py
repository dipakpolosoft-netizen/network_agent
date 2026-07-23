from __future__ import annotations

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
