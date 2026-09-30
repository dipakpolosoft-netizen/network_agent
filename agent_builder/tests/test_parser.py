import pytest

from forgesec_agent.scanning.parser import (
    NmapParseError,
    parse_discovery_xml,
    parse_host_scan_xml,
)


def test_discovery_identity_is_trimmed_and_bounded_for_api() -> None:
    xml = (
        '<nmaprun><host><status state="up" reason="  arp-response  " />'
        '<address addr="192.0.2.10" addrtype="ipv4" />'
        f'<address addr="00:11:22:33:44:55" addrtype="mac" vendor="  {"V" * 300}  " />'
        f'<hostnames><hostname name="  {"h" * 300}  " /></hostnames>'
        '</host></nmaprun>'
    )
    device = parse_discovery_xml(
        xml, local_ip="192.0.2.25", observed_at="2026-09-29T10:00:00Z"
    )[0]
    assert device["hostname"] == "h" * 255
    assert device["vendor"] == "V" * 255
    assert device["discovery_reason"] == "arp-response"


def test_blank_discovery_identity_stays_unknown() -> None:
    xml = (
        '<nmaprun><host><status state="up" reason="  " />'
        '<address addr="192.0.2.10" addrtype="ipv4" />'
        '<address addr="00:11:22:33:44:55" addrtype="mac" vendor="  " />'
        '<hostnames><hostname name="  " /></hostnames>'
        '</host></nmaprun>'
    )
    device = parse_discovery_xml(
        xml, local_ip="192.0.2.25", observed_at="2026-09-29T10:00:00Z"
    )[0]
    assert device["hostname"] is None
    assert device["vendor"] is None
    assert device["discovery_reason"] == "response"


def test_host_scan_parser_keeps_rich_service_evidence() -> None:
    xml = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up" />
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" />
        <service name="https" product="ExampleOS" version="1.2.3"
          extrainfo="admin ui" ostype="embedded" devicetype="router"
          method="probed" conf="10">
          <cpe>cpe:/o:example:exampleos:1.2.3</cpe>
          <cpe>cpe:/a:example:https:1.2.3</cpe>
        </service>
      </port>
    </ports>
  </host>
</nmaprun>
"""

    parsed = parse_host_scan_xml(xml)

    assert parsed["ports"] == [
        {
            "protocol": "tcp",
            "port": 443,
            "state": "open",
            "reason": "syn-ack",
            "service": "https",
            "product": "ExampleOS",
            "version": "1.2.3",
            "extrainfo": "admin ui",
            "ostype": "embedded",
            "devicetype": "router",
            "method": "probed",
            "confidence": 10,
            "cpe": "cpe:/o:example:exampleos:1.2.3",
            "cpes": [
                "cpe:/o:example:exampleos:1.2.3",
                "cpe:/a:example:https:1.2.3",
            ],
        }
    ]


def test_host_scan_parser_keeps_missing_fingerprints_unknown() -> None:
    xml = """<nmaprun><host><hostnames><hostname name="  " /></hostnames>
      <ports><port protocol="tcp" portid="8080"><state state="open" />
        <service name="http" product=" " version="" method="table" conf="3" />
      </port></ports><os><osmatch name=" " accuracy="99" /></os></host></nmaprun>"""

    parsed = parse_host_scan_xml(xml)

    assert parsed["hostname"] is None
    assert parsed["os_matches"] == []
    assert parsed["ports"][0]["service"] == "http"
    assert parsed["ports"][0]["product"] is None
    assert parsed["ports"][0]["version"] is None
    assert parsed["ports"][0]["method"] == "table"
    assert parsed["ports"][0]["cpe"] is None


def test_host_scan_parser_does_not_invent_missing_port_or_protocol() -> None:
    xml = """<nmaprun><host><ports>
      <port portid="443"><state state="open" /></port>
      <port protocol="tcp"><state state="open" /></port>
      <port protocol="udp" portid="0"><state state="open" /></port>
      <port protocol="tcp" portid="22"><state state="open" /></port>
    </ports></host></nmaprun>"""

    parsed = parse_host_scan_xml(xml)

    assert [(port["protocol"], port["port"]) for port in parsed["ports"]] == [
        ("tcp", 22)
    ]


def test_duplicate_xml_port_is_rejected_instead_of_inflating_counts() -> None:
    xml = """<nmaprun><host><ports>
      <port protocol="tcp" portid="443"><state state="open" /></port>
      <port protocol="tcp" portid="443"><state state="filtered" /></port>
    </ports></host></nmaprun>"""

    with pytest.raises(NmapParseError, match="duplicate 443/tcp"):
        parse_host_scan_xml(xml)


@pytest.mark.parametrize(
    ("hosts", "message"),
    [
        ("", "exactly one target"),
        (
            '<host><status state="up"/><address addr="192.168.1.11" '
            'addrtype="ipv4"/></host>',
            "differs from selected target",
        ),
        (
            '<host><status state="down"/><address addr="192.168.1.10" '
            'addrtype="ipv4"/></host>',
            "did not report the selected host as up",
        ),
        (
            '<host><status state="up"/><address addr="192.168.1.10" '
            'addrtype="ipv4"/></host>' * 2,
            "exactly one target",
        ),
    ],
)
def test_selected_host_must_match_raw_xml(hosts: str, message: str) -> None:
    with pytest.raises(NmapParseError, match=message):
        parse_host_scan_xml(f"<nmaprun>{hosts}</nmaprun>", expected_ip="192.168.1.10")
