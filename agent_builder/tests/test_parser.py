from forgesec_agent.scanning.parser import parse_host_scan_xml


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
