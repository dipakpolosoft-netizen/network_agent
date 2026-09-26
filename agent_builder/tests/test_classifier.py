from __future__ import annotations

from forgesec_agent.scanning.classifier import (
    classify,
    classify_discovered_device,
    exposure_flags,
)


def test_classifies_firewall_from_snmp_identity() -> None:
    device_type, confidence = classify_discovered_device(
        {
            "vendor": "Fortinet",
            "snmp_description": "Fortinet FortiGate firewall appliance",
        }
    )

    assert device_type == "firewall"
    assert confidence >= 0.9


def test_classifies_switch_from_snmp_identity() -> None:
    device_type, confidence = classify_discovered_device(
        {
            "snmp_name": "core-switch",
            "snmp_description": "Cisco Catalyst managed switch",
        }
    )

    assert device_type == "switch"
    assert confidence >= 0.9


def test_classifies_camera_from_rtsp_service() -> None:
    device_type, confidence = classify(
        [
            {
                "port": 554,
                "state": "open",
                "service": "rtsp",
                "product": "Hikvision IP Camera",
            }
        ],
        [],
    )

    assert device_type == "camera"
    assert confidence >= 0.8


def test_classifies_router_from_nmap_device_type() -> None:
    device_type, confidence = classify(
        [
            {
                "port": 443,
                "state": "open",
                "service": "https",
                "product": "Router admin",
                "devicetype": "router",
            }
        ],
        [],
    )

    assert device_type == "router"
    assert confidence >= 0.8


def test_classifies_database_server_from_database_port() -> None:
    device_type, confidence = classify(
        [{"port": 5432, "state": "open", "service": "postgresql"}],
        [{"name": "Linux 6.x", "accuracy": 95}],
    )

    assert device_type == "database-server"
    assert confidence >= 0.75


def test_exposure_flags_include_udp_network_services() -> None:
    flags = exposure_flags(
        [
            {"protocol": "udp", "port": 69, "state": "open"},
            {"protocol": "udp", "port": 161, "state": "open"},
            {"protocol": "udp", "port": 500, "state": "open"},
        ]
    )

    assert {flag["code"] for flag in flags} >= {
        "tftp-exposed",
        "snmp-exposed",
        "vpn-ike-service",
    }
