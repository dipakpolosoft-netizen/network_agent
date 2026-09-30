from __future__ import annotations

import pytest

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


@pytest.mark.parametrize(
    ("identity", "expected"),
    [
        ({"snmp_description": "Dell PowerEdge server"}, "server"),
        ({"snmp_description": "Windows 11 workstation"}, "workstation"),
        ({"snmp_description": "Cisco Catalyst managed switch"}, "switch"),
        ({"snmp_description": "MikroTik RouterOS router"}, "router"),
        ({"snmp_description": "FortiGate firewall appliance"}, "firewall"),
    ],
)
def test_known_role_requires_device_evidence(identity: dict, expected: str) -> None:
    role, confidence = classify_discovered_device(identity)
    assert role == expected
    assert confidence >= 0.75


@pytest.mark.parametrize(
    ("ports", "os_matches", "identity"),
    [
        ([], [], {"vendor": "TP-Link Systems"}),
        (
            [{"protocol": "tcp", "port": 443, "state": "open", "service": "https"}],
            [],
            {},
        ),
        ([{"protocol": "udp", "port": 500, "state": "open"}], [], {}),
        (
            [{"protocol": "tcp", "port": 554, "state": "open", "service": "rtsp"}],
            [],
            {},
        ),
        (
            [
                {
                    "protocol": "tcp",
                    "port": 80,
                    "state": "filtered",
                    "product": "FortiGate",
                }
            ],
            [],
            {},
        ),
        ([], [{"name": "Linux 6.x", "accuracy": 95}], {}),
        ([], [], {"device_type": "firewall", "classification_confidence": 0.9}),
        ([{"port": 22, "state": "open", "devicetype": "server"}], [], {}),
    ],
)
def test_ambiguous_clues_keep_role_unknown(
    ports: list[dict], os_matches: list[dict], identity: dict
) -> None:
    assert classify(ports, os_matches, identity) == ("unknown", 0.0)


def test_hostname_role_hint_is_tentative() -> None:
    assert classify_discovered_device({"hostname": "core-switch"}) == ("switch", 0.65)


def test_udp_port_does_not_create_tcp_exposure_flag() -> None:
    assert exposure_flags([{"protocol": "udp", "port": 445, "state": "open"}]) == []


def test_firewall_software_does_not_turn_server_into_firewall() -> None:
    role, _confidence = classify_discovered_device(
        {"snmp_description": "Windows Server with Defender Firewall"}
    )
    assert role == "server"
