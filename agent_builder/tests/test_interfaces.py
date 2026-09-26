from __future__ import annotations

import socket
from collections import namedtuple

from forgesec_agent.scanning import interfaces

Address = namedtuple("Address", "family address netmask broadcast ptp")
Stats = namedtuple("Stats", "isup")


def test_scope_prefers_physical_private_interface(monkeypatch) -> None:
    monkeypatch.setattr(
        interfaces.psutil,
        "net_if_stats",
        lambda: {"Ethernet": Stats(True), "Docker Virtual": Stats(True)},
    )
    monkeypatch.setattr(
        interfaces.psutil,
        "net_if_addrs",
        lambda: {
            "Docker Virtual": [
                Address(socket.AF_INET, "172.20.0.1", "255.255.255.0", None, None)
            ],
            "Ethernet": [
                Address(socket.AF_INET, "192.168.1.25", "255.255.255.0", None, None)
            ],
        },
    )

    selected = interfaces.select_scope()

    assert selected.interface_name == "Ethernet"
    assert selected.network == "192.168.1.0/24"


def test_connected_scope_prefers_physical_ethernet_over_windows_vethernet(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        interfaces.psutil,
        "net_if_stats",
        lambda: {
            "Ethernet": Stats(True),
            "vEthernet (Default Switch)": Stats(True),
            "vEthernet (WSL (Hyper-V firewall))": Stats(True),
        },
    )
    monkeypatch.setattr(
        interfaces.psutil,
        "net_if_addrs",
        lambda: {
            "vEthernet (Default Switch)": [
                Address(socket.AF_INET, "172.25.64.1", "255.255.240.0", None, None)
            ],
            "vEthernet (WSL (Hyper-V firewall))": [
                Address(socket.AF_INET, "172.31.176.1", "255.255.240.0", None, None)
            ],
            "Ethernet": [
                Address(socket.AF_INET, "172.168.1.248", "255.255.252.0", None, None)
            ],
        },
    )

    capability = interfaces.discovery_capability()

    assert capability.connected_scope.interface_name == "Ethernet"
    assert capability.connected_scope.network == "172.168.0.0/22"
    assert capability.scope_options == (
        "172.168.0.0/24",
        "172.168.1.0/24",
        "172.168.2.0/24",
        "172.168.3.0/24",
    )
    assert capability.recommended_scope == "172.168.1.0/24"
    assert capability.requires_authorization is True


def test_scope_rejects_networks_larger_than_safety_ceiling(monkeypatch) -> None:
    monkeypatch.setattr(
        interfaces.psutil,
        "net_if_stats",
        lambda: {"Ethernet": Stats(True)},
    )
    monkeypatch.setattr(
        interfaces.psutil,
        "net_if_addrs",
        lambda: {
            "Ethernet": [
                Address(socket.AF_INET, "10.20.1.25", "255.255.0.0", None, None)
            ]
        },
    )

    assert interfaces.eligible_scopes() == []


def test_scope_error_explains_public_and_oversized_network(monkeypatch) -> None:
    monkeypatch.setattr(
        interfaces.psutil,
        "net_if_stats",
        lambda: {"Ethernet": Stats(True)},
    )
    monkeypatch.setattr(
        interfaces.psutil,
        "net_if_addrs",
        lambda: {
            "Ethernet": [
                Address(socket.AF_INET, "172.168.1.248", "255.255.252.0", None, None)
            ]
        },
    )

    try:
        interfaces.select_scope()
    except interfaces.ScopeError as exc:
        assert exc.code == "scope_not_private"
        assert "172.168.0.0/22" in str(exc)
        assert "1024 addresses" in str(exc)
    else:
        raise AssertionError("Expected unsupported network scope")


def test_public_slash_22_offers_four_slash_24_segments(monkeypatch) -> None:
    monkeypatch.setattr(
        interfaces.psutil,
        "net_if_stats",
        lambda: {"Ethernet": Stats(True)},
    )
    monkeypatch.setattr(
        interfaces.psutil,
        "net_if_addrs",
        lambda: {
            "Ethernet": [
                Address(socket.AF_INET, "172.168.1.248", "255.255.252.0", None, None)
            ]
        },
    )

    capability = interfaces.discovery_capability()

    assert capability.connected_scope.network == "172.168.0.0/22"
    assert capability.scope_options == (
        "172.168.0.0/24",
        "172.168.1.0/24",
        "172.168.2.0/24",
        "172.168.3.0/24",
    )
    assert capability.recommended_scope == "172.168.1.0/24"
    assert capability.requires_authorization is True
    assert capability.all_segments_available is True


def test_requested_public_scope_must_be_authorized_and_attached(monkeypatch) -> None:
    monkeypatch.setattr(
        interfaces.psutil,
        "net_if_stats",
        lambda: {"Ethernet": Stats(True)},
    )
    monkeypatch.setattr(
        interfaces.psutil,
        "net_if_addrs",
        lambda: {
            "Ethernet": [
                Address(socket.AF_INET, "172.168.1.248", "255.255.252.0", None, None)
            ]
        },
    )

    plan = interfaces.resolve_discovery_plan(
        ["172.168.1.0/24"],
        connected_network="172.168.0.0/22",
        interface_name="Ethernet",
        authorization_confirmed=True,
    )

    assert plan.scopes == ("172.168.1.0/24",)
    try:
        interfaces.resolve_discovery_plan(
            ["172.169.1.0/24"],
            connected_network="172.168.0.0/22",
            interface_name="Ethernet",
            authorization_confirmed=True,
        )
    except interfaces.ScopeError as exc:
        assert exc.code == "scope_outside_connected_network"
    else:
        raise AssertionError("Expected a scope outside the adapter to be rejected")
