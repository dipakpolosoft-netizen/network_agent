from __future__ import annotations

import socket
from collections import namedtuple

from telesec_agent.scanning import interfaces

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
