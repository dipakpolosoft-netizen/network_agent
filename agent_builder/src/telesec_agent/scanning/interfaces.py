"""Select an authorized locally attached private IPv4 scope."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

import psutil

MAX_DISCOVERY_ADDRESSES = 256
VIRTUAL_INTERFACE_MARKERS = (
    "docker",
    "hyper-v",
    "loopback",
    "tailscale",
    "tunnel",
    "virtual",
    "vmware",
    "vpn",
    "vbox",
    "wsl",
)


class ScopeError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class InterfaceScope:
    interface_name: str
    local_ip: str
    network: str
    is_virtual: bool


def eligible_scopes() -> list[InterfaceScope]:
    stats = psutil.net_if_stats()
    scopes: list[InterfaceScope] = []
    for name, addresses in psutil.net_if_addrs().items():
        interface = stats.get(name)
        if interface is None or not interface.isup:
            continue
        for address in addresses:
            if address.family != socket.AF_INET or not address.netmask:
                continue
            try:
                ip = ipaddress.ip_address(address.address)
                network = ipaddress.ip_network(
                    f"{address.address}/{address.netmask}", strict=False
                )
            except ValueError:
                continue
            if ip.is_loopback or ip.is_link_local or not ip.is_private:
                continue
            if network.num_addresses > MAX_DISCOVERY_ADDRESSES:
                continue
            lowered = name.lower()
            scopes.append(
                InterfaceScope(
                    interface_name=name,
                    local_ip=str(ip),
                    network=str(network),
                    is_virtual=any(
                        marker in lowered for marker in VIRTUAL_INTERFACE_MARKERS
                    ),
                )
            )
    scopes.sort(
        key=lambda item: (
            item.is_virtual,
            int(ipaddress.ip_address(item.local_ip)),
            item.interface_name.lower(),
        )
    )
    return scopes


def select_scope() -> InterfaceScope:
    scopes = eligible_scopes()
    if not scopes:
        raise ScopeError(
            "No active private IPv4 network of 256 addresses or fewer was found"
        )
    return scopes[0]
