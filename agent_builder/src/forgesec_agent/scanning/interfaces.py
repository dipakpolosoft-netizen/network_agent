"""Select an authorized locally attached private IPv4 scope."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

import psutil

MAX_DISCOVERY_ADDRESSES = 256
MAX_AUTOMATIC_SEGMENTS = 16
VIRTUAL_INTERFACE_MARKERS = (
    "default switch",
    "docker",
    "hyper-v",
    "loopback",
    "nat",
    "tailscale",
    "tunnel",
    "vethernet",
    "virtual",
    "vmware",
    "vpn",
    "vbox",
    "wsl",
)


class ScopeError(RuntimeError):
    def __init__(self, message: str, *, code: str = "scope_unavailable"):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class InterfaceScope:
    interface_name: str
    local_ip: str
    network: str
    is_virtual: bool


@dataclass(frozen=True, slots=True)
class DiscoveryCapability:
    connected_scope: InterfaceScope
    scope_options: tuple[str, ...]
    recommended_scope: str
    capability: str
    requires_authorization: bool
    all_segments_available: bool


@dataclass(frozen=True, slots=True)
class ResolvedDiscoveryPlan:
    connected_scope: InterfaceScope
    scopes: tuple[str, ...]


def eligible_scopes() -> list[InterfaceScope]:
    return [
        scope
        for scope in connected_scopes()
        if ipaddress.ip_address(scope.local_ip).is_private
        and ipaddress.ip_network(scope.network).num_addresses
        <= MAX_DISCOVERY_ADDRESSES
    ]


def connected_scopes() -> list[InterfaceScope]:
    """Return active IPv4 interfaces before discovery-policy filtering."""
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
            if ip.is_loopback or ip.is_link_local:
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
        raise _scope_error()
    return scopes[0]


def select_connected_scope() -> InterfaceScope:
    scopes = connected_scopes()
    if not scopes:
        raise ScopeError("No active IPv4 network was found")
    return scopes[0]


def discovery_capability() -> DiscoveryCapability:
    scope = select_connected_scope()
    network = ipaddress.ip_network(scope.network, strict=True)
    local_ip = ipaddress.ip_address(scope.local_ip)
    if network.num_addresses <= MAX_DISCOVERY_ADDRESSES:
        options = (str(network),)
        recommended = str(network)
        capability = "ready"
        all_segments_available = False
    else:
        current_segment = str(
            ipaddress.ip_network(f"{local_ip}/24", strict=False)
        )
        segment_count = network.num_addresses // MAX_DISCOVERY_ADDRESSES
        if network.prefixlen >= 24:
            options = (str(network),)
        elif segment_count <= MAX_AUTOMATIC_SEGMENTS:
            options = tuple(str(item) for item in network.subnets(new_prefix=24))
        else:
            options = (current_segment,)
        recommended = current_segment
        capability = "selection_required"
        all_segments_available = 1 < len(options) <= MAX_AUTOMATIC_SEGMENTS
    requires_authorization = not local_ip.is_private
    if requires_authorization:
        capability = "authorization_required"
    return DiscoveryCapability(
        connected_scope=scope,
        scope_options=options,
        recommended_scope=recommended,
        capability=capability,
        requires_authorization=requires_authorization,
        all_segments_available=all_segments_available,
    )


def resolve_discovery_plan(
    requested_scopes: list[str],
    *,
    connected_network: str,
    interface_name: str | None,
    authorization_confirmed: bool,
) -> ResolvedDiscoveryPlan:
    """Bind server-selected scopes to the current locally attached network."""
    if not requested_scopes:
        raise ScopeError("The discovery command did not include a network scope")
    try:
        expected_network = ipaddress.ip_network(connected_network, strict=True)
    except ValueError as exc:
        raise ScopeError("The discovery command contains an invalid network") from exc
    candidates = [
        item
        for item in connected_scopes()
        if item.network == str(expected_network)
        and (interface_name is None or item.interface_name == interface_name)
    ]
    if not candidates:
        raise ScopeError(
            f"Connected network changed; {expected_network} is no longer active",
            code="scope_changed",
        )
    connected = candidates[0]
    resolved: list[str] = []
    for value in requested_scopes:
        try:
            requested = ipaddress.ip_network(value, strict=True)
        except ValueError as exc:
            raise ScopeError(f"Invalid requested discovery scope: {value}") from exc
        if requested.version != 4:
            raise ScopeError("Only IPv4 discovery scopes are supported")
        if requested.num_addresses > MAX_DISCOVERY_ADDRESSES:
            raise ScopeError(
                f"{requested} contains {requested.num_addresses} addresses; "
                f"each discovery segment is limited to {MAX_DISCOVERY_ADDRESSES}",
                code="scope_too_large",
            )
        if not requested.subnet_of(expected_network):
            raise ScopeError(
                f"{requested} is outside connected network {expected_network}",
                code="scope_outside_connected_network",
            )
        if not requested.is_private and not authorization_confirmed:
            raise ScopeError(
                f"{requested} requires explicit public-range authorization",
                code="scope_authorization_required",
            )
        normalized = str(requested)
        if normalized not in resolved:
            resolved.append(normalized)
    return ResolvedDiscoveryPlan(connected, tuple(resolved))


def _scope_error() -> ScopeError:
    stats = psutil.net_if_stats()
    reasons: list[tuple[int, str, str]] = []
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
            if ip.is_loopback or ip.is_link_local:
                continue
            issues: list[str] = []
            code = "scope_unavailable"
            if not ip.is_private:
                issues.append("is not a private IPv4 network")
                code = "scope_not_private"
            if network.num_addresses > MAX_DISCOVERY_ADDRESSES:
                issues.append(
                    f"contains {network.num_addresses} addresses; the limit is "
                    f"{MAX_DISCOVERY_ADDRESSES}"
                )
                if code == "scope_unavailable":
                    code = "scope_too_large"
            if issues:
                is_virtual = any(
                    marker in name.lower() for marker in VIRTUAL_INTERFACE_MARKERS
                )
                reasons.append(
                    (
                        1 if is_virtual else 0,
                        code,
                        f"{name} ({network}) {' and '.join(issues)}",
                    )
                )
    if reasons:
        _virtual, code, message = sorted(reasons)[0]
        return ScopeError(message, code=code)
    return ScopeError(
        "No active private IPv4 network of 256 addresses or fewer was found"
    )
