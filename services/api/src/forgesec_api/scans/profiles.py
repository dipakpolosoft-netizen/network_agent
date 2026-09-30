"""Immutable requested-port plans stored with each new scan."""

from __future__ import annotations

from copy import deepcopy

NETWORK_TCP_PORTS = (22, 53, 80, 443, 445, 3389, 8080, 8443)
NETWORK_UDP_PORTS = (53, 67, 69, 123, 137, 161, 500, 4500, 5353, 1900)

PROFILE_PLANS = {
    "inventory": {
        "tcp_top_ports": 200,
        "tcp_all_ports": False,
        "tcp_ports": [],
        "udp_ports": [],
        "version_detection": "light",
        "os_detection": "when_privileged",
        "host_timeout_seconds": 480,
        "assume_host_up": True,
        "open_only_output": True,
    },
    "network_services": {
        "tcp_top_ports": None,
        "tcp_all_ports": False,
        "tcp_ports": list(NETWORK_TCP_PORTS),
        "udp_ports": list(NETWORK_UDP_PORTS),
        "version_detection": "light",
        "os_detection": "not_requested",
        "host_timeout_seconds": 720,
        "assume_host_up": True,
        "open_only_output": True,
    },
    "standard": {
        "tcp_top_ports": 1000,
        "tcp_all_ports": False,
        "tcp_ports": [],
        "udp_ports": [],
        "version_detection": "light",
        "os_detection": "when_privileged",
        "host_timeout_seconds": 900,
        "assume_host_up": True,
        "open_only_output": True,
    },
    "full_tcp": {
        "tcp_top_ports": None,
        "tcp_all_ports": True,
        "tcp_ports": [],
        "udp_ports": [],
        "version_detection": "full",
        "os_detection": "when_privileged",
        "host_timeout_seconds": 2700,
        "assume_host_up": True,
        "open_only_output": True,
    },
}


def profile_plan(profile: str) -> dict:
    return deepcopy(PROFILE_PLANS[profile])
