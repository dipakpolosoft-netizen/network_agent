"""Synthetic scope policy for agent tests only."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta


def approved_policy(cidr: str, **overrides: object) -> dict:
    return {
        "cidr": cidr,
        "exclusions": [],
        "scan_profiles": ["inventory", "network_services", "standard", "full_tcp"],
        "owner": "Test network owner",
        "approval_reference": "TEST-AUTH-001",
        "approved_by": "Test approver",
        "expires_on": (datetime.now(UTC).date() + timedelta(days=30)).isoformat(),
        "authorization_confirmed": True,
        "public_range_authorized": not ipaddress.ip_network(cidr).is_private,
        **overrides,
    }
