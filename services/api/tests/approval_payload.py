"""Synthetic authorization records for API tests only."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta


def approved_scope(cidr: str, label: str, **overrides: object) -> dict:
    network = ipaddress.ip_network(cidr, strict=True)
    return {
        "cidr": cidr,
        "label": label,
        "owner": "Test network owner",
        "approval_reference": "TEST-AUTH-001",
        "approved_by": "Test approver",
        "expires_on": (datetime.now(UTC).date() + timedelta(days=30)).isoformat(),
        "authorization_confirmed": True,
        "public_range_authorized": not network.is_private,
        **overrides,
    }
