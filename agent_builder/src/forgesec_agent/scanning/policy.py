"""Reject commands outside the site policy supplied by the control plane."""

from __future__ import annotations

import ipaddress
from datetime import UTC, date, datetime


def _active(entry: dict) -> bool:
    try:
        expires = date.fromisoformat(entry["expires_on"])
        network = ipaddress.ip_network(entry["cidr"], strict=True)
    except (KeyError, TypeError, ValueError):
        return False
    return bool(
        entry.get("authorization_confirmed") is True
        and all(
            isinstance(entry.get(key), str)
            and bool(entry[key].strip())
            and not entry[key].strip().upper().startswith(
                ("ACTUAL_", "ANOTHER_ACTUAL_")
            )
            for key in ("owner", "approval_reference", "approved_by")
        )
        and (network.is_private or entry.get("public_range_authorized") is True)
        and expires >= datetime.now(UTC).date()
    )


def require_approved(
    policy: object, targets: list[str], profile: str | None = None
) -> None:
    if not isinstance(policy, list) or not policy:
        raise ValueError("No approved site scope was supplied")
    policy = [entry for entry in policy if isinstance(entry, dict) and _active(entry)]
    if not policy:
        raise ValueError("Site approval is missing or expired")
    for target in targets:
        try:
            requested = ipaddress.ip_network(target, strict=True)
        except ValueError as exc:
            raise ValueError("Invalid scan target") from exc
        if requested.version != 4:
            raise ValueError("Only IPv4 scan targets are supported")
        if any(
            requested.subnet_of(ipaddress.ip_network(excluded))
            for entry in policy
            for excluded in entry.get("exclusions", [])
        ):
            raise ValueError(f"{requested} overlaps an excluded network")
        if not any(
            requested.subnet_of(ipaddress.ip_network(entry["cidr"]))
            and (profile is None or profile in entry.get("scan_profiles", []))
            for entry in policy
        ):
            raise ValueError(f"{requested} is outside approved site scope")


def exclusions_for_scope(policy: list[dict], scope: str) -> list[str]:
    network = ipaddress.ip_network(scope, strict=True)
    return list(
        dict.fromkeys(
            excluded
            for entry in policy
            for excluded in entry.get("exclusions", [])
            if ipaddress.ip_network(excluded, strict=True).overlaps(network)
        )
    )
