"""Reject commands outside the site policy supplied by the control plane."""

from __future__ import annotations

import ipaddress


def require_approved(
    policy: object, targets: list[str], profile: str | None = None
) -> None:
    if not isinstance(policy, list) or not policy:
        raise ValueError("No approved site scope was supplied")
    for target in targets:
        try:
            requested = ipaddress.ip_network(target, strict=True)
        except ValueError as exc:
            raise ValueError("Invalid scan target") from exc
        if requested.version != 4:
            raise ValueError("Only IPv4 scan targets are supported")
        if any(
            requested.overlaps(ipaddress.ip_network(excluded))
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
