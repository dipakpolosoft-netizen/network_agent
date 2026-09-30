"""Persist site ownership and enforce explicitly approved network ranges."""

from __future__ import annotations

import ipaddress
from datetime import date
from uuid import uuid4

from forgesec_api.activity import record_activity
from forgesec_api.sites.models import ScopeCreate, SiteCreate
from forgesec_api.storage import JsonStore
from forgesec_api.time import isoformat, utc_now


class SiteNotFound(ValueError):
    pass


class InvalidScope(ValueError):
    pass


DIAGNOSTIC_SCAN_PROFILES = {
    "inventory_nmap": "inventory",
    "network_services_nmap": "network_services",
    "standard_nmap": "standard",
    "full_tcp_nmap": "full_tcp",
}


def _real_approval_text(value: object) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    return not value.strip().upper().startswith(("ACTUAL_", "ANOTHER_ACTUAL_"))


class SiteService:
    def __init__(self, store: JsonStore):
        self.store = store

    def create(self, payload: SiteCreate) -> dict:
        name = payload.name.strip()
        if not name:
            raise ValueError("Site name is required")
        with self.store.locked():
            for site in self.store.list("sites"):
                if site["name"].casefold() == name.casefold():
                    raise ValueError("A site with this name already exists")
            record = {
                "site_id": str(uuid4()),
                "name": name,
                "owner": payload.owner.strip() if payload.owner else None,
                "description": payload.description.strip()
                if payload.description
                else None,
                "created_at": isoformat(utc_now()),
            }
            self.store.write("sites", record["site_id"], record)
            return record

    def get_or_create(self, name: str) -> dict:
        with self.store.locked():
            for site in self.store.list("sites"):
                if site["name"].casefold() == name.strip().casefold():
                    return site
            return self.create(SiteCreate(name=name))

    def get(self, site_id: str) -> dict:
        record = self.store.read("sites", site_id)
        if record is None:
            raise SiteNotFound("Site not found")
        return record

    def list(self) -> list[dict]:
        return sorted(
            self.store.list("sites"), key=lambda item: item["name"].casefold()
        )

    def add_scope(self, site_id: str, payload: ScopeCreate) -> dict:
        self.get(site_id)
        try:
            network = ipaddress.ip_network(payload.cidr, strict=True)
            exclusions = [
                ipaddress.ip_network(item, strict=True) for item in payload.exclusions
            ]
        except ValueError as exc:
            raise InvalidScope(
                "Use canonical CIDR notation for the network and exclusions"
            ) from exc
        if (
            network.version != 4
            or network.is_multicast
            or network.is_loopback
            or network.is_link_local
        ):
            raise InvalidScope("Only routable IPv4 scopes are supported")
        if any(item.version != 4 or not item.subnet_of(network) for item in exclusions):
            raise InvalidScope("Every exclusion must be inside the approved network")
        if not payload.scan_profiles:
            raise InvalidScope("Select at least one scan profile")
        if not payload.label.strip():
            raise InvalidScope("Scope label is required")
        for label, value in (
            ("Owner", payload.owner),
            ("Approval reference", payload.approval_reference),
            ("Approver", payload.approved_by),
        ):
            if not _real_approval_text(value):
                raise InvalidScope(f"{label} must contain real authorization details")
        if payload.expires_on < utc_now().date():
            raise InvalidScope("Approval expiry has passed")
        if not network.is_private and not payload.public_range_authorized:
            raise InvalidScope("This public-range network needs explicit authorization")
        with self.store.locked():
            existing = next(
                (
                    item
                    for item in self.list_scopes(site_id)
                    if item["cidr"] == str(network)
                ),
                None,
            )
            if existing and self.scope_status(existing) == "active":
                raise InvalidScope("This network is already approved for the site")
            now = isoformat(utc_now())
            record = {
                "scope_id": existing["scope_id"] if existing else str(uuid4()),
                "site_id": site_id,
                "cidr": str(network),
                "label": payload.label.strip(),
                "description": payload.description.strip()
                if payload.description
                else None,
                "exclusions": list(dict.fromkeys(str(item) for item in exclusions)),
                "scan_profiles": list(dict.fromkeys(payload.scan_profiles)),
                "owner": payload.owner.strip(),
                "approval_reference": payload.approval_reference.strip(),
                "approved_by": payload.approved_by.strip(),
                "expires_on": payload.expires_on.isoformat(),
                "authorization_confirmed": True,
                "public_range_authorized": payload.public_range_authorized,
                "created_at": existing["created_at"] if existing else now,
                "approved_at": now,
            }
            self.store.write("approved-scopes", record["scope_id"], record)
            record_activity(
                self.store,
                event_type="scope.renewed" if existing else "scope.approved",
                message=(
                    f"Renewed approval for {network}"
                    if existing else f"Approved {network}"
                ),
                resource_type="site",
                resource_id=site_id,
                details={
                    "scope_id": record["scope_id"],
                    "owner": record["owner"],
                    "approval_reference": record["approval_reference"],
                    "approved_by": record["approved_by"],
                    "expires_on": record["expires_on"],
                    "scan_profiles": record["scan_profiles"],
                    "exclusions": record["exclusions"],
                    "public_range_authorized": record["public_range_authorized"],
                },
            )
            return self._public_scope(record)

    @staticmethod
    def scope_status(scope: dict) -> str:
        required = ("owner", "approval_reference", "approved_by", "expires_on")
        if scope.get("authorization_confirmed") is not True or any(
            not _real_approval_text(scope.get(key)) for key in required
        ):
            return "needs_review"
        try:
            expires = date.fromisoformat(scope["expires_on"])
            network = ipaddress.ip_network(scope["cidr"], strict=True)
        except (TypeError, ValueError):
            return "needs_review"
        if not network.is_private and scope.get("public_range_authorized") is not True:
            return "needs_review"
        return "expired" if expires < utc_now().date() else "active"

    def _public_scope(self, scope: dict) -> dict:
        return scope | {"approval_status": self.scope_status(scope)}

    def list_scopes(self, site_id: str) -> list[dict]:
        self.get(site_id)
        return [
            self._public_scope(item)
            for item in self.store.list_by_field("approved-scopes", "site_id", site_id)
            if item["site_id"] == site_id
        ]

    def remove_scope(self, site_id: str, scope_id: str) -> None:
        scope = self.store.read("approved-scopes", scope_id)
        if scope is None or scope["site_id"] != site_id:
            raise SiteNotFound("Approved scope not found")
        self.store.delete("approved-scopes", scope_id)
        record_activity(
            self.store,
            event_type="scope.removed",
            message=f"Removed approval for {scope['cidr']}",
            resource_type="site",
            resource_id=site_id,
            details={
                "scope_id": scope_id,
                "owner": scope.get("owner"),
                "approval_reference": scope.get("approval_reference"),
                "approved_by": scope.get("approved_by"),
                "expires_on": scope.get("expires_on"),
            },
        )

    def approved(
        self, site_id: str | None, target: str, profile: str | None = None
    ) -> bool:
        if not site_id:
            return False
        try:
            address_or_network = ipaddress.ip_network(target, strict=True)
        except ValueError:
            return False
        if address_or_network.version != 4:
            return False
        scopes = self.policy(site_id)
        if any(
            address_or_network.subnet_of(ipaddress.ip_network(excluded))
            for scope in scopes
            for excluded in scope["exclusions"]
        ):
            return False
        for scope in scopes:
            network = ipaddress.ip_network(scope["cidr"])
            if not address_or_network.subnet_of(network):
                continue
            if profile and profile not in scope["scan_profiles"]:
                continue
            return True
        return False

    def policy(self, site_id: str | None) -> list[dict]:
        return (
            [
                scope
                for scope in self.list_scopes(site_id)
                if scope["approval_status"] == "active"
            ]
            if site_id
            else []
        )

    def command_allowed(self, site_id: str | None, command: dict) -> bool:
        payload = command.get("payload") or {}
        kind = command.get("command_type")
        if kind == "discover_network":
            return (
                bool(payload.get("scopes"))
                and all(self.approved(site_id, item) for item in payload["scopes"])
                and all(
                    self.approved(site_id, item)
                    for item in payload.get("known_targets", [])
                )
            )
        if kind == "scan_devices":
            return bool(payload.get("targets")) and all(
                self.approved(site_id, item["ip"], payload.get("profile"))
                for item in payload["targets"]
            )
        if kind == "device_diagnostic":
            diagnostic_type = payload.get("diagnostic_type")
            if (
                diagnostic_type == "full_tcp_nmap"
                and payload.get("full_tcp_confirmed") is not True
            ):
                return False
            return self.approved(
                site_id,
                payload.get("target_ip", ""),
                DIAGNOSTIC_SCAN_PROFILES.get(diagnostic_type),
            )
        return kind == "health_check"

    def migrate_legacy_agents(self) -> None:
        for agent in self.store.list("agents"):
            if agent.get("site_id"):
                continue
            site = self.get_or_create(agent.get("site_name") or "Local Site")
            agent["site_id"] = site["site_id"]
            agent["site_name"] = site["name"]
            self.store.write("agents", agent["agent_id"], agent)
