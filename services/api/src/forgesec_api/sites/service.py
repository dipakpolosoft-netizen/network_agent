"""Persist site ownership and enforce explicitly approved network ranges."""

from __future__ import annotations

import ipaddress
from uuid import uuid4

from forgesec_api.activity import record_activity
from forgesec_api.sites.models import ScopeCreate, SiteCreate
from forgesec_api.storage import JsonStore
from forgesec_api.time import isoformat, utc_now


class SiteNotFound(ValueError):
    pass


class InvalidScope(ValueError):
    pass


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
        with self.store.locked():
            if any(item["cidr"] == str(network) for item in self.list_scopes(site_id)):
                raise InvalidScope("This network is already approved for the site")
            record = {
                "scope_id": str(uuid4()),
                "site_id": site_id,
                "cidr": str(network),
                "label": payload.label.strip(),
                "description": payload.description.strip()
                if payload.description
                else None,
                "exclusions": list(dict.fromkeys(str(item) for item in exclusions)),
                "scan_profiles": list(dict.fromkeys(payload.scan_profiles)),
                "created_at": isoformat(utc_now()),
            }
            self.store.write("approved-scopes", record["scope_id"], record)
            record_activity(
                self.store,
                event_type="scope.approved",
                message=f"Approved {network}",
                resource_type="site",
                resource_id=site_id,
                details={"scope_id": record["scope_id"]},
            )
            return record

    def list_scopes(self, site_id: str) -> list[dict]:
        self.get(site_id)
        return [
            item
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
            details={"scope_id": scope_id},
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
        scopes = self.list_scopes(site_id)
        if any(
            address_or_network.overlaps(ipaddress.ip_network(excluded))
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
        return self.list_scopes(site_id) if site_id else []

    def command_allowed(self, site_id: str | None, command: dict) -> bool:
        payload = command.get("payload") or {}
        kind = command.get("command_type")
        if kind == "discover_network":
            return bool(payload.get("scopes")) and all(
                self.approved(site_id, item) for item in payload["scopes"]
            )
        if kind == "scan_devices":
            return bool(payload.get("targets")) and all(
                self.approved(site_id, item["ip"], payload.get("profile"))
                for item in payload["targets"]
            )
        if kind == "device_diagnostic":
            return self.approved(site_id, payload.get("target_ip", ""))
        return kind == "health_check"

    def migrate_legacy_agents(self) -> None:
        for agent in self.store.list("agents"):
            if agent.get("site_id"):
                continue
            site = self.get_or_create(agent.get("site_name") or "Local Site")
            agent["site_id"] = site["site_id"]
            agent["site_name"] = site["name"]
            self.store.write("agents", agent["agent_id"], agent)
