"""Merge validated probe evidence into durable, site-scoped asset records."""

from __future__ import annotations

import hashlib
import json
import re
from uuid import uuid4

from forgesec_api.activity import record_activity
from forgesec_api.assets.models import AssetPatch
from forgesec_api.storage import JsonStore
from forgesec_api.time import isoformat, parse_timestamp, utc_now

MAC_HEX = re.compile(r"^[0-9a-fA-F:-]+$")
PORT_SAMPLE_LIMIT = 32
IP_HISTORY_LIMIT = 32


class AssetNotFound(RuntimeError):
    pass


def normalize_mac(value: str | None) -> str | None:
    if not value or not MAC_HEX.fullmatch(value):
        return None
    digits = value.replace(":", "").replace("-", "").lower()
    if len(digits) != 12:
        return None
    if digits == "0" * 12 or int(digits[:2], 16) & 1:
        return None
    return ":".join(digits[index : index + 2] for index in range(0, 12, 2))


def merge_role(asset: dict, device_type: str | None, confidence: float | None) -> None:
    if not device_type or device_type == "unknown":
        return
    existing_type = asset.get("device_type")
    existing_confidence = asset.get("classification_confidence") or 0.0
    incoming_confidence = confidence or 0.0
    if (
        existing_type not in {None, "unknown", device_type}
        and incoming_confidence <= existing_confidence
    ):
        return
    asset["device_type"] = device_type
    asset["classification_confidence"] = (
        max(existing_confidence, incoming_confidence)
        if existing_type == device_type
        else confidence
    )


class AssetService:
    def __init__(self, store: JsonStore):
        self.store = store

    @staticmethod
    def _index_key(site_id: str, value: str) -> str:
        return hashlib.sha256(f"{site_id}|{value}".encode()).hexdigest()

    @staticmethod
    def _observation_key(kind: str, source_id: str, device_id: str) -> str:
        return hashlib.sha256(f"{kind}|{source_id}|{device_id}".encode()).hexdigest()

    def _resolve(self, site_id: str, ip: str, mac: str | None) -> dict | None:
        if mac:
            index = self.store.read("asset-mac-index", self._index_key(site_id, mac))
            if index:
                asset = self.store.read("assets", index["asset_id"])
                if asset:
                    return asset
        index = self.store.read("asset-ip-index", self._index_key(site_id, ip))
        if index:
            asset = self.store.read("assets", index["asset_id"])
            if asset and (not mac or asset["mac"] in {None, mac}):
                return asset
        return None

    def _observe(
        self,
        *,
        site_id: str,
        agent_id: str,
        source_type: str,
        source_id: str,
        device: dict,
        observed_at: str,
        result: dict | None = None,
    ) -> str | None:
        device_id = device["device_id"]
        observation_id = self._observation_key(source_type, source_id, device_id)
        with self.store.locked():
            existing = self.store.read("asset-observations", observation_id)
            if existing:
                return existing["asset_id"]
            ip = device["ip"]
            mac = normalize_mac(device.get("mac"))
            asset = self._resolve(site_id, ip, mac)
            now = isoformat(utc_now())
            positive = result is None or result["status"] in {"completed", "partial"}
            if asset is None and not positive:
                return None
            if asset is None:
                asset = {
                    "asset_id": str(uuid4()),
                    "site_id": site_id,
                    "display_name": None,
                    "owner": None,
                    "criticality": "medium",
                    "tags": [],
                    "hostname": None,
                    "mac": None,
                    "last_ip": ip,
                    "ip_history": [],
                    "vendor": None,
                    "device_type": None,
                    "classification_confidence": None,
                    "os_name": None,
                    "os_accuracy": None,
                    "open_port_count": 0,
                    "ports": [],
                    "first_seen": observed_at,
                    "last_seen": observed_at,
                    "last_discovery_at": None,
                    "last_scan_at": None,
                    "last_discovery_id": None,
                    "last_scan_id": None,
                    "last_scan_status": None,
                    "port_snapshot_scan_id": None,
                    "port_snapshot_at": None,
                    "port_snapshot_ip": None,
                    "observation_count": 0,
                    "scan_count": 0,
                    "created_at": now,
                    "updated_at": now,
                }
            elif (
                "port_snapshot_at" not in asset
                and asset.get("last_scan_status") == "completed"
            ):
                asset["port_snapshot_scan_id"] = asset.get("last_scan_id")
                asset["port_snapshot_at"] = asset.get("last_scan_at")
                asset["port_snapshot_ip"] = asset.get("last_ip")
            previous_ip = asset["last_ip"]
            newer = parse_timestamp(observed_at) >= parse_timestamp(asset["last_seen"])
            if positive:
                if parse_timestamp(observed_at) < parse_timestamp(asset["first_seen"]):
                    asset["first_seen"] = observed_at
                if newer:
                    asset["last_seen"] = observed_at
                    asset["last_ip"] = ip
                    if device.get("hostname"):
                        asset["hostname"] = device["hostname"]
                    if device.get("vendor"):
                        asset["vendor"] = device["vendor"]
                    merge_role(
                        asset,
                        device.get("device_type"),
                        device.get("classification_confidence"),
                    )
                if ip not in asset["ip_history"]:
                    asset["ip_history"] = [*asset["ip_history"], ip][-IP_HISTORY_LIMIT:]
            if mac and not asset["mac"]:
                asset["mac"] = mac
            if source_type == "discovery":
                if not asset["last_discovery_at"] or parse_timestamp(
                    observed_at
                ) >= parse_timestamp(asset["last_discovery_at"]):
                    asset["last_discovery_at"] = observed_at
                    asset["last_discovery_id"] = source_id
            else:
                asset["scan_count"] += 1
                if not asset["last_scan_at"] or parse_timestamp(
                    observed_at
                ) >= parse_timestamp(asset["last_scan_at"]):
                    asset["last_scan_at"] = observed_at
                    asset["last_scan_id"] = source_id
                    asset["last_scan_status"] = result["status"]
                if result["status"] == "completed" and (
                    not asset.get("port_snapshot_at")
                    or parse_timestamp(observed_at)
                    >= parse_timestamp(asset["port_snapshot_at"])
                ):
                    ports = [
                        port for port in result.get("ports", [])
                        if port["state"] == "open"
                    ]
                    asset["open_port_count"] = len(ports)
                    sampled_ports = ports[:PORT_SAMPLE_LIMIT]
                    ssh_port = next(
                        (
                            port for port in ports
                            if port["protocol"] == "tcp" and port["port"] == 22
                        ),
                        None,
                    )
                    if ssh_port is not None and ssh_port not in sampled_ports:
                        sampled_ports[-1] = ssh_port
                    asset["ports"] = [
                        {
                            key: port.get(key)
                            for key in (
                                "protocol", "port", "service", "product", "version"
                            )
                        }
                        for port in sampled_ports
                    ]
                    asset["port_snapshot_scan_id"] = source_id
                    asset["port_snapshot_at"] = observed_at
                    asset["port_snapshot_ip"] = ip
                    matches = result.get("os_matches") or []
                    if matches:
                        best = max(matches, key=lambda item: item["accuracy"])
                        asset["os_name"] = best["name"]
                        asset["os_accuracy"] = best["accuracy"]
                    if newer and result.get("hostname"):
                        asset["hostname"] = result["hostname"]
                    if newer:
                        merge_role(
                            asset,
                            result.get("device_type"),
                            result.get("classification_confidence"),
                        )
            asset["observation_count"] += 1
            asset["updated_at"] = now
            self.store.write("assets", asset["asset_id"], asset)
            if mac:
                self.store.write(
                    "asset-mac-index",
                    self._index_key(site_id, mac),
                    {"asset_id": asset["asset_id"]},
                )
            if positive and newer:
                if previous_ip != ip and mac:
                    old_key = self._index_key(site_id, previous_ip)
                    old_index = self.store.read("asset-ip-index", old_key)
                    if old_index and old_index["asset_id"] == asset["asset_id"]:
                        self.store.delete("asset-ip-index", old_key)
                self.store.write(
                    "asset-ip-index",
                    self._index_key(site_id, ip),
                    {"asset_id": asset["asset_id"]},
                )
            observation = {
                "observation_id": observation_id,
                "asset_id": asset["asset_id"],
                "site_id": site_id,
                "source_type": source_type,
                "source_id": source_id,
                "source_device_id": device_id,
                "agent_id": agent_id,
                "observed_at": observed_at,
                "ip": ip,
                "mac": mac,
                "hostname": (
                    result.get("hostname") if result else device.get("hostname")
                ),
                "device_type": (
                    result.get("device_type") if result else device.get("device_type")
                ),
                "status": result["status"] if result else device.get("status", "up"),
                "open_port_count": (
                    sum(port["state"] == "open" for port in result.get("ports", []))
                    if result and result["status"] == "completed"
                    else None
                ),
                "vendor": device.get("vendor") if result is None else None,
                "classification_confidence": (
                    device.get("classification_confidence") if result is None else None
                ),
                "discovery_reason": (
                    device.get("discovery_reason") if result is None else None
                ),
                "latency_ms": device.get("latency_ms") if result is None else None,
                "snmp_name": device.get("snmp_name") if result is None else None,
                "snmp_description": (
                    device.get("snmp_description") if result is None else None
                ),
                "snmp_object_id": (
                    device.get("snmp_object_id") if result is None else None
                ),
                "snmp_uptime_seconds": (
                    device.get("snmp_uptime_seconds") if result is None else None
                ),
                "snmp_interface_count": (
                    device.get("snmp_interface_count") if result is None else None
                ),
                "snmp_interfaces": (
                    device.get("snmp_interfaces", [])[:64] if result is None else []
                ),
                "snmp_interfaces_limited": (
                    len(device.get("snmp_interfaces", [])) > 64
                    if result is None
                    else False
                ),
                "lldp_collected": (
                    bool(device.get("lldp_collected")) if result is None else False
                ),
                "lldp_chassis_subtype": (
                    device.get("lldp_chassis_subtype") if result is None else None
                ),
                "lldp_chassis_id": (
                    device.get("lldp_chassis_id") if result is None else None
                ),
                "lldp_neighbors": (
                    device.get("lldp_neighbors", []) if result is None else []
                ),
            }
            self.store.write("asset-observations", observation_id, observation)
            return asset["asset_id"]

    def observe_discovery(self, discovery: dict) -> None:
        site_id = discovery.get("site_id")
        if not site_id:
            return
        observed_at = discovery.get("completed_at") or discovery["created_at"]
        for device in discovery.get("devices", []):
            if device.get("is_agent"):
                continue
            self._observe(
                site_id=site_id,
                agent_id=discovery["agent_id"],
                source_type="discovery",
                source_id=discovery["discovery_id"],
                device=device,
                observed_at=observed_at,
            )

    def observe_scan(self, scan: dict, result: dict) -> None:
        site_id = scan.get("site_id")
        if not site_id:
            return
        discovery = self.store.read("discoveries", scan["discovery_id"])
        if (
            not discovery
            or discovery.get("site_id") != site_id
            or discovery.get("agent_id") != scan["agent_id"]
        ):
            return
        device = next(
            (
                item
                for item in (discovery or {}).get("devices", [])
                if item["device_id"] == result["device_id"]
            ),
            None,
        )
        if device is None:
            device = next(
                (
                    item
                    for item in scan["targets"]
                    if item["device_id"] == result["device_id"]
                ),
                None,
            )
        if device is None:
            return
        self._observe(
            site_id=site_id,
            agent_id=scan["agent_id"],
            source_type="scan",
            source_id=scan["scan_id"],
            device=device,
            observed_at=result.get("completed_at") or result["started_at"],
            result=result,
        )

    def backfill(self) -> None:
        if self.store.exists("asset-migrations", "v1"):
            return
        for discovery in sorted(
            self.store.list("discoveries"), key=lambda item: item["created_at"]
        ):
            self.observe_discovery(discovery)
        for scan in sorted(
            self.store.list("scans"), key=lambda item: item["created_at"]
        ):
            for result in scan.get("results", []):
                self.observe_scan(scan, result)
        self.store.write(
            "asset-migrations", "v1", {"completed_at": isoformat(utc_now())}
        )

    def list_assets(
        self, *, site_id: str | None, query: str, limit: int, offset: int
    ) -> dict:
        return self.store.page_assets(
            site_id=site_id, query=query, limit=limit, offset=offset
        )

    def get(self, asset_id: str) -> dict:
        asset = self.store.read("assets", asset_id)
        if asset is None:
            raise AssetNotFound
        return asset

    def observations(self, asset_id: str, *, limit: int, offset: int) -> list[dict]:
        asset = self.get(asset_id)
        items = self.store.list_by_field("asset-observations", "asset_id", asset_id)
        items.sort(key=lambda item: (item["observed_at"], item["observation_id"]))
        previous: dict[tuple[str, str, str, str], tuple[str, dict]] = {}
        enriched: list[dict] = []
        for item in items:
            entry = dict(item)
            if item["source_type"] != "scan":
                enriched.append(entry)
                continue
            scan = self.store.read("scans", item["source_id"])
            if (
                not scan
                or scan.get("site_id") != asset["site_id"]
                or scan.get("agent_id") != item["agent_id"]
            ):
                enriched.append(entry)
                continue
            entry["scan_profile"] = scan.get("profile")
            result = next(
                (
                    result for result in scan.get("results", [])
                    if result["device_id"] == item["source_device_id"]
                    and result["ip"] == item["ip"]
                ),
                None,
            )
            if not result or result.get("status") != "completed":
                enriched.append(entry)
                continue
            plan = scan.get("profile_plan")
            if not isinstance(plan, dict) or not plan:
                enriched.append(entry)
                continue
            ports = {
                (port["protocol"], port["port"]): {
                    "protocol": port["protocol"],
                    "port": port["port"],
                    "service": port.get("service"),
                }
                for port in result.get("ports", [])
                if port.get("state") == "open"
            }
            signature = (
                item["agent_id"],
                item["ip"],
                scan["profile"],
                json.dumps(plan, sort_keys=True),
            )
            baseline = previous.get(signature)
            if baseline:
                baseline_id, old_ports = baseline
                opened = sorted(ports.keys() - old_ports.keys())
                no_longer = sorted(old_ports.keys() - ports.keys())
                entry["port_delta"] = {
                    "baseline_scan_id": baseline_id,
                    "opened_count": len(opened),
                    "no_longer_confirmed_count": len(no_longer),
                    "opened_ports": [ports[key] for key in opened[:32]],
                    "no_longer_confirmed_ports": [
                        old_ports[key] for key in no_longer[:32]
                    ],
                }
            previous[signature] = (scan["scan_id"], ports)
            enriched.append(entry)
        enriched.reverse()
        return enriched[offset : offset + limit]

    def update(
        self, asset_id: str, payload: AssetPatch, *, actor_id: str | None
    ) -> dict:
        with self.store.locked():
            asset = self.get(asset_id)
            changes = payload.model_dump(exclude_unset=True)
            if "criticality" in changes and changes["criticality"] is None:
                changes["criticality"] = "medium"
            for key in ("display_name", "owner"):
                if key in changes and not changes[key]:
                    changes[key] = None
            if "tags" in changes and changes["tags"] is None:
                changes["tags"] = []
            asset.update(changes)
            asset["updated_at"] = isoformat(utc_now())
            self.store.write("assets", asset_id, asset)
            record_activity(
                self.store,
                event_type="asset.updated",
                message="Asset annotations updated",
                actor_type="user",
                actor_id=actor_id,
                resource_type="asset",
                resource_id=asset_id,
                details={"fields": list(changes)},
            )
            return asset
