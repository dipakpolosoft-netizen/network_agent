"""Site-scoped LLDP graph from durable discovery observations."""

from __future__ import annotations

import hashlib
from datetime import timedelta

from forgesec_api.assets.service import normalize_mac
from forgesec_api.storage import JsonStore
from forgesec_api.time import parse_timestamp, utc_now

STALE_AFTER = timedelta(days=7)
MAX_LINKS = 1000


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:24]


def _unique_index(pairs: list[tuple[str, str]]) -> tuple[dict[str, str], set[str]]:
    candidates: dict[str, set[str]] = {}
    for key, asset_id in pairs:
        candidates.setdefault(key, set()).add(asset_id)
    return (
        {key: next(iter(ids)) for key, ids in candidates.items() if len(ids) == 1},
        {key for key, ids in candidates.items() if len(ids) > 1},
    )


def _asset_node(asset: dict) -> dict:
    return {
        "id": f"asset:{asset['asset_id']}",
        "asset_id": asset["asset_id"],
        "label": asset.get("display_name") or asset.get("hostname") or asset["last_ip"],
        "ip": asset["last_ip"],
        "device_type": asset.get("device_type"),
        "observed_only": False,
        "last_seen": asset["last_seen"],
    }


def _neighbor_node(site_id: str, reporter_id: str, neighbor: dict) -> dict:
    chassis = neighbor["remote_chassis_id"]
    subtype = neighbor["remote_chassis_subtype"]
    label = neighbor.get("remote_system_name")
    if not label and subtype == 4 and len(chassis) == 12:
        label = ":".join(chassis[index : index + 2] for index in range(0, 12, 2))
    return {
        "id": "neighbor:" + _digest(
            "|".join(
                (
                    site_id,
                    reporter_id,
                    neighbor["local_port"],
                    str(subtype),
                    chassis,
                    neighbor.get("remote_port") or "",
                )
            )
        ),
        "asset_id": None,
        "label": label or "Unresolved LLDP neighbor",
        "ip": None,
        "device_type": None,
        "observed_only": True,
        "last_seen": None,
    }


def build_topology(store: JsonStore, site_id: str, *, include_stale: bool) -> dict:
    assets = {
        asset["asset_id"]: asset
        for asset in store.list_by_field("assets", "site_id", site_id)
        if asset["site_id"] == site_id
    }
    snapshots: dict[str, dict] = {}
    for observation in store.list_by_field("asset-observations", "site_id", site_id):
        asset_id = observation["asset_id"]
        if (
            asset_id not in assets
            or observation.get("source_type") != "discovery"
            or not observation.get("lldp_collected")
        ):
            continue
        previous = snapshots.get(asset_id)
        observed_at = parse_timestamp(observation["observed_at"])
        previous_at = (
            parse_timestamp(previous["observed_at"]) if previous else None
        )
        if (
            previous_at is None
            or observed_at > previous_at
            or (
                observed_at == previous_at
                and observation["source_id"]
                == assets[asset_id].get("last_discovery_id")
            )
        ):
            snapshots[asset_id] = observation

    cutoff = utc_now() - STALE_AFTER
    chassis_index, ambiguous_chassis = _unique_index(
        [
            (
                f"{item['lldp_chassis_subtype']}:{item['lldp_chassis_id']}",
                asset_id,
            )
            for asset_id, item in snapshots.items()
            if item.get("lldp_chassis_subtype") and item.get("lldp_chassis_id")
            and parse_timestamp(item["observed_at"]) >= cutoff
        ]
    )
    mac_index, _ambiguous_macs = _unique_index(
        [
            (mac, asset_id)
            for asset_id, asset in assets.items()
            if (mac := normalize_mac(asset.get("mac")))
            and parse_timestamp(asset["last_seen"]) >= cutoff
        ]
    )
    nodes: dict[str, dict] = {}
    links: dict[str, dict] = {}
    stale_hidden = 0
    latest = None
    for asset_id, observation in snapshots.items():
        observed_at = observation["observed_at"]
        latest = max(latest, observed_at) if latest else observed_at
        stale = parse_timestamp(observed_at) < cutoff
        for neighbor in observation.get("lldp_neighbors", []):
            if stale and not include_stale:
                stale_hidden += 1
                continue
            subtype = neighbor["remote_chassis_subtype"]
            chassis = neighbor["remote_chassis_id"]
            chassis_key = f"{subtype}:{chassis}"
            remote_id = chassis_index.get(chassis_key)
            match_method = "chassis_id" if remote_id else "unresolved"
            if (
                remote_id is None
                and chassis_key not in ambiguous_chassis
                and subtype == 4
                and len(chassis) == 12
            ):
                mac = normalize_mac(
                    ":".join(chassis[index : index + 2] for index in range(0, 12, 2))
                )
                remote_id = mac_index.get(mac) if mac else None
                if remote_id:
                    match_method = "mac"
            if remote_id == asset_id:
                remote_id = None
                match_method = "unresolved"
            source = _asset_node(assets[asset_id])
            target = (
                _asset_node(assets[remote_id])
                if remote_id
                else _neighbor_node(site_id, asset_id, neighbor)
            )
            nodes[source["id"]] = source
            nodes[target["id"]] = target
            link_id = _digest(
                "|".join(
                    (
                        observation["observation_id"],
                        neighbor["local_port"],
                        str(subtype),
                        chassis,
                        neighbor.get("remote_port") or "",
                    )
                )
            )
            links[link_id] = {
                "id": link_id,
                "source": source["id"],
                "target": target["id"],
                "reported_by": asset_id,
                "probe_id": observation["agent_id"],
                "local_port": neighbor["local_port"],
                "remote_port": neighbor.get("remote_port"),
                "remote_system_name": neighbor.get("remote_system_name"),
                "match_method": match_method,
                "discovery_id": observation["source_id"],
                "observed_at": observed_at,
                "stale": stale,
            }
    ordered_links = sorted(
        links.values(), key=lambda link: (link["observed_at"], link["id"]), reverse=True
    )
    visible_links = ordered_links[:MAX_LINKS]
    visible_nodes = {
        endpoint
        for link in visible_links
        for endpoint in (link["source"], link["target"])
    }
    return {
        "site_id": site_id,
        "nodes": sorted(
            (node for node_id, node in nodes.items() if node_id in visible_nodes),
            key=lambda node: (node["observed_only"], node["label"].casefold()),
        ),
        "links": visible_links,
        "probes": [
            {
                "agent_id": agent["agent_id"],
                "label": agent["label"],
                "hostname": agent["hostname"],
                "ip": agent.get("local_ip"),
                "subnet": agent.get("subnet"),
                "os_name": agent["os_name"],
                "agent_version": agent["agent_version"],
                "last_heartbeat_at": agent.get("last_heartbeat_at"),
            }
            for agent in store.list_by_field("agents", "site_id", site_id)
            if agent.get("site_id") == site_id
            and agent.get("last_heartbeat_at")
            and not agent.get("revoked_at")
        ],
        "observed_assets": len(snapshots),
        "unlinked_assets": len(assets)
        - len({node["asset_id"] for node in nodes.values() if node["asset_id"]}),
        "stale_hidden": stale_hidden,
        "total_links": len(ordered_links),
        "truncated": len(ordered_links) > MAX_LINKS,
        "latest_observed_at": latest,
    }
