"""Project bounded discovery and SNMP detail for a durable asset."""

from __future__ import annotations

from forgesec_api.storage import JsonStore

MAX_INTERFACES = 64
SNMP_FIELDS = (
    "snmp_name",
    "snmp_description",
    "snmp_object_id",
    "snmp_uptime_seconds",
    "snmp_interface_count",
)


def _source_device(store: JsonStore, observation: dict) -> dict:
    """Recover fields from older observations without trusting IP-only matches."""
    if "discovery_reason" in observation and "snmp_name" in observation:
        return observation
    discovery = store.read("discoveries", observation["source_id"])
    if not discovery or discovery.get("agent_id") != observation["agent_id"]:
        return observation
    device = next(
        (
            item
            for item in discovery.get("devices", [])
            if item["device_id"] == observation["source_device_id"]
            and item["ip"] == observation["ip"]
        ),
        None,
    )
    return {**(device or {}), **observation}


def build_device_profile(store: JsonStore, asset: dict) -> dict:
    observations = sorted(
        (
            item
            for item in store.list_by_field(
                "asset-observations", "asset_id", asset["asset_id"]
            )
            if item["asset_id"] == asset["asset_id"]
            and item["site_id"] == asset["site_id"]
            and item["source_type"] == "discovery"
        ),
        key=lambda item: item["observed_at"],
        reverse=True,
    )
    if not observations:
        return {"asset_id": asset["asset_id"], "discovery": None, "snmp": None}

    latest_observation = observations[0]
    latest = _source_device(store, latest_observation)
    discovery = {
        "discovery_id": latest_observation["source_id"],
        "observed_at": latest_observation["observed_at"],
        "ip": latest_observation["ip"],
        "hostname": latest.get("hostname"),
        "vendor": latest.get("vendor"),
        "device_type": latest.get("device_type"),
        "classification_confidence": latest.get("classification_confidence"),
        "discovery_reason": latest.get("discovery_reason"),
        "latency_ms": latest.get("latency_ms"),
    }

    management = None
    for observation in observations:
        source = _source_device(store, observation)
        if not any(
            source.get(field) is not None for field in SNMP_FIELDS
        ) and not source.get("snmp_interfaces"):
            continue
        interfaces = source.get("snmp_interfaces") or []
        management = {
            "discovery_id": observation["source_id"],
            "observed_at": observation["observed_at"],
            "ip": observation["ip"],
            "latest_discovery": (
                observation["source_id"] == asset.get("last_discovery_id")
                and observation["ip"] == asset["last_ip"]
            ),
            "name": source.get("snmp_name"),
            "description": source.get("snmp_description"),
            "object_id": source.get("snmp_object_id"),
            "uptime_seconds": source.get("snmp_uptime_seconds"),
            "reported_interface_count": source.get("snmp_interface_count"),
            "interfaces": interfaces[:MAX_INTERFACES],
            "interfaces_limited": bool(source.get("snmp_interfaces_limited"))
            or len(interfaces) > MAX_INTERFACES,
        }
        break
    return {"asset_id": asset["asset_id"], "discovery": discovery, "snmp": management}
