"""Discovery lifecycle and uploaded-device validation."""

from __future__ import annotations

import ipaddress
from uuid import uuid4

from forgesec_api.activity import record_activity
from forgesec_api.agents.service import AgentNotFound, AgentService
from forgesec_api.assets.service import AssetService
from forgesec_api.commands.models import CommandEvent
from forgesec_api.commands.service import CommandNotFound, CommandService
from forgesec_api.discoveries.models import DiscoveryResult
from forgesec_api.settings import Settings
from forgesec_api.sites.service import SiteService
from forgesec_api.storage import JsonStore
from forgesec_api.time import isoformat, utc_now


class DiscoveryError(RuntimeError):
    pass


class DiscoveryNotFound(DiscoveryError):
    pass


class DiscoveryOwnershipError(DiscoveryError):
    pass


class InvalidDiscoveryResult(DiscoveryError):
    pass


class AgentOffline(DiscoveryError):
    pass


class ScannerUnavailable(DiscoveryError):
    pass


class DiscoveryInProgress(DiscoveryError):
    pass


class InvalidDiscoveryScope(DiscoveryError):
    pass


ACTIVE_STATUSES = {"queued", "running", "cancelling"}
TERMINAL_STATUSES = {"completed", "partial", "failed", "cancelled"}
MAX_EVENTS = 40


class DiscoveryService:
    def __init__(
        self,
        store: JsonStore,
        settings: Settings,
        agents: AgentService,
        commands: CommandService,
        sites: SiteService,
        assets: AssetService,
    ):
        self.store = store
        self.settings = settings
        self.agents = agents
        self.commands = commands
        self.sites = sites
        self.assets = assets

    def create(
        self,
        *,
        agent_id: str,
        requested_scope: str | None = None,
        mode: str = "selected",
        authorization_confirmed: bool = False,
    ) -> dict:
        try:
            agent = self.agents.get_public(agent_id)
        except AgentNotFound as exc:
            raise DiscoveryNotFound from exc
        if agent["status"] == "offline":
            raise AgentOffline
        if not agent.get("nmap_version"):
            raise ScannerUnavailable("Nmap is not installed on this agent")
        if agent.get("npcap_status") != "available":
            raise ScannerUnavailable("Npcap is not available on this agent")
        plan = self._scope_plan(agent, requested_scope, mode, authorization_confirmed)
        if not all(
            self.sites.approved(agent.get("site_id"), scope) for scope in plan["scopes"]
        ):
            raise InvalidDiscoveryScope(
                "Approve every selected CIDR in the probe's site before discovery"
            )
        with self.store.locked():
            for existing in self.list(agent_id):
                if existing["status"] in ACTIVE_STATUSES:
                    raise DiscoveryInProgress(
                        f"Discovery {existing['discovery_id']} is already active"
                    )
            discovery_id = str(uuid4())
            command = self.commands.create(
                agent_id=agent_id,
                command_type="discover_network",
                payload={
                    "discovery_id": discovery_id,
                    "connected_network": plan["connected_network"],
                    "interface_name": agent.get("discovery_interface"),
                    "scopes": plan["scopes"],
                    "mode": mode,
                    "authorization_confirmed": authorization_confirmed,
                    "scope_policy": self.sites.policy(agent.get("site_id")),
                },
            )
            now = isoformat(utc_now())
            record = {
                "discovery_id": discovery_id,
                "command_id": command["command_id"],
                "agent_id": agent_id,
                "status": "queued",
                "stage": "queued",
                "network": plan["network"],
                "connected_network": plan["connected_network"],
                "interface_name": agent.get("discovery_interface"),
                "mode": mode,
                "requested_scopes": plan["scopes"],
                "completed_scopes": [],
                "failed_scopes": [],
                "current_scope": None,
                "total_scopes": len(plan["scopes"]),
                "public_scope_authorized": plan["public_scope_authorized"],
                "device_count": 0,
                "found_count": 0,
                "progress_percent": None,
                "cancel_requested": False,
                "authorization_confirmed": authorization_confirmed,
                "created_at": now,
                "started_at": None,
                "completed_at": None,
                "devices": [],
                "error": None,
                "events": [
                    self._event(
                        status="queued",
                        stage="queued",
                        message="Discovery queued for the agent",
                        occurred_at=now,
                    )
                ],
            }
            self.store.write("discoveries", discovery_id, record)
            return record

    def save_result(self, authenticated_agent_id: str, result: DiscoveryResult) -> dict:
        discovery_id = str(result.discovery_id)
        with self.store.locked():
            record = self.store.read("discoveries", discovery_id)
            if record is None:
                raise DiscoveryNotFound
            if (
                record["agent_id"] != authenticated_agent_id
                or str(result.agent_id) != authenticated_agent_id
            ):
                raise DiscoveryOwnershipError
            try:
                network = ipaddress.ip_network(result.network, strict=True)
            except ValueError as exc:
                raise InvalidDiscoveryResult("Invalid discovery network") from exc
            if network.version != 4:
                raise InvalidDiscoveryResult("Only IPv4 discovery is supported")
            expected_network = record.get("network")
            if expected_network and str(network) != expected_network:
                raise InvalidDiscoveryResult(
                    f"Result network {network} does not match requested "
                    f"{expected_network}"
                )
            if (
                not self.settings.allow_public_scopes
                and not record.get("public_scope_authorized", False)
                and not network.is_private
            ):
                raise InvalidDiscoveryResult("Public discovery networks are disabled")
            requested_scopes = {
                str(ipaddress.ip_network(item, strict=True))
                for item in record.get("requested_scopes", [str(network)])
            }
            if (
                result.requested_scopes
                and set(result.requested_scopes) != requested_scopes
            ):
                raise InvalidDiscoveryResult(
                    "Result scopes do not match requested scopes"
                )
            if len(requested_scopes) > 1 and not result.requested_scopes:
                raise InvalidDiscoveryResult(
                    "Multi-segment results must include requested scopes"
                )
            reported_completed = result.completed_scopes
            if (
                not reported_completed
                and result.status == "completed"
                and len(requested_scopes) == 1
            ):
                reported_completed = list(requested_scopes)
            completed_scopes = self._validated_result_scopes(
                reported_completed, requested_scopes, "completed"
            )
            failed_scopes = self._validated_result_scopes(
                result.failed_scopes, requested_scopes, "failed"
            )
            if set(completed_scopes) & set(failed_scopes):
                raise InvalidDiscoveryResult(
                    "A scope cannot be both completed and failed"
                )
            if result.status == "completed" and (
                set(completed_scopes) != requested_scopes or failed_scopes
            ):
                raise InvalidDiscoveryResult(
                    "Completed discovery must account for every requested scope"
                )
            seen_ips: set[str] = set()
            for device in result.devices:
                try:
                    address = ipaddress.ip_address(device.ip)
                except ValueError as exc:
                    raise InvalidDiscoveryResult("Invalid discovered IP") from exc
                if address not in network:
                    raise InvalidDiscoveryResult(
                        f"Discovered IP {address} is outside {network}"
                    )
                if device.discovery_scope:
                    try:
                        source_scope = ipaddress.ip_network(
                            device.discovery_scope, strict=True
                        )
                    except ValueError as exc:
                        raise InvalidDiscoveryResult(
                            "Invalid device discovery scope"
                        ) from exc
                    if (
                        str(source_scope) not in requested_scopes
                        or address not in source_scope
                    ):
                        raise InvalidDiscoveryResult(
                            f"Discovered IP {address} does not match its source scope"
                        )
                elif len(requested_scopes) > 1:
                    raise InvalidDiscoveryResult(
                        "Multi-segment devices must identify their discovery scope"
                    )
                if str(address) in seen_ips:
                    raise InvalidDiscoveryResult(f"Duplicate discovered IP {address}")
                seen_ips.add(str(address))
            record.update(
                {
                    "status": result.status,
                    "stage": result.status,
                    "network": str(network),
                    "interface_name": result.interface_name,
                    "completed_scopes": completed_scopes,
                    "failed_scopes": failed_scopes,
                    "current_scope": None,
                    "device_count": len(result.devices),
                    "found_count": len(result.devices),
                    "progress_percent": (
                        100.0 if result.status == "completed" else None
                    ),
                    "started_at": isoformat(result.started_at),
                    "completed_at": (
                        isoformat(result.completed_at) if result.completed_at else None
                    ),
                    "devices": [
                        device.model_dump(mode="json") for device in result.devices
                    ],
                    "error": result.error,
                }
            )
            self._append_event(
                record,
                status=result.status,
                stage=result.status,
                message=(
                    f"Discovery completed with {len(result.devices)} active devices"
                    if result.status == "completed"
                    else result.error
                    or f"Discovery finished with status {result.status}"
                ),
                occurred_at=(
                    isoformat(result.completed_at)
                    if result.completed_at
                    else isoformat(result.started_at)
                ),
                progress_percent=record["progress_percent"],
                found_count=len(result.devices),
            )
            self.store.write("discoveries", discovery_id, record)
            self.assets.observe_discovery(record)
            record_activity(
                self.store,
                event_type=f"discovery.{result.status}",
                message=f"Discovery found {len(result.devices)} active devices",
                actor_type="agent",
                actor_id=authenticated_agent_id,
                resource_type="discovery",
                resource_id=discovery_id,
                details={"network": str(network), "device_count": len(result.devices)},
                severity="error" if result.status == "failed" else "info",
            )
            return record

    def sync_command_event(self, command: dict, event: CommandEvent) -> None:
        if command.get("command_type") != "discover_network":
            return
        discovery_id = str(command.get("payload", {}).get("discovery_id", ""))
        if not discovery_id:
            return
        with self.store.locked():
            record = self.store.read("discoveries", discovery_id)
            if record is None:
                return
            self._normalize(record)
            details = event.details
            stage = str(details.get("stage") or event.status)
            occurred_at = isoformat(event.occurred_at)
            progress = self._optional_percent(details.get("progress_percent"))
            found_count = self._nonnegative_int(
                details.get("found_count"), record["found_count"]
            )
            network = details.get("network")
            if isinstance(network, str) and network:
                record["network"] = network
            interface_name = details.get("interface_name")
            if isinstance(interface_name, str) and interface_name:
                record["interface_name"] = interface_name
            current_scope = details.get("current_scope")
            if isinstance(current_scope, str) and current_scope:
                record["current_scope"] = current_scope
            elif "current_scope" in details and current_scope is None:
                record["current_scope"] = None
            completed_scopes = details.get("completed_scopes")
            if isinstance(completed_scopes, list):
                record["completed_scopes"] = [str(item) for item in completed_scopes]
            failed_scopes = details.get("failed_scopes")
            if isinstance(failed_scopes, list):
                record["failed_scopes"] = [str(item) for item in failed_scopes]
            if event.status == "running":
                record["status"] = (
                    "cancelling" if record["cancel_requested"] else "running"
                )
                record["stage"] = "cancelling" if record["cancel_requested"] else stage
                record["started_at"] = record["started_at"] or occurred_at
                if progress is not None:
                    record["progress_percent"] = progress
                record["found_count"] = max(record["found_count"], found_count)
            elif event.status in {"failed", "cancelled", "completed"}:
                if event.status == "cancelled" and record["status"] == "partial":
                    record["stage"] = "cancelled"
                elif event.status == "completed" and record["status"] == "partial":
                    record["stage"] = "partial"
                else:
                    record["status"] = event.status
                    record["stage"] = stage
                record["completed_at"] = record["completed_at"] or occurred_at
                if event.status == "failed":
                    record["error"] = event.message
                if event.status == "completed":
                    record["progress_percent"] = 100.0
            self._append_event(
                record,
                status=event.status,
                stage=stage,
                message=event.message,
                occurred_at=occurred_at,
                progress_percent=progress,
                found_count=found_count,
            )
            self.store.write("discoveries", discovery_id, record)

    def request_cancel(self, discovery_id: str) -> dict:
        with self.store.locked():
            record = self.store.read("discoveries", discovery_id)
            if record is None:
                raise DiscoveryNotFound
            record = self._reconcile(record)
            self._normalize(record)
            if record["status"] in TERMINAL_STATUSES:
                return record
            command = self.commands.get(record["command_id"])
            now = isoformat(utc_now())
            record["cancel_requested"] = True
            if command["status"] == "queued":
                self.commands.cancel_pending(
                    record["command_id"],
                    message="Discovery cancelled before it started",
                )
                record["status"] = "cancelled"
                record["stage"] = "cancelled"
                record["completed_at"] = now
                message = "Discovery cancelled before it started"
            else:
                record["status"] = "cancelling"
                record["stage"] = "cancelling"
                message = "Stopping discovery on the agent"
            self._append_event(
                record,
                status=record["status"],
                stage=record["stage"],
                message=message,
                occurred_at=now,
                found_count=record["found_count"],
            )
            self.store.write("discoveries", discovery_id, record)
            record_activity(
                self.store,
                event_type="discovery.cancel_requested",
                message=message,
                resource_type="discovery",
                resource_id=discovery_id,
                details={"agent_id": record["agent_id"]},
            )
            return record

    def control(self, discovery_id: str, agent_id: str) -> dict:
        record = self.get(discovery_id)
        if record["agent_id"] != agent_id:
            raise DiscoveryOwnershipError
        return {
            "discovery_id": discovery_id,
            "cancel_requested": record["cancel_requested"],
        }

    def get(self, discovery_id: str) -> dict:
        record = self.store.read("discoveries", discovery_id)
        if record is None:
            raise DiscoveryNotFound
        return self._reconcile(record)

    def list(self, agent_id: str | None = None) -> list[dict]:
        records = [self._reconcile(item) for item in self.store.list("discoveries")]
        if agent_id is not None:
            records = [item for item in records if item["agent_id"] == agent_id]
        records.sort(key=lambda item: item["created_at"], reverse=True)
        return records

    def _reconcile(self, record: dict) -> dict:
        changed = self._normalize(record)
        if record["status"] in ACTIVE_STATUSES:
            try:
                command = self.commands.get(record["command_id"])
            except CommandNotFound:
                command = None
            if command and command["status"] in {"failed", "expired", "cancelled"}:
                status = "cancelled" if command["status"] == "cancelled" else "failed"
                message = command.get("last_message") or (
                    "Discovery command expired before completion"
                    if command["status"] == "expired"
                    else "Discovery command failed"
                )
                occurred_at = command.get("updated_at") or isoformat(utc_now())
                record.update(
                    {
                        "status": status,
                        "stage": status,
                        "completed_at": record["completed_at"] or occurred_at,
                        "error": message if status == "failed" else record["error"],
                    }
                )
                self._append_event(
                    record,
                    status=status,
                    stage=status,
                    message=message,
                    occurred_at=occurred_at,
                    found_count=record["found_count"],
                )
                changed = True
        if changed:
            self.store.write("discoveries", record["discovery_id"], record)
        return record

    @staticmethod
    def _normalize(record: dict) -> bool:
        defaults = {
            "stage": record.get("status", "queued"),
            "found_count": record.get("device_count", 0),
            "progress_percent": None,
            "cancel_requested": False,
            "events": [],
            "mode": "selected",
            "connected_network": record.get("network"),
            "requested_scopes": ([record["network"]] if record.get("network") else []),
            "completed_scopes": [],
            "failed_scopes": [],
            "current_scope": None,
            "total_scopes": 1,
            "public_scope_authorized": False,
        }
        changed = False
        for key, value in defaults.items():
            if key not in record:
                record[key] = value
                changed = True
        return changed

    @staticmethod
    def _scope_plan(
        agent: dict,
        requested_scope: str | None,
        mode: str,
        authorization_confirmed: bool,
    ) -> dict:
        connected_value = agent.get("discovery_network") or agent.get("subnet")
        if not connected_value:
            raise InvalidDiscoveryScope("The agent has not reported an active network")
        try:
            connected = ipaddress.ip_network(connected_value, strict=True)
            local_ip = ipaddress.ip_address(agent.get("local_ip") or "")
        except ValueError as exc:
            raise InvalidDiscoveryScope(
                "The agent reported an invalid network"
            ) from exc
        if connected.version != 4 or local_ip.version != 4 or local_ip not in connected:
            raise InvalidDiscoveryScope(
                "The agent network and local address do not match"
            )
        if not connected.is_private and not authorization_confirmed:
            raise InvalidDiscoveryScope(
                f"{connected} requires explicit public-range authorization"
            )
        reported = agent.get("discovery_scope_options") or []
        options: list[str] = []
        for value in reported:
            try:
                scope = ipaddress.ip_network(value, strict=True)
            except ValueError:
                continue
            if (
                scope.version == 4
                and scope.num_addresses <= 256
                and scope.subnet_of(connected)
            ):
                options.append(str(scope))
        if not options:
            if connected.num_addresses <= 256:
                options = [str(connected)]
            elif connected.prefixlen >= 20:
                options = [str(item) for item in connected.subnets(new_prefix=24)]
            else:
                options = [str(ipaddress.ip_network(f"{local_ip}/24", strict=False))]
        options = list(dict.fromkeys(options))
        approved = set(agent.get("approved_discovery_scopes") or [])
        options = [item for item in options if item in approved]
        if not options:
            raise InvalidDiscoveryScope(
                "Approve a connected network segment for this probe's site"
            )
        recommended = agent.get("discovery_recommended_scope")
        if recommended not in options:
            current = str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
            recommended = current if current in options else options[0]
        if mode == "all":
            if len(options) < 2 or len(options) > 16:
                raise InvalidDiscoveryScope(
                    "Scan all is available only for 2 to 16 /24 segments"
                )
            scopes = options
            network = str(connected)
        elif mode == "selected":
            selected = requested_scope or recommended
            if selected not in options:
                raise InvalidDiscoveryScope(
                    f"{selected} is not an available scope for {connected}"
                )
            scopes = [selected]
            network = selected
        else:
            raise InvalidDiscoveryScope("Invalid discovery mode")
        return {
            "connected_network": str(connected),
            "network": network,
            "scopes": scopes,
            "public_scope_authorized": not connected.is_private,
        }

    @staticmethod
    def _validated_result_scopes(
        values: list[str], requested: set[str], label: str
    ) -> list[str]:
        normalized: list[str] = []
        for value in values:
            try:
                scope = str(ipaddress.ip_network(value, strict=True))
            except ValueError as exc:
                raise InvalidDiscoveryResult(f"Invalid {label} scope") from exc
            if scope not in requested:
                raise InvalidDiscoveryResult(
                    f"{label.title()} scope {scope} was not requested"
                )
            if scope not in normalized:
                normalized.append(scope)
        return normalized

    @staticmethod
    def _event(
        *,
        status: str,
        stage: str,
        message: str,
        occurred_at: str,
        progress_percent: float | None = None,
        found_count: int = 0,
    ) -> dict:
        return {
            "event_id": str(uuid4()),
            "status": status,
            "stage": stage,
            "message": message[:1024],
            "occurred_at": occurred_at,
            "progress_percent": progress_percent,
            "found_count": found_count,
        }

    @classmethod
    def _append_event(cls, record: dict, **values) -> None:
        events = record.setdefault("events", [])
        latest = events[-1] if events else None
        candidate = cls._event(**values)
        if latest and all(
            latest.get(key) == candidate.get(key)
            for key in ("status", "stage", "message", "progress_percent", "found_count")
        ):
            return
        events.append(candidate)
        record["events"] = events[-MAX_EVENTS:]

    @staticmethod
    def _optional_percent(value) -> float | None:
        try:
            return max(0.0, min(100.0, float(value))) if value is not None else None
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _nonnegative_int(value, fallback: int) -> int:
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            return fallback
