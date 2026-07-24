"""Execute one server-authorized discovery command."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any, Protocol

from telesec_agent.enrollment import AgentIdentity, timestamp
from telesec_agent.heartbeat import HeartbeatSender
from telesec_agent.scanning.interfaces import (
    InterfaceScope,
    ResolvedDiscoveryPlan,
    ScopeError,
    resolve_discovery_plan,
    select_scope,
)
from telesec_agent.scanning.nmap_runner import (
    DiscoveryProgress,
    NmapExecutionError,
    NmapRunner,
    NmapUnavailable,
    ScanCancelled,
    ScanTimedOut,
)
from telesec_agent.scanning.parser import parse_discovery_xml

LOGGER = logging.getLogger(__name__)


class DiscoveryProtocolClient(Protocol):
    def command_event(
        self,
        command_id: str,
        payload: dict[str, Any],
        *,
        credential: str,
    ) -> dict[str, Any]: ...

    def upload_discovery(
        self,
        discovery_id: str,
        payload: dict[str, Any],
        *,
        credential: str,
    ) -> dict[str, Any]: ...

    def discovery_control(
        self,
        discovery_id: str,
        *,
        credential: str,
    ) -> dict[str, Any]: ...


class DiscoveryCommandHandler:
    def __init__(
        self,
        nmap: NmapRunner,
        scope_selector: Callable[[], InterfaceScope] = select_scope,
        scope_resolver: Callable[..., ResolvedDiscoveryPlan] = resolve_discovery_plan,
        heartbeat: HeartbeatSender | None = None,
    ):
        self.nmap = nmap
        self.scope_selector = scope_selector
        self.scope_resolver = scope_resolver
        self.heartbeat = heartbeat

    def handle(
        self,
        command: dict[str, Any],
        identity: AgentIdentity,
        client: DiscoveryProtocolClient,
    ) -> None:
        command_id = str(command["command_id"])
        payload = command["payload"]
        discovery_id = str(payload["discovery_id"])
        started_at = timestamp()
        self._event(
            client,
            identity,
            command_id,
            status="running",
            message="Validating the authorized network scope",
            details={"stage": "validating_scope", "found_count": 0},
        )
        self._keepalive(identity, command_id, client)
        scope: InterfaceScope | None = None
        scan_scopes: tuple[str, ...] = ()
        result_network: str | None = None
        completed_scopes: list[str] = []
        failed_scopes: list[str] = []
        devices_by_ip: dict[str, dict[str, Any]] = {}
        current_scope: str | None = None
        control_checked_at = 0.0
        cancellation_requested = False

        def should_cancel() -> bool:
            nonlocal control_checked_at, cancellation_requested
            now = time.monotonic()
            if now - control_checked_at < 1:
                return cancellation_requested
            cancellation_requested = self._cancel_requested(
                client, identity, discovery_id
            )
            control_checked_at = now
            return cancellation_requested

        try:
            if should_cancel():
                raise ScanCancelled("Discovery cancelled before Nmap started")
            requested = payload.get("scopes")
            if isinstance(requested, list) and requested:
                plan = self.scope_resolver(
                    [str(item) for item in requested],
                    connected_network=str(payload.get("connected_network") or ""),
                    interface_name=payload.get("interface_name"),
                    authorization_confirmed=bool(
                        payload.get("authorization_confirmed")
                    ),
                )
                scope = plan.connected_scope
                scan_scopes = plan.scopes
            else:
                scope = self.scope_selector()
                scan_scopes = (scope.network,)
            mode = str(payload.get("mode") or "selected")
            result_network = (
                str(payload.get("connected_network"))
                if mode == "all"
                else scan_scopes[0]
            )
            total_scopes = len(scan_scopes)
            last_keepalive = time.monotonic()

            for scope_index, target_scope in enumerate(scan_scopes, start=1):
                current_scope = target_scope
                if should_cancel():
                    raise ScanCancelled("Discovery stopped by the user")
                self._event(
                    client,
                    identity,
                    command_id,
                    status="running",
                    message=(
                        f"Scanning segment {scope_index} of {total_scopes}: "
                        f"{target_scope}"
                    ),
                    details=self._progress_details(
                        result_network=result_network,
                        current_scope=target_scope,
                        interface_name=scope.interface_name,
                        scope_index=scope_index,
                        total_scopes=total_scopes,
                        completed_scopes=completed_scopes,
                        failed_scopes=failed_scopes,
                        found_count=len(devices_by_ip),
                        progress_percent=((scope_index - 1) / total_scopes) * 100,
                        address_count=_network_address_count(target_scope),
                        command=(
                            "nmap -sn --host-timeout 30s --stats-every 2s "
                            f"{target_scope}"
                        ),
                    ),
                )

                def progress(
                    update: DiscoveryProgress,
                    *,
                    index: int = scope_index,
                    target: str = target_scope,
                ) -> None:
                    nonlocal last_keepalive
                    aggregate_found = len(devices_by_ip) + update.found_count
                    segment_percent = update.progress_percent or 0
                    aggregate_percent = (
                        ((index - 1) + segment_percent / 100) / total_scopes
                    ) * 100
                    try:
                        self._event(
                            client,
                            identity,
                            command_id,
                            status="running",
                            message=(
                                f"Segment {index} of {total_scopes}: "
                                f"{aggregate_found} active devices found"
                            ),
                            details=self._progress_details(
                                result_network=result_network,
                                current_scope=target,
                                interface_name=scope.interface_name,
                                scope_index=index,
                                total_scopes=total_scopes,
                                completed_scopes=completed_scopes,
                                failed_scopes=failed_scopes,
                                found_count=aggregate_found,
                                progress_percent=aggregate_percent,
                                elapsed_seconds=update.elapsed_seconds,
                            ),
                        )
                        if (
                            self.heartbeat is not None
                            and time.monotonic() - last_keepalive
                            >= identity.heartbeat_interval_seconds
                        ):
                            self._keepalive(identity, command_id, client)
                            last_keepalive = time.monotonic()
                    except Exception as exc:
                        LOGGER.warning(
                            "Unable to report discovery progress: %s", exc
                        )

                try:
                    xml_output = self.nmap.discover(
                        target_scope,
                        cancel_requested=should_cancel,
                        progress_callback=progress,
                    )
                    segment_devices = parse_discovery_xml(
                        xml_output,
                        local_ip=scope.local_ip,
                        observed_at=timestamp(),
                    )
                    for device in segment_devices:
                        device["discovery_scope"] = target_scope
                        devices_by_ip[device["ip"]] = device
                    completed_scopes.append(target_scope)
                    self._event(
                        client,
                        identity,
                        command_id,
                        status="running",
                        message=(
                            f"Segment {scope_index} of {total_scopes} completed "
                            f"with {len(segment_devices)} active devices"
                        ),
                        details=self._progress_details(
                            result_network=result_network,
                            current_scope=target_scope,
                            interface_name=scope.interface_name,
                            scope_index=scope_index,
                            total_scopes=total_scopes,
                            completed_scopes=completed_scopes,
                            failed_scopes=failed_scopes,
                            found_count=len(devices_by_ip),
                            progress_percent=(scope_index / total_scopes) * 100,
                        ),
                    )
                except ScanCancelled:
                    raise
                except NmapUnavailable:
                    raise
                except (ScanTimedOut, NmapExecutionError) as exc:
                    failed_scopes.append(target_scope)
                    self._event(
                        client,
                        identity,
                        command_id,
                        status="running",
                        message=f"Segment {target_scope} failed: {exc}",
                        details=self._progress_details(
                            result_network=result_network,
                            current_scope=target_scope,
                            interface_name=scope.interface_name,
                            scope_index=scope_index,
                            total_scopes=total_scopes,
                            completed_scopes=completed_scopes,
                            failed_scopes=failed_scopes,
                            found_count=len(devices_by_ip),
                            progress_percent=(scope_index / total_scopes) * 100,
                        ),
                    )

            self._event(
                client,
                identity,
                command_id,
                status="running",
                message="Processing discovered device records",
                details={
                    "stage": "processing",
                    "network": result_network,
                    "current_scope": current_scope,
                    "interface_name": scope.interface_name,
                    "completed_scopes": completed_scopes,
                    "failed_scopes": failed_scopes,
                    "found_count": len(devices_by_ip),
                },
            )
            completed_at = timestamp()
            devices = _sorted_devices(devices_by_ip)
            result_status = (
                "completed"
                if not failed_scopes
                else "partial"
                if completed_scopes
                else "failed"
            )
            result_error = (
                f"{len(failed_scopes)} of {len(scan_scopes)} segments failed"
                if failed_scopes
                else None
            )
            client.upload_discovery(
                discovery_id,
                {
                    "schema_version": "1.0",
                    "message_type": "discovery.result",
                    "discovery_id": discovery_id,
                    "agent_id": identity.agent_id,
                    "network": result_network,
                    "interface_name": scope.interface_name,
                    "status": result_status,
                    "started_at": started_at,
                    "completed_at": completed_at,
                    "devices": devices,
                    "error": result_error,
                    "requested_scopes": list(scan_scopes),
                    "completed_scopes": completed_scopes,
                    "failed_scopes": failed_scopes,
                },
                credential=identity.credential,
            )
            self._event(
                client,
                identity,
                command_id,
                status="failed" if result_status == "failed" else "completed",
                message=(
                    f"Discovery {result_status} with {len(devices)} active devices"
                ),
                details={
                    "stage": result_status,
                    "device_count": len(devices),
                    "found_count": len(devices),
                    "progress_percent": 100,
                    "network": result_network,
                    "current_scope": None,
                    "interface_name": scope.interface_name,
                    "completed_scopes": completed_scopes,
                    "failed_scopes": failed_scopes,
                },
            )
        except ScanCancelled as exc:
            completed_at = timestamp()
            if scope is not None and current_scope and exc.partial_xml:
                for device in parse_discovery_xml(
                    exc.partial_xml,
                    local_ip=scope.local_ip,
                    observed_at=completed_at,
                ):
                    device["discovery_scope"] = current_scope
                    devices_by_ip[device["ip"]] = device
            devices = _sorted_devices(devices_by_ip)
            if scope is not None and result_network is not None:
                client.upload_discovery(
                    discovery_id,
                    {
                        "schema_version": "1.0",
                        "message_type": "discovery.result",
                        "discovery_id": discovery_id,
                        "agent_id": identity.agent_id,
                        "network": result_network,
                        "interface_name": scope.interface_name,
                        "status": "partial" if devices else "cancelled",
                        "started_at": started_at,
                        "completed_at": completed_at,
                        "devices": devices,
                        "error": "Discovery stopped by the user",
                        "requested_scopes": list(scan_scopes),
                        "completed_scopes": completed_scopes,
                        "failed_scopes": failed_scopes,
                    },
                    credential=identity.credential,
                )
            self._event(
                client,
                identity,
                command_id,
                status="cancelled",
                message=(
                    f"Discovery stopped with {len(devices)} active devices"
                    if devices
                    else "Discovery stopped by the user"
                ),
                details={
                    "stage": "cancelled",
                    "network": result_network,
                    "current_scope": current_scope,
                    "found_count": len(devices),
                    "completed_scopes": completed_scopes,
                    "failed_scopes": failed_scopes,
                },
            )
        except Exception as exc:
            self._event(
                client,
                identity,
                command_id,
                status="failed",
                message=str(exc)[:1024] or "Discovery failed",
                details={
                    "stage": "failed",
                    "failure_code": _failure_code(exc),
                    "network": result_network,
                    "current_scope": current_scope,
                    "interface_name": scope.interface_name if scope else None,
                    "completed_scopes": completed_scopes,
                    "failed_scopes": failed_scopes,
                },
            )

    def _keepalive(
        self,
        identity: AgentIdentity,
        command_id: str,
        client: DiscoveryProtocolClient,
    ) -> None:
        if self.heartbeat is not None:
            self.heartbeat.send(
                identity,
                service_status="busy",
                current_command_id=command_id,
                activity="Discovering network",
                client=client,
            )

    @staticmethod
    def _cancel_requested(
        client: DiscoveryProtocolClient,
        identity: AgentIdentity,
        discovery_id: str,
    ) -> bool:
        try:
            control = client.discovery_control(
                discovery_id, credential=identity.credential
            )
        except Exception as exc:
            LOGGER.warning("Unable to read discovery control: %s", exc)
            return False
        return bool(control.get("cancel_requested"))

    @staticmethod
    def _event(
        client: DiscoveryProtocolClient,
        identity: AgentIdentity,
        command_id: str,
        *,
        status: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        client.command_event(
            command_id,
            {
                "schema_version": "1.0",
                "message_type": "command.event",
                "status": status,
                "message": message,
                "details": details or {},
                "occurred_at": timestamp(),
            },
            credential=identity.credential,
        )

    @staticmethod
    def _progress_details(
        *,
        result_network: str,
        current_scope: str,
        interface_name: str,
        scope_index: int,
        total_scopes: int,
        completed_scopes: list[str],
        failed_scopes: list[str],
        found_count: int,
        progress_percent: float,
        **extra: Any,
    ) -> dict[str, Any]:
        return {
            "stage": "scanning",
            "network": result_network,
            "current_scope": current_scope,
            "interface_name": interface_name,
            "scope_index": scope_index,
            "total_scopes": total_scopes,
            "completed_scopes": list(completed_scopes),
            "failed_scopes": list(failed_scopes),
            "found_count": found_count,
            "progress_percent": round(progress_percent, 2),
            **extra,
        }


def _network_address_count(network: str) -> int:
    import ipaddress

    return ipaddress.ip_network(network, strict=True).num_addresses


def _sorted_devices(devices_by_ip: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        devices_by_ip.values(),
        key=lambda item: tuple(int(part) for part in item["ip"].split(".")),
    )


def _failure_code(error: Exception) -> str:
    if isinstance(error, ScopeError):
        return error.code
    if isinstance(error, NmapUnavailable):
        return "nmap_unavailable"
    if isinstance(error, ScanTimedOut):
        return "nmap_timeout"
    if isinstance(error, NmapExecutionError):
        return "nmap_failed"
    return "discovery_failed"
