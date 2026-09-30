"""Execute one server-authorized discovery command."""

from __future__ import annotations

import ipaddress
import logging
import time
from collections.abc import Callable
from typing import Any, Protocol

from forgesec_agent.enrollment import AgentIdentity, timestamp
from forgesec_agent.heartbeat import HeartbeatSender
from forgesec_agent.scanning.enrichment import DeviceEnricher
from forgesec_agent.scanning.interfaces import (
    InterfaceScope,
    ResolvedDiscoveryPlan,
    ScopeError,
    resolve_discovery_plan,
    select_scope,
)
from forgesec_agent.scanning.nmap_runner import (
    DiscoveryProgress,
    NmapExecutionError,
    NmapRunner,
    NmapUnavailable,
    ScanCancelled,
    ScanTimedOut,
)
from forgesec_agent.scanning.parser import NmapParseError, parse_discovery_xml
from forgesec_agent.scanning.policy import exclusions_for_scope, require_approved

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
        enricher: DeviceEnricher | None = None,
    ):
        self.nmap = nmap
        self.scope_selector = scope_selector
        self.scope_resolver = scope_resolver
        self.heartbeat = heartbeat
        self.enricher = enricher or DeviceEnricher()

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
        follow_up_checks: list[dict[str, Any]] = []
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
            require_approved(payload.get("scope_policy"), list(scan_scopes))
            scope_policy = payload["scope_policy"]
            mode = str(payload.get("mode") or "selected")
            known_targets = payload.get("known_targets") or []
            if not isinstance(known_targets, list) or len(known_targets) > 3:
                raise ValueError("Choose up to three known IPv4 hosts")
            if known_targets and mode != "selected":
                raise ValueError("Known-host checks require one selected scope")
            if len(set(known_targets)) != len(known_targets):
                raise ValueError("Known-host checks must be distinct")
            for target in known_targets:
                address = ipaddress.IPv4Address(target)
                if (
                    address not in ipaddress.ip_network(scan_scopes[0])
                    or target == scope.local_ip
                ):
                    raise ValueError(
                        "Known host is outside selected scope or is the probe"
                    )
            require_approved(payload.get("scope_policy"), known_targets)
            result_network = (
                str(payload.get("connected_network"))
                if mode == "all"
                else scan_scopes[0]
            )
            total_scopes = len(scan_scopes)
            discovery_weight = 85 if known_targets else 100
            last_keepalive = time.monotonic()

            def accept_segment_devices(xml_output: str, target_scope: str) -> int:
                accepted_count = 0
                target_network = ipaddress.ip_network(target_scope)
                for device in parse_discovery_xml(
                    xml_output,
                    local_ip=scope.local_ip,
                    observed_at=timestamp(),
                ):
                    if ipaddress.ip_address(device["ip"]) not in target_network:
                        LOGGER.warning(
                            "Discarded discovered host outside selected segment"
                        )
                        continue
                    try:
                        require_approved(scope_policy, [device["ip"]])
                    except ValueError:
                        LOGGER.warning("Discarded discovered host outside site policy")
                        continue
                    device["discovery_scope"] = target_scope
                    devices_by_ip[device["ip"]] = device
                    accepted_count += 1
                return accepted_count

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
                        progress_percent=(
                            (scope_index - 1) / total_scopes
                        ) * discovery_weight,
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
                    ) * discovery_weight
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
                        LOGGER.warning("Unable to report discovery progress: %s", exc)

                try:
                    exclusions = exclusions_for_scope(scope_policy, target_scope)
                    xml_output = self.nmap.discover(
                        target_scope,
                        exclusions=exclusions,
                        cancel_requested=should_cancel,
                        progress_callback=progress,
                    )
                    accepted_count = accept_segment_devices(xml_output, target_scope)
                    completed_scopes.append(target_scope)
                    self._event(
                        client,
                        identity,
                        command_id,
                        status="running",
                        message=(
                            f"Segment {scope_index} of {total_scopes} completed "
                            f"with {accepted_count} active devices"
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
                            progress_percent=(
                                scope_index / total_scopes
                            ) * discovery_weight,
                        ),
                    )
                except ScanCancelled:
                    raise
                except NmapUnavailable:
                    raise
                except (ScanTimedOut, NmapExecutionError) as exc:
                    partial_count = 0
                    if isinstance(exc, ScanTimedOut) and exc.partial_xml:
                        partial_count = accept_segment_devices(
                            exc.partial_xml, target_scope
                        )
                    failed_scopes.append(target_scope)
                    self._event(
                        client,
                        identity,
                        command_id,
                        status="running",
                        message=(
                            f"Segment {target_scope} failed: {exc}"
                            + (
                                f"; {partial_count} partial host(s) retained"
                                if partial_count else ""
                            )
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
                            progress_percent=(
                                scope_index / total_scopes
                            ) * discovery_weight,
                        ),
                    )

            if completed_scopes and known_targets:
                for index, target in enumerate(known_targets, start=1):
                    if should_cancel():
                        raise ScanCancelled("Discovery stopped by the user")
                    existing = devices_by_ip.get(target)
                    if existing:
                        follow_up_checks.append({
                            "ip": target,
                            "status": "already_discovered",
                            "method": "initial_discovery",
                            "checked_at": existing["last_seen"],
                            "reason": existing["discovery_reason"],
                        })
                        continue
                    self._event(
                        client, identity, command_id,
                        status="running",
                        message=f"Checking known host {index} of {len(known_targets)}",
                        details={
                            "stage": "verifying_known_hosts",
                            "network": result_network,
                            "found_count": len(devices_by_ip),
                            "progress_percent": 85 + (
                                (index - 1) / len(known_targets)
                            ) * 15,
                        },
                    )

                    def keepalive() -> None:
                        nonlocal last_keepalive
                        if self.heartbeat is not None and (
                            time.monotonic() - last_keepalive
                            >= identity.heartbeat_interval_seconds
                        ):
                            self._keepalive(identity, command_id, client)
                            last_keepalive = time.monotonic()

                    try:
                        xml_output = self.nmap.verify_known_host(
                            target,
                            cancel_requested=should_cancel,
                            activity_callback=keepalive,
                        )
                        matched = next(
                            (
                                device for device in parse_discovery_xml(
                                    xml_output,
                                    local_ip=scope.local_ip,
                                    observed_at=timestamp(),
                                )
                                if device["ip"] == target
                            ),
                            None,
                        )
                        if matched:
                            reason = matched["discovery_reason"]
                            matched["discovery_reason"] = f"targeted-{reason}"
                            matched["discovery_scope"] = scan_scopes[0]
                            devices_by_ip[target] = matched
                            status = "responsive"
                        else:
                            reason = "no-response"
                            status = "no_response"
                        error = None
                    except ScanCancelled:
                        raise
                    except (
                        NmapUnavailable,
                        ScanTimedOut,
                        NmapExecutionError,
                        NmapParseError,
                    ) as exc:
                        status, reason, error = "error", None, str(exc)[:512]
                    follow_up_checks.append({
                        "ip": target,
                        "status": status,
                        "method": "targeted_tcp_icmp",
                        "checked_at": timestamp(),
                        "reason": reason,
                        "error": error,
                    })
                    self._event(
                        client, identity, command_id,
                        status="running",
                        message=f"Known host {target}: {status.replace('_', ' ')}",
                        details={
                            "stage": "verifying_known_hosts",
                            "network": result_network,
                            "found_count": len(devices_by_ip),
                            "progress_percent": 85 + (index / len(known_targets)) * 15,
                        },
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
            devices = self.enricher.enrich(_sorted_devices(devices_by_ip))
            follow_up_failures = sum(
                check["status"] == "error" for check in follow_up_checks
            )
            result_status = (
                "completed"
                if not failed_scopes and not follow_up_failures
                else "partial"
                if completed_scopes or devices_by_ip
                else "failed"
            )
            failures = []
            if failed_scopes:
                failures.append(f"{len(failed_scopes)} segment(s) failed")
            if follow_up_failures:
                failures.append(f"{follow_up_failures} known-host check(s) failed")
            result_error = "; ".join(failures) or None
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
                    "follow_up_checks": follow_up_checks,
                },
                credential=identity.credential,
            )
            self._event(
                client,
                identity,
                command_id,
                status="failed" if result_status == "failed" else "completed",
                message=(
                    f"Discovery {result_status} with {len(devices)} observed devices"
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
                selected_network = ipaddress.ip_network(current_scope)
                for device in parse_discovery_xml(
                    exc.partial_xml,
                    local_ip=scope.local_ip,
                    observed_at=completed_at,
                ):
                    if ipaddress.ip_address(device["ip"]) not in selected_network:
                        LOGGER.warning(
                            "Discarded partial host outside selected segment"
                        )
                        continue
                    try:
                        require_approved(scope_policy, [device["ip"]])
                    except ValueError:
                        LOGGER.warning("Discarded partial host outside site policy")
                        continue
                    device["discovery_scope"] = current_scope
                    devices_by_ip[device["ip"]] = device
            devices = self.enricher.enrich(_sorted_devices(devices_by_ip))
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
                        "follow_up_checks": follow_up_checks,
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
            return True
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
