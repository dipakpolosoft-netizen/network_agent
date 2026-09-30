"""Bounded device diagnostics for selected discovered hosts."""

from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any, Protocol

from forgesec_agent.enrollment import AgentIdentity, timestamp
from forgesec_agent.heartbeat import HeartbeatSender
from forgesec_agent.scanning.nmap_runner import (
    NETWORK_SERVICE_PORTS,
    find_nmap_executable,
)
from forgesec_agent.scanning.policy import require_approved

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
MAX_OUTPUT_CHARS = 16000
LOGGER = logging.getLogger(__name__)
DIAGNOSTIC_SCAN_PROFILES = {
    "inventory_nmap": "inventory",
    "network_services_nmap": "network_services",
    "standard_nmap": "standard",
    "full_tcp_nmap": "full_tcp",
}


class DiagnosticClient(Protocol):
    def command_event(
        self,
        command_id: str,
        payload: dict[str, Any],
        *,
        credential: str,
    ) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class DiagnosticSpec:
    label: str
    argv: tuple[str, ...]
    display: str
    timeout_seconds: int


class DeviceDiagnosticHandler:
    def __init__(self, heartbeat: HeartbeatSender | None = None):
        self.heartbeat = heartbeat

    def handle(
        self,
        command: dict[str, Any],
        identity: AgentIdentity,
        client: DiagnosticClient,
    ) -> None:
        command_id = str(command["command_id"])
        payload = command["payload"]
        diagnostic_type = str(payload.get("diagnostic_type", ""))
        try:
            target_ip = str(ipaddress.IPv4Address(str(payload.get("target_ip", ""))))
            if (
                diagnostic_type == "full_tcp_nmap"
                and payload.get("full_tcp_confirmed") is not True
            ):
                raise ValueError("Full TCP host check requires separate confirmation")
            require_approved(
                payload.get("scope_policy"),
                [target_ip],
                DIAGNOSTIC_SCAN_PROFILES.get(diagnostic_type),
            )
            spec = _diagnostic_spec(diagnostic_type, target_ip)
        except Exception as exc:
            self._event(
                client,
                identity,
                command_id,
                status="failed",
                message=str(exc)[:1024],
                details={
                    "diagnostic_type": diagnostic_type,
                    "target_ip": str(payload.get("target_ip", "")),
                },
            )
            return

        started = timestamp()
        self._event(
            client,
            identity,
            command_id,
            status="running",
            message=f"{spec.label} running",
            details={
                "diagnostic_type": diagnostic_type,
                "target_ip": target_ip,
                "command_line": spec.display,
                "started_at": started,
            },
        )
        started_at = time.monotonic()
        keepalive_stop = threading.Event()
        keepalive_thread: threading.Thread | None = None
        if self.heartbeat is not None:
            self._keepalive(identity, command_id, spec.label, client)
            keepalive_thread = threading.Thread(
                target=self._keepalive_until_stopped,
                args=(keepalive_stop, identity, command_id, spec.label, client),
                name="forgesec-diagnostic-heartbeat",
                daemon=True,
            )
            keepalive_thread.start()
        try:
            result = subprocess.run(
                list(spec.argv),
                capture_output=True,
                check=False,
                creationflags=NO_WINDOW,
                text=True,
                timeout=spec.timeout_seconds,
            )
            completed = timestamp()
            output = _trim_output(result.stdout, result.stderr)
            ping_result = (
                _ping_result(target_ip, _decode(result.stdout))
                if diagnostic_type == "ping"
                else None
            )
            details = {
                "diagnostic_type": diagnostic_type,
                "target_ip": target_ip,
                "command_line": spec.display,
                "output": output,
                "exit_code": result.returncode,
                "duration_ms": int((time.monotonic() - started_at) * 1000),
                "started_at": started,
                "completed_at": completed,
            }
            if ping_result is not None:
                details["reachable"] = ping_result == "reply"
                details["ping_result"] = ping_result
            self._event(
                client,
                identity,
                command_id,
                status="completed",
                message=_summary(
                    spec.label, diagnostic_type, result.returncode, ping_result
                ),
                details=details,
            )
        except subprocess.TimeoutExpired as exc:
            self._event(
                client,
                identity,
                command_id,
                status="failed",
                message=f"{spec.label} timed out after {spec.timeout_seconds}s",
                details={
                    "diagnostic_type": diagnostic_type,
                    "target_ip": target_ip,
                    "command_line": spec.display,
                    "output": _trim_output(exc.stdout, exc.stderr),
                    "duration_ms": int((time.monotonic() - started_at) * 1000),
                    "started_at": started,
                    "completed_at": timestamp(),
                },
            )
        except OSError as exc:
            self._event(
                client,
                identity,
                command_id,
                status="failed",
                message=f"Unable to run {spec.label}: {exc}",
                details={
                    "diagnostic_type": diagnostic_type,
                    "target_ip": target_ip,
                    "command_line": spec.display,
                    "duration_ms": int((time.monotonic() - started_at) * 1000),
                    "started_at": started,
                    "completed_at": timestamp(),
                },
            )
        finally:
            keepalive_stop.set()
            if keepalive_thread is not None:
                keepalive_thread.join(timeout=30)

    def _keepalive_until_stopped(
        self,
        stop: threading.Event,
        identity: AgentIdentity,
        command_id: str,
        label: str,
        client: DiagnosticClient,
    ) -> None:
        interval = min(20.0, max(0.1, identity.heartbeat_interval_seconds / 2))
        while not stop.wait(interval):
            self._keepalive(identity, command_id, label, client)

    def _keepalive(
        self,
        identity: AgentIdentity,
        command_id: str,
        label: str,
        client: DiagnosticClient,
    ) -> None:
        if self.heartbeat is None:
            return
        try:
            self.heartbeat.send(
                identity,
                service_status="busy",
                current_command_id=command_id,
                activity=f"Running {label}",
                client=client,
            )
        except Exception as exc:
            LOGGER.warning("Unable to report diagnostic heartbeat: %s", exc)

    @staticmethod
    def _event(
        client: DiagnosticClient,
        identity: AgentIdentity,
        command_id: str,
        *,
        status: str,
        message: str,
        details: dict[str, Any],
    ) -> None:
        client.command_event(
            command_id,
            {
                "schema_version": "1.0",
                "message_type": "command.event",
                "status": status,
                "message": message[:1024],
                "details": details,
                "occurred_at": timestamp(),
            },
            credential=identity.credential,
        )


def _diagnostic_spec(diagnostic_type: str, target_ip: str) -> DiagnosticSpec:
    if diagnostic_type == "ping":
        return DiagnosticSpec(
            "Ping",
            ("ping", "-n", "4", target_ip),
            f"ping -n 4 {target_ip}",
            20,
        )
    if diagnostic_type == "reverse_dns":
        return DiagnosticSpec(
            "Reverse DNS",
            ("nslookup", target_ip),
            f"nslookup {target_ip}",
            20,
        )
    if diagnostic_type == "arp_cache":
        return DiagnosticSpec(
            "ARP cache",
            ("arp", "-a", target_ip),
            f"arp -a {target_ip}",
            10,
        )
    if diagnostic_type == "powershell_test":
        script = (
            f"Test-NetConnection {target_ip} -InformationLevel Detailed | Out-String"
        )
        return DiagnosticSpec(
            "PowerShell test",
            (
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ),
            f"Test-NetConnection {target_ip} -InformationLevel Detailed",
            35,
        )
    if diagnostic_type in {
        "inventory_nmap",
        "network_services_nmap",
        "standard_nmap",
        "full_tcp_nmap",
    }:
        nmap = find_nmap_executable()
        if not nmap:
            raise RuntimeError("Nmap is not installed on this agent")
        if diagnostic_type == "inventory_nmap":
            return DiagnosticSpec(
                "Inventory Nmap",
                (
                    nmap,
                    "-Pn",
                    "--top-ports",
                    "200",
                    "-sV",
                    "--version-light",
                    "--max-retries",
                    "2",
                    target_ip,
                ),
                (
                    "nmap -Pn --top-ports 200 -sV --version-light "
                    f"--max-retries 2 {target_ip}"
                ),
                2 * 60,
            )
        if diagnostic_type == "network_services_nmap":
            return DiagnosticSpec(
                "Network Services Nmap",
                (
                    nmap,
                    "-Pn",
                    "-sU",
                    "-sT",
                    "-p",
                    NETWORK_SERVICE_PORTS,
                    "-sV",
                    "--version-light",
                    "--max-retries",
                    "2",
                    target_ip,
                ),
                (
                    f"nmap -Pn -sU -sT -p {NETWORK_SERVICE_PORTS} "
                    f"-sV --version-light --max-retries 2 {target_ip}"
                ),
                6 * 60,
            )
        if diagnostic_type == "standard_nmap":
            return DiagnosticSpec(
                "Standard Nmap",
                (
                    nmap,
                    "-Pn",
                    "--top-ports",
                    "1000",
                    "-sV",
                    "--version-light",
                    target_ip,
                ),
                f"nmap -Pn --top-ports 1000 -sV --version-light {target_ip}",
                4 * 60,
            )
        return DiagnosticSpec(
            "Full TCP Nmap",
            (nmap, "-Pn", "-p-", "-sV", "--version-all", target_ip),
            f"nmap -Pn -p- -sV --version-all {target_ip}",
            20 * 60,
        )
    raise RuntimeError(f"Unsupported diagnostic: {diagnostic_type}")


def _trim_output(stdout: str | bytes | None, stderr: str | bytes | None) -> str:
    parts = [_decode(stdout).strip(), _decode(stderr).strip()]
    combined = "\n\n".join(part for part in parts if part)
    if len(combined) <= MAX_OUTPUT_CHARS:
        return combined
    return combined[:MAX_OUTPUT_CHARS] + "\n\n[output truncated]"


def _decode(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _ping_result(target_ip: str, output: str) -> str:
    target_reply = re.compile(
        rf"^\s*Reply from {re.escape(target_ip)}:\s*bytes\s*=\s*\d+",
        re.IGNORECASE | re.MULTILINE,
    )
    if target_reply.search(output):
        return "reply"
    normalized = output.lower()
    if any(
        term in normalized
        for term in ("unreachable", "general failure", "transmit failed")
    ):
        return "unreachable"
    if "timed out" in normalized:
        return "timeout"
    return "no_reply"


def _summary(
    label: str, diagnostic_type: str, exit_code: int, ping_result: str | None = None
) -> str:
    if diagnostic_type == "ping":
        outcome = {
            "reply": "host responded",
            "unreachable": "destination unreachable",
            "timeout": "timed out",
        }.get(ping_result, "no echo reply")
        return f"Ping completed: {outcome}"
    return (
        f"{label} completed"
        if exit_code == 0
        else f"{label} completed with exit code {exit_code}"
    )
