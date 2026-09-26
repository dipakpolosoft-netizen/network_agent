"""Bounded device diagnostics for selected discovered hosts."""

from __future__ import annotations

import ipaddress
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Protocol

from forgesec_agent.enrollment import AgentIdentity, timestamp
from forgesec_agent.scanning.nmap_runner import (
    NETWORK_SERVICE_PORTS,
    find_nmap_executable,
)
from forgesec_agent.scanning.policy import require_approved

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
MAX_OUTPUT_CHARS = 16000


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
            require_approved(payload.get("scope_policy"), [target_ip])
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
            details = {
                "diagnostic_type": diagnostic_type,
                "target_ip": target_ip,
                "command_line": spec.display,
                "output": output,
                "exit_code": result.returncode,
                "duration_ms": int((time.monotonic() - started_at) * 1000),
                "started_at": started,
                "completed_at": completed,
                "reachable": (
                    result.returncode == 0 if diagnostic_type == "ping" else None
                ),
            }
            self._event(
                client,
                identity,
                command_id,
                status="completed",
                message=_summary(spec.label, diagnostic_type, result.returncode),
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


def _summary(label: str, diagnostic_type: str, exit_code: int) -> str:
    if diagnostic_type == "ping":
        return (
            "Ping completed: host responded"
            if exit_code == 0
            else "Ping completed: no response"
        )
    return (
        f"{label} completed"
        if exit_code == 0
        else f"{label} completed with exit code {exit_code}"
    )
