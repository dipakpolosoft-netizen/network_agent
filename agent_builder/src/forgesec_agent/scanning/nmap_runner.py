"""Structured Nmap invocation for discovery-only scans."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
NETWORK_TCP_PORTS = (22, 53, 80, 443, 445, 3389, 8080, 8443)
NETWORK_UDP_PORTS = (53, 67, 69, 123, 137, 161, 500, 4500, 5353, 1900)
NETWORK_SERVICE_PORTS = (
    f"T:{','.join(map(str, NETWORK_TCP_PORTS))},"
    f"U:{','.join(map(str, NETWORK_UDP_PORTS))}"
)
SCAN_PROFILES = {
    "inventory": {
        "tcp_top_ports": 200,
        "version_detection": "light",
        "max_retries": 2,
        "timeout_seconds": 8 * 60,
    },
    "network_services": {
        "tcp_ports": NETWORK_TCP_PORTS,
        "udp_ports": NETWORK_UDP_PORTS,
        "version_detection": "light",
        "max_retries": 2,
        "timeout_seconds": 12 * 60,
        "os_detection": False,
    },
    "standard": {
        "tcp_top_ports": 1000,
        "version_detection": "light",
        "timeout_seconds": 15 * 60,
    },
    "full_tcp": {
        "tcp_all_ports": True,
        "version_detection": "full",
        "timeout_seconds": 45 * 60,
    },
}


def scan_profile_plan(profile: str) -> dict:
    definition = SCAN_PROFILES[profile]
    return {
        "tcp_top_ports": definition.get("tcp_top_ports"),
        "tcp_all_ports": bool(definition.get("tcp_all_ports")),
        "tcp_ports": list(definition.get("tcp_ports", ())),
        "udp_ports": list(definition.get("udp_ports", ())),
        "version_detection": definition["version_detection"],
        "os_detection": (
            "when_privileged" if definition.get("os_detection", True)
            else "not_requested"
        ),
        "host_timeout_seconds": definition["timeout_seconds"],
        "assume_host_up": True,
        "open_only_output": True,
    }


class NmapUnavailable(RuntimeError):
    pass


class NmapExecutionError(RuntimeError):
    pass


class ScanCancelled(NmapExecutionError):
    def __init__(self, message: str, *, partial_xml: str | None = None):
        super().__init__(message)
        self.partial_xml = partial_xml


class ScanTimedOut(NmapExecutionError):
    def __init__(self, message: str, *, partial_xml: str | None = None):
        super().__init__(message)
        self.partial_xml = partial_xml


@dataclass(frozen=True, slots=True)
class DiscoveryProgress:
    elapsed_seconds: int
    progress_percent: float | None
    found_count: int


_HOST_XML = re.compile(r"<host(?:\s[^>]*)?>.*?</host>", re.DOTALL)
_PERCENT = re.compile(r"About\s+(\d+(?:\.\d+)?)%\s+done", re.IGNORECASE)


def find_nmap_executable() -> str | None:
    discovered = shutil.which("nmap")
    if discovered:
        return discovered
    for variable in ("ProgramFiles", "ProgramFiles(x86)"):
        program_files = os.getenv(variable)
        if not program_files:
            continue
        candidate = Path(program_files) / "Nmap" / "nmap.exe"
        if candidate.is_file():
            return str(candidate)
    return None


class NmapRunner:
    def __init__(self, *, timeout_seconds: int = 180):
        self.timeout_seconds = timeout_seconds

    def discover(
        self,
        network: str,
        *,
        exclusions: list[str] | None = None,
        cancel_requested: Callable[[], bool] = lambda: False,
        progress_callback: Callable[[DiscoveryProgress], None] | None = None,
    ) -> str:
        executable = find_nmap_executable()
        if not executable:
            raise NmapUnavailable("Nmap is not installed or is not on PATH")
        with tempfile.TemporaryDirectory(prefix="forgesec-discovery-") as directory:
            xml_path = Path(directory) / "discovery.xml"
            stats_path = Path(directory) / "nmap.stderr"
            command = [
                executable,
                "-sn",
                "--host-timeout",
                "30s",
                "--stats-every",
                "2s",
                "-oX",
                str(xml_path),
            ]
            if exclusions:
                command.extend(["--exclude", ",".join(exclusions)])
            command.append(network)
            try:
                with stats_path.open("wb") as stats_handle:
                    process = subprocess.Popen(
                        command,
                        stdout=subprocess.DEVNULL,
                        stderr=stats_handle,
                        creationflags=NO_WINDOW,
                    )
                    started = time.monotonic()
                    last_reported: tuple[float | None, int] | None = None
                    last_reported_at = -2
                    while process.poll() is None:
                        partial_xml, found_count = _partial_discovery_xml(xml_path)
                        progress_percent = _progress_percent(stats_path)
                        current = (progress_percent, found_count)
                        elapsed = int(time.monotonic() - started)
                        if progress_callback and (
                            current != last_reported or elapsed - last_reported_at >= 2
                        ):
                            progress_callback(
                                DiscoveryProgress(
                                    elapsed_seconds=elapsed,
                                    progress_percent=progress_percent,
                                    found_count=found_count,
                                )
                            )
                            last_reported = current
                            last_reported_at = elapsed
                        if cancel_requested():
                            _stop_process(process)
                            raise ScanCancelled(
                                "Discovery cancelled",
                                partial_xml=partial_xml,
                            )
                        if time.monotonic() - started >= self.timeout_seconds:
                            _stop_process(process)
                            final_partial_xml, _ = _partial_discovery_xml(xml_path)
                            raise ScanTimedOut(
                                "Nmap discovery timed out",
                                partial_xml=final_partial_xml or partial_xml,
                            )
                        time.sleep(0.5)
            except OSError as exc:
                raise NmapExecutionError("Unable to start Nmap") from exc
            stderr = _safe_read_text(stats_path)
            if process.returncode != 0:
                raise NmapExecutionError(
                    (stderr.strip() or "Nmap discovery failed")[:2048]
                )
            xml_output = _safe_read_text(xml_path)
            if not xml_output.strip():
                raise NmapExecutionError("Nmap returned no XML output")
            if progress_callback:
                _partial, found_count = _partial_discovery_xml(xml_path)
                progress_callback(
                    DiscoveryProgress(
                        elapsed_seconds=int(time.monotonic() - started),
                        progress_percent=100.0,
                        found_count=found_count,
                    )
                )
            return xml_output

    def verify_known_host(
        self,
        ip: str,
        *,
        cancel_requested: Callable[[], bool],
        activity_callback: Callable[[], None] | None = None,
    ) -> str:
        executable = find_nmap_executable()
        if not executable:
            raise NmapUnavailable("Nmap is not installed or is not on PATH")
        command = [
            executable, "-sn", "-n", "--disable-arp-ping", "-PE",
            "-PS22,80,443", "-PA80,443", "--max-retries", "1",
            "--host-timeout", "15s", "-oX", "-", ip,
        ]
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=NO_WINDOW,
                text=True,
            )
        except OSError as exc:
            raise NmapExecutionError("Unable to start known-host check") from exc
        started = time.monotonic()
        while True:
            try:
                stdout, stderr = process.communicate(timeout=1)
                break
            except subprocess.TimeoutExpired:
                if cancel_requested():
                    _stop_process(process)
                    raise ScanCancelled("Known-host check cancelled") from None
                if time.monotonic() - started >= 20:
                    _stop_process(process)
                    raise ScanTimedOut("Known-host check timed out") from None
                if activity_callback:
                    activity_callback()
        if process.returncode != 0:
            raise NmapExecutionError(
                (stderr.strip() or "Known-host check failed")[:512]
            )
        if not stdout.strip():
            raise NmapExecutionError("Nmap returned no known-host XML output")
        return stdout

    def scan_host(
        self,
        ip: str,
        profile: str,
        *,
        cancel_requested: Callable[[], bool],
    ) -> str:
        executable = find_nmap_executable()
        if not executable:
            raise NmapUnavailable("Nmap is not installed or is not on PATH")
        privileged = _is_windows_admin()
        profile_definition = SCAN_PROFILES.get(profile)
        if profile_definition is None:
            raise NmapExecutionError(f"Unsupported scan profile: {profile}")
        if profile_definition.get("udp_ports") and not privileged:
            raise NmapExecutionError(
                "Network services requires an elevated probe for UDP scanning"
            )
        timeout_seconds = int(profile_definition["timeout_seconds"])
        command = [executable, "-Pn", "-T3"]
        if profile_definition.get("udp_ports"):
            command.extend(["-sU", "-sS" if privileged else "-sT"])
        else:
            command.append("-sS" if privileged else "-sT")
        if profile_definition.get("tcp_all_ports"):
            command.append("-p-")
        elif profile_definition.get("tcp_top_ports"):
            command.extend(["--top-ports", str(profile_definition["tcp_top_ports"])])
        else:
            command.extend(["-p", NETWORK_SERVICE_PORTS])
        version_flag = (
            "--version-all" if profile_definition["version_detection"] == "full"
            else "--version-light"
        )
        command.extend(["-sV", version_flag])
        if profile_definition.get("max_retries") is not None:
            command.extend(["--max-retries", str(profile_definition["max_retries"])])
        command.append("--open")
        if privileged and profile_definition.get("os_detection", True):
            command.extend(["-O", "--osscan-limit"])
        command.extend(["--host-timeout", f"{timeout_seconds}s", "-oX", "-", ip])
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=NO_WINDOW,
                text=True,
            )
        except OSError as exc:
            raise NmapExecutionError("Unable to start Nmap") from exc
        started = time.monotonic()
        while True:
            try:
                stdout, stderr = process.communicate(timeout=1)
                break
            except subprocess.TimeoutExpired:
                try:
                    cancelled = cancel_requested()
                except Exception:
                    _stop_process(process)
                    raise
                if cancelled:
                    _stop_process(process)
                    raise ScanCancelled("Scan cancelled") from None
                if time.monotonic() - started >= timeout_seconds:
                    _stop_process(process)
                    raise ScanTimedOut("Host scan timed out") from None
        if process.returncode != 0:
            raise NmapExecutionError((stderr.strip() or "Nmap scan failed")[:4096])
        if not stdout.strip():
            raise NmapExecutionError("Nmap returned no XML output")
        return stdout


def _is_windows_admin() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _stop_process(process: subprocess.Popen) -> None:
    process.terminate()
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()


def _safe_read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _partial_discovery_xml(path: Path) -> tuple[str | None, int]:
    content = _safe_read_text(path)
    hosts: list[str] = []
    found_count = 0
    for match in _HOST_XML.finditer(content):
        fragment = match.group(0)
        try:
            host = ElementTree.fromstring(fragment)
        except ElementTree.ParseError:
            continue
        hosts.append(fragment)
        status = host.find("status")
        if status is not None and status.get("state") == "up":
            found_count += 1
    if not hosts:
        return None, 0
    return f"<nmaprun>{''.join(hosts)}</nmaprun>", found_count


def _progress_percent(path: Path) -> float | None:
    matches = _PERCENT.findall(_safe_read_text(path))
    return float(matches[-1]) if matches else None
