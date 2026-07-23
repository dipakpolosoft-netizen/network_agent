"""Structured Nmap invocation for discovery-only scans."""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class NmapUnavailable(RuntimeError):
    pass


class NmapExecutionError(RuntimeError):
    pass


class ScanCancelled(NmapExecutionError):
    pass


class ScanTimedOut(NmapExecutionError):
    pass


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

    def discover(self, network: str) -> str:
        executable = find_nmap_executable()
        if not executable:
            raise NmapUnavailable("Nmap is not installed or is not on PATH")
        command = [
            executable,
            "-sn",
            "--host-timeout",
            "30s",
            "-oX",
            "-",
            network,
        ]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                check=False,
                creationflags=NO_WINDOW,
                text=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise NmapExecutionError("Nmap discovery timed out") from exc
        except OSError as exc:
            raise NmapExecutionError("Unable to start Nmap") from exc
        if result.returncode != 0:
            detail = result.stderr.strip() or "Nmap discovery failed"
            raise NmapExecutionError(detail[:2048])
        if not result.stdout.strip():
            raise NmapExecutionError("Nmap returned no XML output")
        return result.stdout

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
        command = [executable, "-Pn", "-sS" if privileged else "-sT"]
        timeout_seconds = 15 * 60
        if profile == "standard":
            command.extend(["--top-ports", "1000"])
        elif profile == "full_tcp":
            command.append("-p-")
            timeout_seconds = 45 * 60
        else:
            raise NmapExecutionError(f"Unsupported scan profile: {profile}")
        command.extend(["-sV", "--version-light", "--open"])
        if privileged:
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
                if cancel_requested():
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
