"""Windows Service Control Manager integration."""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from pathlib import Path

from telesec_agent.runtime import build_runtime

SERVICE_NAME = "TelesecNetworkAgent"
SERVICE_DISPLAY_NAME = "Telesec Network Agent"
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
SERVICE_STATE_NAMES = {
    1: "STOPPED",
    2: "START_PENDING",
    3: "STOP_PENDING",
    4: "RUNNING",
}


def _run_sc(*arguments: str) -> None:
    result = subprocess.run(
        ["sc.exe", *arguments],
        capture_output=True,
        check=False,
        creationflags=NO_WINDOW,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(detail or f"sc.exe failed with code {result.returncode}")


def _service_state() -> str | None:
    result = subprocess.run(
        ["sc.exe", "query", SERVICE_NAME],
        capture_output=True,
        check=False,
        creationflags=NO_WINDOW,
        text=True,
    )
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        if "STATE" not in line or ":" not in line:
            continue
        value = line.split(":", 1)[1].strip().split()[0]
        if value.isdigit():
            return SERVICE_STATE_NAMES.get(int(value), "UNKNOWN")
    return "UNKNOWN"


def _service_exists() -> bool:
    return _service_state() is not None


def _wait_for_service_state(expected: str | None, timeout_seconds: float = 30) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if _service_state() == expected:
            return
        time.sleep(0.5)
    label = expected or "removed"
    raise RuntimeError(f"Telesec service did not become {label} in time")


def service_command(action: str) -> None:
    if action == "install":
        if not getattr(sys, "frozen", False):
            raise RuntimeError(
                "Service installation requires the packaged agent executable"
            )
        executable = str(Path(sys.executable).resolve())
        binary_path = f'"{executable}" service-run'
        operation = "config" if _service_exists() else "create"
        _run_sc(
            operation,
            SERVICE_NAME,
            "binPath=",
            binary_path,
            "start=",
            "auto",
            "DisplayName=",
            SERVICE_DISPLAY_NAME,
        )
        _run_sc(
            "description",
            SERVICE_NAME,
            "Discovers and inventories authorized networks for Telesec.",
        )
        _run_sc("failure", SERVICE_NAME, "reset=", "86400", "actions=", "restart/5000")
        return
    if action == "start":
        if _service_state() == "RUNNING":
            return
        _run_sc("start", SERVICE_NAME)
        _wait_for_service_state("RUNNING")
        return
    if action == "stop":
        state = _service_state()
        if state is None or state == "STOPPED":
            return
        _run_sc("stop", SERVICE_NAME)
        _wait_for_service_state("STOPPED")
        return
    if action == "remove":
        state = _service_state()
        if state is None:
            return
        if state != "STOPPED":
            _run_sc("stop", SERVICE_NAME)
            _wait_for_service_state("STOPPED")
        _run_sc("delete", SERVICE_NAME)
        _wait_for_service_state(None)
        return
    raise ValueError(f"Unsupported service action: {action}")


try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil
except ImportError:  # pragma: no cover - Windows build dependency
    servicemanager = None
    win32event = None
    win32service = None
    win32serviceutil = None


if win32serviceutil is not None:

    class TelesecWindowsService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME

        def __init__(self, args):
            super().__init__(args)
            self.stop_event = threading.Event()
            self.stop_handle = win32event.CreateEvent(None, 0, 0, None)

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.stop_event.set()
            win32event.SetEvent(self.stop_handle)

        def SvcDoRun(self):
            runtime = build_runtime(console=False, stop_event=self.stop_event)
            runtime.run()


def run_service_dispatcher() -> None:
    if servicemanager is None or win32serviceutil is None:
        raise RuntimeError("Windows service support is unavailable")
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(TelesecWindowsService)
    servicemanager.StartServiceCtrlDispatcher()
