"""Composition root shared by console and Windows service execution."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path

from forgesec_agent.command_diagnostics import DeviceDiagnosticHandler
from forgesec_agent.command_loop import AgentLoop
from forgesec_agent.commands import CommandDispatcher
from forgesec_agent.config import AgentPaths, default_data_directory
from forgesec_agent.enrollment import EnrollmentManager, IdentityStore
from forgesec_agent.heartbeat import HeartbeatSender
from forgesec_agent.job_scheduler import ScanScheduler
from forgesec_agent.logging_setup import configure_logging
from forgesec_agent.scanning.discovery import DiscoveryCommandHandler
from forgesec_agent.scanning.nmap_runner import NmapRunner
from forgesec_agent.scanning.scan import ScanCommandHandler
from forgesec_agent.security.dpapi import DpapiProtector, SecretProtector
from forgesec_agent.storage import AgentStorage


@dataclass(slots=True)
class AgentRuntime:
    loop: AgentLoop

    def run(self) -> None:
        self.loop.run()


def build_runtime(
    *,
    console: bool,
    stop_event: threading.Event | None = None,
    data_directory: Path | None = None,
    protector: SecretProtector | None = None,
) -> AgentRuntime:
    paths = AgentPaths((data_directory or default_data_directory()).resolve())
    storage = AgentStorage(paths)
    storage.initialize()
    configure_logging(paths.log, console=console)
    identities = IdentityStore(storage, paths, protector or DpapiProtector())
    enrollment = EnrollmentManager(storage, paths, identities)
    heartbeat = HeartbeatSender(storage, paths.state, paths.public_status)
    nmap = NmapRunner()
    discovery = DiscoveryCommandHandler(nmap, heartbeat=heartbeat)
    scheduler = ScanScheduler(nmap, storage, paths.root / "scans")
    scan = ScanCommandHandler(scheduler, heartbeat)
    diagnostics = DeviceDiagnosticHandler(heartbeat)
    commands = CommandDispatcher(discovery, scan, diagnostics)
    return AgentRuntime(
        AgentLoop(
            enrollment,
            heartbeat,
            commands,
            stop_event or threading.Event(),
        )
    )
