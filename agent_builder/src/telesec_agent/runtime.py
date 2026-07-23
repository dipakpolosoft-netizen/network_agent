"""Composition root shared by console and Windows service execution."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path

from telesec_agent.command_loop import AgentLoop
from telesec_agent.commands import CommandDispatcher
from telesec_agent.config import AgentPaths, default_data_directory
from telesec_agent.enrollment import EnrollmentManager, IdentityStore
from telesec_agent.heartbeat import HeartbeatSender
from telesec_agent.job_scheduler import ScanScheduler
from telesec_agent.logging_setup import configure_logging
from telesec_agent.scanning.discovery import DiscoveryCommandHandler
from telesec_agent.scanning.nmap_runner import NmapRunner
from telesec_agent.scanning.scan import ScanCommandHandler
from telesec_agent.security.dpapi import DpapiProtector, SecretProtector
from telesec_agent.storage import AgentStorage


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
    discovery = DiscoveryCommandHandler(nmap)
    scheduler = ScanScheduler(nmap, storage, paths.root / "scans")
    scan = ScanCommandHandler(scheduler, heartbeat)
    commands = CommandDispatcher(discovery, scan)
    return AgentRuntime(
        AgentLoop(
            enrollment,
            heartbeat,
            commands,
            stop_event or threading.Event(),
        )
    )
