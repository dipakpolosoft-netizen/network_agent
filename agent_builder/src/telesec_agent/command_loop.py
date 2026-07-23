"""Long-running service loop; command claiming is added in the next phase."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Protocol

from telesec_agent.api_client import ApiClientError, TelesecApiClient
from telesec_agent.config import ConfigurationError
from telesec_agent.enrollment import AgentIdentity, EnrollmentManager
from telesec_agent.heartbeat import HeartbeatSender

LOGGER = logging.getLogger(__name__)


class CommandHandler(Protocol):
    def handle(
        self,
        command: dict[str, Any],
        identity: AgentIdentity,
        client: TelesecApiClient,
    ) -> None: ...


class AgentLoop:
    def __init__(
        self,
        enrollment: EnrollmentManager,
        heartbeat: HeartbeatSender,
        command_handler: CommandHandler,
        stop_event: threading.Event,
    ):
        self.enrollment = enrollment
        self.heartbeat = heartbeat
        self.command_handler = command_handler
        self.stop_event = stop_event

    def run(self) -> None:
        next_heartbeat_at = 0.0
        identity: AgentIdentity | None = None
        while not self.stop_event.is_set():
            try:
                identity = self.enrollment.ensure_enrolled()
                client = TelesecApiClient(identity.server_url)
                now = time.monotonic()
                if now >= next_heartbeat_at:
                    self.heartbeat.send(identity, client=client)
                    next_heartbeat_at = now + identity.heartbeat_interval_seconds
                command = client.next_command(credential=identity.credential)
                if command is not None:
                    self.command_handler.handle(command, identity, client)
                    next_heartbeat_at = 0.0
                    delay = 0.1
                else:
                    delay = 3
            except (ApiClientError, ConfigurationError, OSError, ValueError) as exc:
                LOGGER.warning("Agent cycle failed: %s", exc)
                delay = 15
            except Exception:
                LOGGER.exception("Agent command failed")
                delay = 5
            self.stop_event.wait(delay)
        if identity is not None:
            try:
                client = TelesecApiClient(identity.server_url, timeout_seconds=5.0)
                self.heartbeat.send(
                    identity,
                    service_status="offline",
                    client=client,
                )
            except Exception as exc:
                LOGGER.warning("Unable to report final offline status: %s", exc)
