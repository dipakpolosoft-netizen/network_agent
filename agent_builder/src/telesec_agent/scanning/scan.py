"""Handle one selected-device scan command."""

from __future__ import annotations

from typing import Any

from telesec_agent.enrollment import AgentIdentity, timestamp
from telesec_agent.heartbeat import HeartbeatSender
from telesec_agent.job_scheduler import ScanProtocolClient, ScanScheduler


class ScanCommandHandler:
    def __init__(self, scheduler: ScanScheduler, heartbeat: HeartbeatSender):
        self.scheduler = scheduler
        self.heartbeat = heartbeat

    def handle(
        self,
        command: dict[str, Any],
        identity: AgentIdentity,
        client: ScanProtocolClient,
    ) -> None:
        command_id = str(command["command_id"])
        payload = command["payload"]
        self._event(
            client, identity, command_id, "running", "Selected-device scan started"
        )

        def keepalive() -> None:
            self.heartbeat.send(
                identity,
                service_status="busy",
                current_command_id=command_id,
                client=client,
            )

        keepalive()
        try:
            final_status = self.scheduler.run(
                scan_id=str(payload["scan_id"]),
                profile=str(payload["profile"]),
                targets=list(payload["targets"]),
                concurrency=int(payload["concurrency"]),
                identity=identity,
                client=client,
                keepalive=keepalive,
            )
            event_status = "cancelled" if final_status == "cancelled" else "completed"
            self._event(
                client,
                identity,
                command_id,
                event_status,
                f"Selected-device scan finished with status {final_status}",
            )
        except Exception as exc:
            self._event(
                client,
                identity,
                command_id,
                "failed",
                str(exc)[:1024] or "Selected-device scan failed",
            )
            raise

    @staticmethod
    def _event(
        client: ScanProtocolClient,
        identity: AgentIdentity,
        command_id: str,
        status: str,
        message: str,
    ) -> None:
        client.command_event(
            command_id,
            {
                "schema_version": "1.0",
                "message_type": "command.event",
                "status": status,
                "message": message,
                "details": {},
                "occurred_at": timestamp(),
            },
            credential=identity.credential,
        )
