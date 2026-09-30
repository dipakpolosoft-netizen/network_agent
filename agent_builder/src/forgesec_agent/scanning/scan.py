"""Handle one selected-device scan command."""

from __future__ import annotations

from typing import Any

from forgesec_agent.enrollment import AgentIdentity, timestamp
from forgesec_agent.heartbeat import HeartbeatSender
from forgesec_agent.job_scheduler import ScanProtocolClient, ScanScheduler
from forgesec_agent.scanning.nmap_runner import scan_profile_plan
from forgesec_agent.scanning.policy import require_approved


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
        try:
            if payload.get("profile_plan") != scan_profile_plan(
                str(payload["profile"])
            ):
                raise ValueError("Probe scan profile differs from the requested plan")
            require_approved(
                payload.get("scope_policy"),
                [str(target["ip"]) for target in payload["targets"]],
                str(payload["profile"]),
            )
            if payload["profile"] == "full_tcp":
                if len(payload["targets"]) != 1:
                    raise ValueError("Full TCP is limited to one selected target")
                if payload.get("full_tcp_confirmed") is not True:
                    raise ValueError("Full TCP escalation was not confirmed")
        except (ValueError, KeyError, TypeError) as exc:
            self._event(client, identity, command_id, "failed", str(exc)[:1024])
            return
        self._event(
            client, identity, command_id, "running", "Selected-device scan started"
        )

        def keepalive() -> None:
            self.heartbeat.send(
                identity,
                service_status="busy",
                current_command_id=command_id,
                activity="Scanning selected devices",
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
