"""Persistent command creation, claiming, and status transitions."""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from uuid import uuid4

from telesec_api.activity import record_activity
from telesec_api.commands.models import CommandEvent
from telesec_api.settings import Settings
from telesec_api.storage import JsonStore
from telesec_api.time import isoformat, parse_timestamp, utc_now


class CommandError(RuntimeError):
    pass


class CommandNotFound(CommandError):
    pass


class CommandOwnershipError(CommandError):
    pass


class InvalidCommandTransition(CommandError):
    pass


class CommandService:
    def __init__(self, store: JsonStore, settings: Settings):
        self.store = store
        self.settings = settings

    def create(
        self,
        *,
        agent_id: str,
        command_type: str,
        payload: dict[str, Any],
    ) -> dict:
        now = utc_now()
        command_id = str(uuid4())
        record = {
            "schema_version": "1.0",
            "message_type": "agent.command",
            "command_id": command_id,
            "agent_id": agent_id,
            "command_type": command_type,
            "created_at": isoformat(now),
            "expires_at": isoformat(
                now + timedelta(seconds=self.settings.command_ttl_seconds)
            ),
            "payload": payload,
            "status": "queued",
            "claimed_at": None,
            "updated_at": isoformat(now),
            "last_message": None,
        }
        self.store.write("commands", command_id, record)
        record_activity(
            self.store,
            event_type="command.queued",
            message=f"{command_type} command queued",
            resource_type="command",
            resource_id=command_id,
            details={"agent_id": agent_id},
        )
        return record

    def claim_next(self, agent_id: str) -> dict | None:
        with self.store.locked():
            commands = sorted(
                self.store.list("commands"), key=lambda item: item["created_at"]
            )
            now = utc_now()
            for command in commands:
                if command["agent_id"] != agent_id or command["status"] != "queued":
                    continue
                if parse_timestamp(command["expires_at"]) <= now:
                    command["status"] = "expired"
                    command["updated_at"] = isoformat(now)
                    self.store.write("commands", command["command_id"], command)
                    continue
                command["status"] = "claimed"
                command["claimed_at"] = isoformat(now)
                command["updated_at"] = isoformat(now)
                self.store.write("commands", command["command_id"], command)
                return command
        return None

    def update_from_agent(
        self,
        *,
        command_id: str,
        agent_id: str,
        event: CommandEvent,
    ) -> dict:
        with self.store.locked():
            command = self.store.read("commands", command_id)
            if command is None:
                raise CommandNotFound
            if command["agent_id"] != agent_id:
                raise CommandOwnershipError
            allowed = {
                "claimed": {"running", "failed", "cancelled"},
                "running": {"running", "completed", "failed", "cancelled"},
            }
            if event.status not in allowed.get(command["status"], set()):
                raise InvalidCommandTransition
            command["status"] = event.status
            command["last_message"] = event.message
            command["updated_at"] = isoformat(utc_now())
            self.store.write("commands", command_id, command)
            if event.status != "running":
                record_activity(
                    self.store,
                    event_type=f"command.{event.status}",
                    message=event.message,
                    actor_type="agent",
                    actor_id=agent_id,
                    resource_type="command",
                    resource_id=command_id,
                    details=event.details,
                    severity="error" if event.status == "failed" else "info",
                )
            return command
