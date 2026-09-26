"""Persistent command creation, claiming, and status transitions."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from forgesec_api.activity import record_activity
from forgesec_api.commands.models import CommandEvent
from forgesec_api.settings import Settings
from forgesec_api.storage import JsonStore
from forgesec_api.time import isoformat, parse_timestamp, utc_now


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
            "last_details": {},
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

    def get(self, command_id: str) -> dict:
        with self.store.locked():
            command = self.store.read("commands", command_id)
            if command is None:
                raise CommandNotFound
            self._expire_queued(command, utc_now())
            return command

    def _expire_queued(self, command: dict, now: datetime) -> bool:
        if (
            command["status"] != "queued"
            or parse_timestamp(command["expires_at"]) > now
        ):
            return False
        command["status"] = "expired"
        command["updated_at"] = isoformat(now)
        command["last_message"] = "Command expired before the agent claimed it"
        self.store.write("commands", command["command_id"], command)
        record_activity(
            self.store,
            event_type="command.expired",
            message=command["last_message"],
            resource_type="command",
            resource_id=command["command_id"],
            details={"agent_id": command["agent_id"]},
        )
        return True

    def cancel_pending(self, command_id: str, *, message: str) -> dict:
        with self.store.locked():
            command = self.store.read("commands", command_id)
            if command is None:
                raise CommandNotFound
            if command["status"] != "queued":
                return command
            now = isoformat(utc_now())
            command["status"] = "cancelled"
            command["last_message"] = message
            command["updated_at"] = now
            self.store.write("commands", command_id, command)
            record_activity(
                self.store,
                event_type="command.cancelled",
                message=message,
                resource_type="command",
                resource_id=command_id,
                details={"agent_id": command["agent_id"]},
            )
            return command

    def claim_next(
        self, agent_id: str, allowed: Callable[[dict], bool] | None = None
    ) -> dict | None:
        with self.store.locked():
            agent = self.store.read("agents", agent_id)
            if agent is None or agent.get("revoked_at"):
                return None
            commands = sorted(
                self.store.list("commands"), key=lambda item: item["created_at"]
            )
            now = utc_now()
            for command in commands:
                if command["agent_id"] != agent_id or command["status"] != "queued":
                    continue
                if self._expire_queued(command, now):
                    continue
                if allowed is not None and not allowed(command):
                    self.cancel_pending(
                        command["command_id"],
                        message="Site scope approval changed before the job started",
                    )
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
            command["last_details"] = event.details
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
