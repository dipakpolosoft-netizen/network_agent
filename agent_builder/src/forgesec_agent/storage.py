"""Atomic local persistence for identity, state, queues, and scan data."""

from __future__ import annotations

import json
import os
import threading
import uuid
from pathlib import Path
from typing import Any

from forgesec_agent.config import AgentPaths


class AgentStorage:
    DIRECTORIES = (
        "config",
        "identity",
        "state",
        "public",
        "queue",
        "scans",
        "logs",
    )

    def __init__(self, paths: AgentPaths):
        self.paths = paths
        self._lock = threading.RLock()

    def initialize(self) -> None:
        for name in self.DIRECTORIES:
            (self.paths.root / name).mkdir(parents=True, exist_ok=True)

    def read_json(self, path: Path) -> dict[str, Any] | None:
        with self._lock:
            if not path.is_file():
                return None
            return json.loads(path.read_text(encoding="utf-8"))

    def write_json(self, path: Path, document: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        serialized = json.dumps(document, indent=2, sort_keys=True) + "\n"
        with self._lock:
            try:
                with temporary.open("w", encoding="utf-8", newline="\n") as handle:
                    handle.write(serialized)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)

    def write_text(self, path: Path, value: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        with self._lock:
            try:
                with temporary.open("w", encoding="utf-8", newline="\n") as handle:
                    handle.write(value)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)

    def remove(self, path: Path) -> None:
        with self._lock:
            path.unlink(missing_ok=True)
