"""Thread-safe atomic JSON persistence for the single-process v1 server."""

from __future__ import annotations

import json
import os
import re
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9_.-]+$")


class StorageError(RuntimeError):
    """Base persistence error."""


class InvalidStorageKey(StorageError):
    """Raised when a collection or record key is unsafe."""


class CorruptDocument(StorageError):
    """Raised when a persisted JSON document cannot be decoded."""


class JsonStore:
    FILTER_FIELDS = frozenset({"site_id", "asset_id", "source_asset_id"})
    ASSET_SEARCH_FIELDS = (
        "display_name",
        "hostname",
        "last_ip",
        "mac",
        "vendor",
        "device_type",
    )
    COLLECTIONS = (
        "deployment",
        "sites",
        "approved-scopes",
        "users",
        "sessions",
        "auth-attempts",
        "agents",
        "agent-credentials",
        "scanner-workers",
        "scanner-worker-credentials",
        "scanner-worker-jobs",
        "assets",
        "asset-observations",
        "asset-evidence-reviews",
        "asset-mac-index",
        "asset-ip-index",
        "asset-migrations",
        "vulnerability-cache",
        "vulnerability-assessments",
        "enrollments",
        "commands",
        "discoveries",
        "scans",
        "activity",
    )

    def __init__(self, root: Path):
        self.root = root.resolve()
        self._lock = threading.RLock()

    def initialize(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        for collection in self.COLLECTIONS:
            (self.root / collection).mkdir(parents=True, exist_ok=True)

    @contextmanager
    def locked(self) -> Iterator[None]:
        with self._lock:
            yield

    def _path(self, collection: str, key: str) -> Path:
        if collection not in self.COLLECTIONS:
            raise InvalidStorageKey(f"Unknown collection: {collection}")
        if not SAFE_COMPONENT.fullmatch(key):
            raise InvalidStorageKey(f"Unsafe storage key: {key}")
        return self.root / collection / f"{key}.json"

    def exists(self, collection: str, key: str) -> bool:
        return self._path(collection, key).is_file()

    def read(self, collection: str, key: str) -> dict[str, Any] | None:
        path = self._path(collection, key)
        with self._lock:
            if not path.is_file():
                return None
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                raise CorruptDocument(f"Unable to read {path}") from exc

    def write(self, collection: str, key: str, document: dict[str, Any]) -> None:
        path = self._path(collection, key)
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

    def delete(self, collection: str, key: str) -> None:
        path = self._path(collection, key)
        with self._lock:
            path.unlink(missing_ok=True)

    def list(self, collection: str) -> list[dict[str, Any]]:
        if collection not in self.COLLECTIONS:
            raise InvalidStorageKey(f"Unknown collection: {collection}")
        directory = self.root / collection
        with self._lock:
            documents: list[dict[str, Any]] = []
            for path in sorted(directory.glob("*.json")):
                try:
                    documents.append(json.loads(path.read_text(encoding="utf-8")))
                except (json.JSONDecodeError, OSError) as exc:
                    raise CorruptDocument(f"Unable to read {path}") from exc
            return documents

    def contains_data(self, *, exclude: tuple[str, ...] = ()) -> bool:
        with self._lock:
            for collection in self.COLLECTIONS:
                if collection not in exclude and any(
                    (self.root / collection).glob("*.json")
                ):
                    return True
            activity = self.root / "activity" / "activity.jsonl"
            return activity.is_file() and activity.stat().st_size > 0

    def list_by_field(self, collection: str, field: str, value: str) -> list[dict]:
        if field not in self.FILTER_FIELDS:
            raise ValueError("Unsupported document filter")
        return [item for item in self.list(collection) if item.get(field) == value]

    def page_assets(
        self, *, site_id: str | None, query: str, limit: int, offset: int
    ) -> dict:
        items = (
            self.list_by_field("assets", "site_id", site_id)
            if site_id
            else self.list("assets")
        )
        if query:
            needle = query.casefold()
            items = [
                item
                for item in items
                if any(
                    needle in str(item.get(field) or "").casefold()
                    for field in self.ASSET_SEARCH_FIELDS
                )
            ]
        items.sort(key=lambda item: item["last_seen"], reverse=True)
        return {
            "items": items[offset : offset + limit],
            "total": len(items),
            "limit": limit,
            "offset": offset,
        }

    def append_activity(self, event: dict[str, Any]) -> None:
        path = self.root / "activity" / "activity.jsonl"
        line = json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
        with self._lock, path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
