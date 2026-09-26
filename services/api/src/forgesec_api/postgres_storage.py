"""PostgreSQL-backed document store for the central control plane."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from psycopg import sql
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from forgesec_api.storage import SAFE_COMPONENT, InvalidStorageKey, JsonStore


class PostgresStore(JsonStore):
    def __init__(self, root: Path, database_url: str):
        super().__init__(root)
        self.pool = ConnectionPool(database_url, min_size=1, max_size=8, open=False)
        self._local = threading.local()

    def initialize(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.pool.open(wait=True)
        with self.pool.connection() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS forgesec_schema_version ("
                "version integer PRIMARY KEY, "
                "applied_at timestamptz NOT NULL DEFAULT now())"
            )
            versions = conn.execute(
                "SELECT version FROM forgesec_schema_version"
            ).fetchall()
            if not versions:
                conn.execute("INSERT INTO forgesec_schema_version (version) VALUES (1)")
            elif versions != [(1,)]:
                raise RuntimeError("Unsupported ForgeSec database schema version")
            conn.execute(
                """CREATE TABLE IF NOT EXISTS forgesec_documents (
                    collection text NOT NULL,
                    key text NOT NULL,
                    document jsonb NOT NULL,
                    PRIMARY KEY (collection, key)
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS forgesec_activity (
                    event_id uuid PRIMARY KEY,
                    event jsonb NOT NULL,
                    occurred_at timestamptz NOT NULL
                )"""
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS forgesec_activity_time ON "
                "forgesec_activity (occurred_at DESC)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS forgesec_assets_site_seen ON "
                "forgesec_documents ((document->>'site_id'), "
                "(document->>'last_seen') DESC, key) WHERE collection='assets'"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS forgesec_observations_asset_time ON "
                "forgesec_documents ((document->>'asset_id'), "
                "(document->>'observed_at') DESC) "
                "WHERE collection='asset-observations'"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS forgesec_observations_site ON "
                "forgesec_documents ((document->>'site_id')) "
                "WHERE collection='asset-observations'"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS forgesec_jobs_site_time ON "
                "forgesec_documents ((document->>'site_id'), "
                "(document->>'created_at') DESC) "
                "WHERE collection='scanner-worker-jobs'"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS forgesec_jobs_asset ON "
                "forgesec_documents ((document->>'source_asset_id')) "
                "WHERE collection='scanner-worker-jobs'"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS forgesec_scopes_site ON "
                "forgesec_documents ((document->>'site_id')) "
                "WHERE collection='approved-scopes'"
            )

    def close(self) -> None:
        self.pool.close()

    @contextmanager
    def locked(self) -> Iterator[None]:
        with self._lock:
            if getattr(self._local, "connection", None) is not None:
                yield
                return
            with self.pool.connection() as conn:
                conn.execute("SELECT pg_advisory_xact_lock(706672347)")
                self._local.connection = conn
                try:
                    yield
                finally:
                    self._local.connection = None

    @contextmanager
    def _connection(self) -> Iterator[Any]:
        connection = getattr(self._local, "connection", None)
        if connection is not None:
            yield connection
        else:
            with self.pool.connection() as connection:
                yield connection

    def _validate(self, collection: str, key: str | None = None) -> None:
        if collection not in self.COLLECTIONS:
            raise InvalidStorageKey(f"Unknown collection: {collection}")
        if key is not None and not SAFE_COMPONENT.fullmatch(key):
            raise InvalidStorageKey(f"Unsafe storage key: {key}")

    def exists(self, collection: str, key: str) -> bool:
        self._validate(collection, key)
        with self._connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM forgesec_documents WHERE collection = %s AND key = %s",
                (collection, key),
            ).fetchone()
        return row is not None

    def read(self, collection: str, key: str) -> dict[str, Any] | None:
        self._validate(collection, key)
        with self._connection() as conn:
            row = conn.execute(
                "SELECT document FROM forgesec_documents "
                "WHERE collection = %s AND key = %s",
                (collection, key),
            ).fetchone()
        return row[0] if row else None

    def write(self, collection: str, key: str, document: dict[str, Any]) -> None:
        self._validate(collection, key)
        with self._connection() as conn:
            conn.execute(
                "INSERT INTO forgesec_documents (collection, key, document) "
                "VALUES (%s, %s, %s) ON CONFLICT (collection, key) "
                "DO UPDATE SET document = EXCLUDED.document",
                (collection, key, Jsonb(document)),
            )

    def delete(self, collection: str, key: str) -> None:
        self._validate(collection, key)
        with self._connection() as conn:
            conn.execute(
                "DELETE FROM forgesec_documents WHERE collection = %s AND key = %s",
                (collection, key),
            )

    def list(self, collection: str) -> list[dict[str, Any]]:
        self._validate(collection)
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT document FROM forgesec_documents "
                "WHERE collection = %s ORDER BY key",
                (collection,),
            ).fetchall()
        return [row[0] for row in rows]

    def list_by_field(self, collection: str, field: str, value: str) -> list[dict]:
        self._validate(collection)
        if field not in self.FILTER_FIELDS:
            raise ValueError("Unsupported document filter")
        with self._connection() as conn:
            rows = conn.execute(
                sql.SQL(
                    "SELECT document FROM forgesec_documents "
                    "WHERE collection = {} AND document->>{} = %s ORDER BY key"
                ).format(sql.Literal(collection), sql.Literal(field)),
                (value,),
            ).fetchall()
        return [row[0] for row in rows]

    def page_assets(
        self, *, site_id: str | None, query: str, limit: int, offset: int
    ) -> dict:
        where = ["collection = 'assets'"]
        params: list[Any] = []
        if site_id:
            where.append("document->>'site_id' = %s")
            params.append(site_id)
        if query:
            escaped = (
                query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            )
            predicate = " OR ".join(
                f"document->>'{field}' ILIKE %s ESCAPE '\\'"
                for field in self.ASSET_SEARCH_FIELDS
            )
            where.append(f"({predicate})")
            params.extend([f"%{escaped}%"] * len(self.ASSET_SEARCH_FIELDS))
        condition = " AND ".join(where)
        with self._connection() as conn:
            total = int(
                conn.execute(
                    f"SELECT count(*) FROM forgesec_documents WHERE {condition}",
                    params,
                ).fetchone()[0]
            )
            rows = conn.execute(
                "SELECT document FROM forgesec_documents WHERE "
                f"{condition} ORDER BY document->>'last_seen' DESC, key ASC "
                "LIMIT %s OFFSET %s",
                [*params, limit, offset],
            ).fetchall()
        return {
            "items": [row[0] for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    def contains_data(self, *, exclude: tuple[str, ...] = ()) -> bool:
        with self._connection() as conn:
            documents = conn.execute(
                "SELECT EXISTS(SELECT 1 FROM forgesec_documents "
                "WHERE collection <> ALL(%s::text[]) LIMIT 1)",
                (list(exclude),),
            ).fetchone()[0]
            if documents:
                return True
            return bool(
                conn.execute(
                    "SELECT EXISTS(SELECT 1 FROM forgesec_activity)"
                ).fetchone()[0]
            )

    def append_activity(self, event: dict[str, Any]) -> None:
        with self._connection() as conn:
            conn.execute(
                "INSERT INTO forgesec_activity (event_id, event, occurred_at) "
                "VALUES (%s, %s, %s)",
                (event["event_id"], Jsonb(event), event["occurred_at"]),
            )

    def activity_count(self) -> int:
        with self._connection() as conn:
            row = conn.execute("SELECT count(*) FROM forgesec_activity").fetchone()
        return int(row[0])
