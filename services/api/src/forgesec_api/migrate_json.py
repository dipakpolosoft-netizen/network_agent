"""One-time, non-destructive import of local JSON state into PostgreSQL."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from forgesec_api.postgres_storage import PostgresStore
from forgesec_api.settings import Settings
from forgesec_api.storage import JsonStore


def import_json(source_root: Path, destination: PostgresStore) -> dict[str, int]:
    source_root = source_root.resolve()
    if not source_root.is_dir():
        raise ValueError(f"Source directory does not exist: {source_root}")
    counts: dict[str, int] = {}
    with destination.locked():
        if any(destination.list(collection) for collection in JsonStore.COLLECTIONS):
            raise ValueError(
                "PostgreSQL already contains data; import requires an empty store"
            )
        if destination.activity_count():
            raise ValueError(
                "PostgreSQL already contains activity; import requires an empty store"
            )
        for collection in JsonStore.COLLECTIONS:
            directory = source_root / collection
            count = 0
            for path in sorted(directory.glob("*.json")):
                document = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(document, dict):
                    raise ValueError(f"Expected a JSON object: {path}")
                destination.write(collection, path.stem, document)
                count += 1
            counts[collection] = count
        activity_file = source_root / "activity" / "activity.jsonl"
        counts["activity-events"] = 0
        if activity_file.exists():
            for line in activity_file.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                destination.append_activity(json.loads(line))
                counts["activity-events"] += 1
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    settings = Settings.from_env()
    if not settings.database_url:
        raise SystemExit("Set FORGESEC_DATABASE_URL before importing")
    destination = PostgresStore(settings.runtime_data_dir, settings.database_url)
    destination.initialize()
    try:
        counts = import_json(args.source, destination)
        print("Imported without changing the JSON source:")
        for collection, count in counts.items():
            print(f"  {collection}: {count}")
    finally:
        destination.close()


if __name__ == "__main__":
    main()
