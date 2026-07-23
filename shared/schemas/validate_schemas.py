"""Perform dependency-free structural checks on Telesec schema documents."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


SCHEMA_DIRECTORY = Path(__file__).resolve().parent


def iter_references(value: Any):
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "$ref" and isinstance(item, str):
                yield item
            else:
                yield from iter_references(item)
    elif isinstance(value, list):
        for item in value:
            yield from iter_references(item)


def main() -> int:
    paths = sorted(SCHEMA_DIRECTORY.glob("*.schema.json"))
    if not paths:
        raise SystemExit("No schema documents found")

    documents: dict[str, dict[str, Any]] = {}
    for path in paths:
        with path.open("r", encoding="utf-8") as handle:
            document = json.load(handle)
        schema_id = document.get("$id")
        if not isinstance(schema_id, str) or not schema_id:
            raise SystemExit(f"{path.name}: missing $id")
        if schema_id in documents:
            raise SystemExit(f"{path.name}: duplicate $id {schema_id}")
        if document.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise SystemExit(f"{path.name}: expected JSON Schema 2020-12")
        if not document.get("title"):
            raise SystemExit(f"{path.name}: missing title")
        documents[schema_id] = document

    for path in paths:
        document = json.loads(path.read_text(encoding="utf-8"))
        for reference in iter_references(document):
            if reference.startswith("#"):
                continue
            referenced_id = reference.split("#", 1)[0]
            if referenced_id not in documents:
                raise SystemExit(f"{path.name}: unresolved schema reference {reference}")

    print(f"Validated {len(paths)} Telesec schema documents")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

