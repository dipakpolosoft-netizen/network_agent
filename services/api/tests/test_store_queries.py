from __future__ import annotations

from pathlib import Path

import pytest

from forgesec_api.storage import JsonStore


def test_asset_paging_and_site_filter_are_deterministic(tmp_path: Path) -> None:
    store = JsonStore(tmp_path / "data")
    store.initialize()
    for key, site, name, seen in (
        ("a", "site-a", "Core 100%", "2026-01-01T00:00:00Z"),
        ("b", "site-a", "Edge", "2026-02-01T00:00:00Z"),
        ("c", "site-b", "Core 100%", "2026-03-01T00:00:00Z"),
    ):
        store.write(
            "assets",
            key,
            {
                "asset_id": key,
                "site_id": site,
                "display_name": name,
                "last_seen": seen,
            },
        )
    page = store.page_assets(site_id="site-a", query="", limit=1, offset=0)
    assert page["total"] == 2
    assert page["items"][0]["asset_id"] == "b"
    assert (
        store.page_assets(site_id="site-a", query="100%", limit=10, offset=0)["items"][
            0
        ]["asset_id"]
        == "a"
    )
    assert store.list_by_field("assets", "site_id", "site-b")[0]["asset_id"] == "c"
    with pytest.raises(ValueError, match="Unsupported"):
        store.list_by_field("assets", "password_hash", "x")
