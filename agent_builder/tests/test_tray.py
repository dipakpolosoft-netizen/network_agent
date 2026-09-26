from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from forgesec_agent.config import dashboard_url_for_server
from forgesec_agent.tray import collect_snapshot, status_icon_pixels

NOW = datetime(2026, 7, 23, 12, 0, tzinfo=UTC)


def write_status(path, *, age_seconds=10, status="online"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "status": status,
                "last_heartbeat_at": (NOW - timedelta(seconds=age_seconds)).isoformat(),
                "heartbeat_interval_seconds": 30,
                "dashboard_url": "http://127.0.0.1:3000/network-agent",
                "nmap_version": None,
                "npcap_status": "missing",
                "activity": "Discovering network" if status == "busy" else None,
            }
        ),
        encoding="utf-8",
    )


def test_online_snapshot_is_green_even_when_scanner_setup_is_incomplete(tmp_path):
    status_path = tmp_path / "public" / "status.json"
    write_status(status_path)

    snapshot = collect_snapshot(status_path, service_running=True, now=NOW)

    assert snapshot.tone == "online"
    assert snapshot.label == "Online"
    assert snapshot.nmap == "Unavailable"
    assert snapshot.npcap == "Missing"


def test_stopped_service_is_offline(tmp_path):
    status_path = tmp_path / "status.json"
    write_status(status_path)

    snapshot = collect_snapshot(status_path, service_running=False, now=NOW)

    assert snapshot.tone == "offline"
    assert snapshot.service == "Stopped"


def test_stale_heartbeat_is_disconnected(tmp_path):
    status_path = tmp_path / "status.json"
    write_status(status_path, age_seconds=91)

    snapshot = collect_snapshot(status_path, service_running=True, now=NOW)

    assert snapshot.tone == "offline"
    assert snapshot.label == "Disconnected"


def test_busy_agent_uses_attention_icon(tmp_path):
    status_path = tmp_path / "status.json"
    write_status(status_path, status="busy")

    snapshot = collect_snapshot(status_path, service_running=True, now=NOW)

    assert snapshot.tone == "attention"
    assert snapshot.label == "Scanning"
    assert snapshot.activity == "Discovering network"


def test_invalid_heartbeat_interval_does_not_break_status(tmp_path):
    status_path = tmp_path / "status.json"
    write_status(status_path)
    document = json.loads(status_path.read_text(encoding="utf-8"))
    document["heartbeat_interval_seconds"] = "invalid"
    status_path.write_text(json.dumps(document), encoding="utf-8")

    snapshot = collect_snapshot(status_path, service_running=True, now=NOW)

    assert snapshot.tone == "online"


def test_local_dashboard_url_uses_web_port():
    assert dashboard_url_for_server("http://127.0.0.1:8000") == (
        "http://127.0.0.1:3000/network-agent"
    )
    assert dashboard_url_for_server("https://forgesec.example/api") == (
        "https://forgesec.example/network-agent"
    )


def test_status_icons_have_distinct_colors():
    online = status_icon_pixels("online")
    offline = status_icon_pixels("offline")

    assert len(online) == 32 * 32 * 4
    assert online != offline
