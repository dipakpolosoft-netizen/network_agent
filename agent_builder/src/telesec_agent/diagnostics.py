"""Local installation and dependency diagnostics."""

from __future__ import annotations

import json
import os
from pathlib import Path

from telesec_agent.config import AgentPaths, default_data_directory
from telesec_agent.heartbeat import nmap_version, npcap_status


def doctor(data_directory: Path | None = None) -> dict:
    paths = AgentPaths((data_directory or default_data_directory()).resolve())
    writable = False
    try:
        paths.root.mkdir(parents=True, exist_ok=True)
        probe = paths.root / f".write-test-{os.getpid()}"
        probe.write_text("ok", encoding="ascii")
        probe.unlink()
        writable = True
    except OSError:
        writable = False
    nmap = nmap_version()
    npcap = npcap_status()
    return {
        "status": "ready"
        if writable and nmap and npcap == "available"
        else "attention",
        "data_directory": str(paths.root),
        "data_directory_writable": writable,
        "bootstrap_present": paths.bootstrap.is_file(),
        "identity_present": paths.identity.is_file(),
        "nmap_version": nmap,
        "npcap_status": npcap,
    }


def print_json(document: dict) -> None:
    print(json.dumps(document, indent=2, sort_keys=True))
