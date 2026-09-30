from __future__ import annotations

from pathlib import Path
from runpy import run_path

from forgesec_agent.scanning.nmap_runner import SCAN_PROFILES, scan_profile_plan


def test_probe_profile_plans_match_control_plane() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    api_profiles = run_path(
        str(repo_root / "services/api/src/forgesec_api/scans/profiles.py")
    )
    assert set(SCAN_PROFILES) == set(api_profiles["PROFILE_PLANS"])
    for profile in SCAN_PROFILES:
        assert scan_profile_plan(profile) == api_profiles["profile_plan"](profile)
