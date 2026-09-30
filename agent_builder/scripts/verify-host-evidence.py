"""Offline check of one exported scan result against the probe's raw XML."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from forgesec_agent.scanning.evidence import verify_host_evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan", required=True, type=Path, help="Exported scan JSON")
    parser.add_argument("--xml", required=True, type=Path, help="Probe raw host XML")
    parser.add_argument("--device-id", required=True, help="Selected device ID")
    args = parser.parse_args()
    try:
        scan = json.loads(args.scan.read_text(encoding="utf-8-sig"))
        raw_xml = args.xml.read_bytes()
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        parser.exit(2, f"Cannot read evidence: {exc}\n")
    if not isinstance(scan, dict):
        parser.exit(2, "Scan JSON must contain an object\n")
    issues = verify_host_evidence(raw_xml, scan, args.device_id)
    for issue in issues:
        print(f"FAIL: {issue}")
    if issues:
        return 1
    print("PASS: Raw Nmap XML matches the saved host result")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
