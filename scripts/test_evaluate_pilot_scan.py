"""Offline checks for the discovery/scan pilot evaluator."""

from __future__ import annotations

import copy
import unittest

from evaluate_pilot_scan import evaluate
from test_pilot_plan import valid_plan


def evidence() -> tuple[dict, dict]:
    discovery = {
        "discovery_id": "discovery-1",
        "agent_id": "agent-1",
        "status": "completed",
        "mode": "selected",
        "network": "192.168.1.0/24",
        "requested_scopes": ["192.168.1.0/24"],
        "completed_scopes": ["192.168.1.0/24"],
        "devices": [
            {"device_id": "device-pc", "ip": "192.168.1.20", "is_agent": False, "hostname": "test-pc", "device_type": "workstation"},
            {"device_id": "device-router", "ip": "192.168.1.1", "is_agent": False, "hostname": "router", "device_type": "router"},
        ],
    }
    scan = {
        "discovery_id": "discovery-1",
        "agent_id": "agent-1",
        "status": "completed",
        "profile": "standard",
        "total": 1,
        "queued": 0,
        "running": 0,
        "completed": 1,
        "failed": 0,
        "cancelled": 0,
        "targets": [{"device_id": "device-pc", "ip": "192.168.1.20"}],
        "results": [
            {
                "device_id": "device-pc",
                "ip": "192.168.1.20",
                "status": "completed",
                "ports": [{"protocol": "tcp", "port": 445, "state": "open"}],
            }
        ],
    }
    return discovery, scan


class PilotScanEvaluationTests(unittest.TestCase):
    def test_matching_single_target_baseline_passes(self) -> None:
        discovery, scan = evidence()
        self.assertEqual(evaluate(discovery, scan, valid_plan()), [])

    def test_missing_expected_device_fails(self) -> None:
        discovery, scan = evidence()
        discovery["devices"].pop()
        findings = evaluate(discovery, scan, valid_plan())
        self.assertTrue(any(item.level == "FAIL" and "not discovered" in item.message for item in findings))

    def test_missing_expected_open_port_fails(self) -> None:
        discovery, scan = evidence()
        scan["results"][0]["ports"] = []
        findings = evaluate(discovery, scan, valid_plan())
        self.assertTrue(any(item.level == "FAIL" and "445" in item.message for item in findings))

    def test_completed_scan_requires_target_result(self) -> None:
        discovery, scan = evidence()
        scan["results"] = []
        findings = evaluate(discovery, scan, valid_plan())
        self.assertTrue(any("one result for every" in item.message for item in findings))

    def test_inconsistent_progress_counters_fail(self) -> None:
        discovery, scan = evidence()
        scan["queued"] = 1
        findings = evaluate(discovery, scan, valid_plan())
        self.assertTrue(any("counters" in item.message for item in findings))

    def test_partial_scan_requires_new_pilot_run(self) -> None:
        discovery, scan = evidence()
        scan["status"] = "partial"
        self.assertTrue(any(item.level == "FAIL" for item in evaluate(discovery, scan, valid_plan())))
        self.assertTrue(any(item.level == "REVIEW" for item in evaluate(discovery, scan)))

    def test_unrelated_scan_and_out_of_scope_device_fail(self) -> None:
        discovery, scan = evidence()
        scan["discovery_id"] = "different"
        discovery["devices"][0]["ip"] = "192.168.2.20"
        findings = evaluate(discovery, scan, valid_plan())
        self.assertTrue(any("does not belong" in item.message for item in findings))
        self.assertTrue(any("outside" in item.message for item in findings))

    def test_unplanned_target_fails(self) -> None:
        discovery, scan = evidence()
        extra = {"device_id": "device-extra", "ip": "192.168.1.30", "is_agent": False}
        discovery["devices"].append(extra)
        scan["targets"] = [{"device_id": extra["device_id"], "ip": extra["ip"]}]
        scan["results"][0]["device_id"] = extra["device_id"]
        scan["results"][0]["ip"] = extra["ip"]
        findings = evaluate(discovery, scan, valid_plan())
        self.assertTrue(any("unplanned" in item.message for item in findings))

    def test_classification_mismatch_needs_review(self) -> None:
        discovery, scan = evidence()
        discovery = copy.deepcopy(discovery)
        discovery["devices"][0]["device_type"] = "server"
        findings = evaluate(discovery, scan, valid_plan())
        self.assertTrue(any(item.level == "REVIEW" and "type" in item.message for item in findings))


if __name__ == "__main__":
    unittest.main()
