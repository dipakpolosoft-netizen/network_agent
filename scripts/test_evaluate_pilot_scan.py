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
        "authorization_confirmed": True,
        "total_scopes": 1,
        "mode": "selected",
        "network": "192.168.1.0/24",
        "requested_scopes": ["192.168.1.0/24"],
        "completed_scopes": ["192.168.1.0/24"],
        "known_targets": ["192.168.1.20", "192.168.1.1"],
        "follow_up_checks": [
            {"ip": "192.168.1.20", "status": "already_discovered"},
            {"ip": "192.168.1.1", "status": "already_discovered"},
        ],
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
        "profile_plan": {
            "tcp_top_ports": 1000,
            "tcp_all_ports": False,
            "udp_ports": [],
            "open_only_output": True,
        },
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
        "summary": {
            "open_ports": 1,
            "open_filtered_ports": 0,
            "filtered_ports": 0,
            "tcp_ports": 1,
            "udp_ports": 0,
        },
    }
    return discovery, scan


class PilotScanEvaluationTests(unittest.TestCase):
    def test_matching_single_target_baseline_passes(self) -> None:
        discovery, scan = evidence()
        self.assertEqual(evaluate(discovery, scan, valid_plan()), [])

    def test_pilot_rejects_missing_authorization_and_extra_completed_scope(self) -> None:
        discovery, scan = evidence()
        discovery["authorization_confirmed"] = False
        discovery["completed_scopes"].append("192.168.2.0/24")
        discovery["total_scopes"] = 2
        findings = evaluate(discovery, scan, valid_plan())
        self.assertTrue(any("operator authorization" in item.message for item in findings))
        self.assertTrue(any("completed discovery scopes" in item.message for item in findings))
        self.assertTrue(any("more than one scope" in item.message for item in findings))

    def test_pilot_rejects_missing_or_broadened_scan_port_plan(self) -> None:
        discovery, scan = evidence()
        scan["profile_plan"]["tcp_all_ports"] = True
        findings = evaluate(discovery, scan, valid_plan())
        self.assertTrue(any("port plan" in item.message for item in findings))
        scan["profile_plan"] = None
        self.assertTrue(any("port plan" in item.message for item in evaluate(discovery, scan, valid_plan())))

    def test_public_pilot_requires_discovery_public_range_record(self) -> None:
        discovery, scan = evidence()
        plan = valid_plan()
        plan["approval"].update(
            approved_cidr="172.168.0.0/22",
            discovery_cidr="172.168.1.0/24",
            public_range_authorized=True,
        )
        plan["probe"]["ipv4"] = "172.168.1.10"
        plan["known_devices"][0]["ipv4"] = "172.168.1.20"
        plan["known_devices"][1]["ipv4"] = "172.168.1.1"
        findings = evaluate(discovery, scan, plan)
        self.assertTrue(any("public-range authorization" in item.message for item in findings))

    def test_pilot_rejects_cross_site_scan(self) -> None:
        discovery, scan = evidence()
        discovery["site_id"] = "site-a"
        scan["site_id"] = "site-b"
        findings = evaluate(discovery, scan, valid_plan())
        self.assertTrue(any("site IDs differ" in item.message for item in findings))

    def test_pilot_rejects_unexpected_udp_evidence(self) -> None:
        discovery, scan = evidence()
        scan["results"][0]["ports"].append({"protocol": "udp", "port": 161, "state": "open"})
        scan["summary"]["open_ports"] = 2
        scan["summary"]["udp_ports"] = 1
        findings = evaluate(discovery, scan, valid_plan())
        self.assertTrue(any("unexpectedly includes UDP" in item.message for item in findings))

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

    def test_selected_target_requires_a_known_expected_port(self) -> None:
        discovery, scan = evidence()
        scan["targets"][0] = {"device_id": "device-router", "ip": "192.168.1.1"}
        scan["results"][0]["device_id"] = "device-router"
        scan["results"][0]["ip"] = "192.168.1.1"
        findings = evaluate(discovery, scan, valid_plan())
        self.assertTrue(any("Selected pilot target needs" in item.message for item in findings))

    def test_inflated_open_total_or_ambiguous_expected_port_fails(self) -> None:
        discovery, scan = evidence()
        scan["results"][0]["ports"][0]["state"] = "open|filtered"
        findings = evaluate(discovery, scan, valid_plan())
        self.assertTrue(any("summary open_ports" in item.message for item in findings))
        self.assertTrue(any("Expected open TCP port 445" in item.message for item in findings))

    def test_missing_new_port_state_summary_fails_pilot(self) -> None:
        discovery, scan = evidence()
        scan["summary"].pop("open_filtered_ports")
        findings = evaluate(discovery, scan, valid_plan())
        self.assertTrue(any("summary open_filtered_ports" in item.message for item in findings))

    def test_structural_audit_checks_port_totals_without_a_plan(self) -> None:
        discovery, scan = evidence()
        scan["summary"]["open_ports"] = 3
        findings = evaluate(discovery, scan)
        self.assertTrue(any(item.level == "FAIL" and "summary open_ports" in item.message for item in findings))

    def test_accuracy_gate_requires_known_device_baseline(self) -> None:
        discovery, scan = evidence()
        plan = valid_plan()
        plan["known_devices"] = []
        findings = evaluate(discovery, scan, plan)
        self.assertTrue(any(item.level == "FAIL" and "known_devices" in item.message for item in findings))

    def test_targeted_recovery_is_reported_as_initial_discovery_miss(self) -> None:
        discovery, scan = evidence()
        discovery["known_targets"] = ["192.168.1.20", "192.168.1.1"]
        discovery["follow_up_checks"] = [
            {"ip": "192.168.1.20", "status": "responsive"},
            {"ip": "192.168.1.1", "status": "already_discovered"},
        ]
        findings = evaluate(discovery, scan, valid_plan())
        self.assertTrue(any(item.level == "REVIEW" and "targeted check recovered" in item.message for item in findings))

    def test_missing_known_host_check_cannot_pass(self) -> None:
        discovery, scan = evidence()
        discovery["known_targets"] = ["192.168.1.20", "192.168.1.1"]
        discovery["follow_up_checks"] = [
            {"ip": "192.168.1.20", "status": "already_discovered"},
        ]
        findings = evaluate(discovery, scan, valid_plan())
        self.assertTrue(any(item.level == "FAIL" and "no saved check" in item.message for item in findings))

    def test_omitting_known_host_checks_cannot_pass(self) -> None:
        discovery, scan = evidence()
        discovery["known_targets"] = []
        discovery["follow_up_checks"] = []
        findings = evaluate(discovery, scan, valid_plan())
        self.assertTrue(any(item.level == "FAIL" and "pilot baseline IPs" in item.message for item in findings))

    def test_unexpected_known_host_outcome_cannot_pass(self) -> None:
        discovery, scan = evidence()
        discovery["follow_up_checks"][1]["ip"] = "192.168.1.30"
        findings = evaluate(discovery, scan, valid_plan())
        self.assertTrue(any("Saved known-host results" in item.message for item in findings))
        discovery["follow_up_checks"][1]["ip"] = "192.168.1.1"
        discovery["follow_up_checks"][1]["status"] = "unexpected"
        findings = evaluate(discovery, scan, valid_plan())
        self.assertTrue(any("unrecognized check status" in item.message for item in findings))


if __name__ == "__main__":
    unittest.main()
