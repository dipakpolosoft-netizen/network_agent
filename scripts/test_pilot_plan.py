"""Offline tests for the Step 14 pilot gate."""

from __future__ import annotations

import copy
import unittest
from datetime import date

from check_pilot_plan import validate


def valid_plan() -> dict:
    return {
        "site": {"name": "Lab pilot", "owner": "Lab owner"},
        "approval": {
            "confirmed": True,
            "reference": "LAB-42",
            "approved_by": "Lab owner",
            "expires_on": "2099-12-31",
            "approved_cidr": "192.168.0.0/23",
            "discovery_cidr": "192.168.1.0/24",
            "exclusions": [],
            "profiles": ["inventory", "standard"],
            "public_range_authorized": False,
        },
        "probe": {
            "machine_name": "LAB-PROBE",
            "placement": "separate_windows_pc_or_vm",
            "ipv4": "192.168.1.10",
        },
        "server": {
            "dashboard_url": "http://127.0.0.1:3000",
            "agent_api_url": "https://api.lab.example",
        },
        "known_devices": [
            {"name": "Test PC", "device_type": "workstation", "ipv4": "192.168.1.20", "expected_tcp_ports": [445]},
            {"name": "Test router", "device_type": "router", "ipv4": "192.168.1.1", "expected_tcp_ports": []},
        ],
    }


class PilotPlanTests(unittest.TestCase):
    def check(self, plan: dict, *, mode: str = "authorization") -> list[str]:
        return validate(plan, today=date(2026, 9, 25), mode=mode)

    def test_valid_private_scope(self) -> None:
        self.assertEqual(self.check(valid_plan()), [])

    def test_written_approval_is_required(self) -> None:
        plan = valid_plan()
        plan["approval"]["confirmed"] = False
        self.assertIn("approval.confirmed", " ".join(self.check(plan)))

    def test_public_range_needs_explicit_approval(self) -> None:
        plan = valid_plan()
        plan["approval"].update(approved_cidr="172.168.0.0/22", discovery_cidr="172.168.1.0/24")
        plan["probe"]["ipv4"] = "172.168.1.10"
        plan["known_devices"][0]["ipv4"] = "172.168.1.20"
        plan["known_devices"][1]["ipv4"] = "172.168.1.1"
        self.assertIn("public_range_authorized", " ".join(self.check(plan)))
        plan["approval"]["public_range_authorized"] = True
        self.assertEqual(self.check(plan), [])

    def test_discovery_segment_must_be_bounded_and_contained(self) -> None:
        plan = valid_plan()
        plan["approval"]["discovery_cidr"] = "192.168.0.0/23"
        self.assertIn("at most 256", " ".join(self.check(plan)))
        plan["approval"]["discovery_cidr"] = "10.0.0.0/24"
        self.assertIn("inside approval.approved_cidr", " ".join(self.check(plan)))

    def test_known_devices_must_be_inside_and_not_excluded(self) -> None:
        plan = valid_plan()
        plan["known_devices"][0]["ipv4"] = "192.168.0.20"
        self.assertIn("first discovery segment", " ".join(self.check(plan, mode="accuracy")))
        plan["known_devices"][0]["ipv4"] = "192.168.1.20"
        plan["approval"]["exclusions"] = ["192.168.1.20/32"]
        self.assertIn("excluded", " ".join(self.check(plan, mode="accuracy")))

    def test_probe_cannot_be_excluded(self) -> None:
        plan = valid_plan()
        plan["approval"]["exclusions"] = ["192.168.1.10/32"]
        self.assertIn("probe.ipv4 is excluded", " ".join(self.check(plan)))

    def test_discovery_allows_narrow_host_exclusion(self) -> None:
        plan = valid_plan()
        plan["approval"]["exclusions"] = ["192.168.1.99/32"]
        self.assertEqual(self.check(plan, mode="accuracy"), [])

    def test_discovery_rejects_completely_excluded_segment(self) -> None:
        plan = valid_plan()
        plan["approval"]["exclusions"] = [
            "192.168.1.0/25",
            "192.168.1.128/25",
        ]
        self.assertIn(
            "Exclusions cover the entire first discovery segment",
            " ".join(self.check(plan)),
        )

    def test_remote_probe_cannot_use_localhost_or_plain_http(self) -> None:
        plan = valid_plan()
        plan["server"]["agent_api_url"] = "http://127.0.0.1:8000"
        errors = " ".join(self.check(plan, mode="accuracy"))
        self.assertIn("separate pilot machine", errors)
        self.assertIn("HTTPS", errors)
        plan["server"]["agent_api_url"] = "http://api.lab.example"
        self.assertIn("HTTPS", " ".join(self.check(plan)))

    def test_same_machine_loopback_is_allowed(self) -> None:
        plan = valid_plan()
        plan["probe"]["placement"] = "same_machine"
        plan["server"]["agent_api_url"] = "http://127.0.0.1:8000"
        self.assertEqual(self.check(plan), [])

    def test_expired_approval_and_invalid_port_are_rejected(self) -> None:
        plan = copy.deepcopy(valid_plan())
        plan["approval"]["expires_on"] = "2026-09-24"
        plan["known_devices"][0]["expected_tcp_ports"] = [0]
        errors = " ".join(self.check(plan, mode="accuracy"))
        self.assertIn("has passed", errors)
        self.assertIn("1-65535", errors)

    def test_pilot_needs_a_known_open_tcp_port(self) -> None:
        plan = valid_plan()
        plan["known_devices"][0]["expected_tcp_ports"] = []
        self.assertIn("expected open TCP port", " ".join(self.check(plan, mode="accuracy")))

    def test_authorization_does_not_require_known_devices(self) -> None:
        plan = valid_plan()
        plan.pop("known_devices")
        self.assertEqual(self.check(plan), [])
        self.assertIn("known_devices", " ".join(self.check(plan, mode="accuracy")))

    def test_literal_template_placeholders_are_rejected(self) -> None:
        plan = valid_plan()
        plan["site"]["owner"] = "ACTUAL_NETWORK_OWNER"
        plan["approval"]["reference"] = "ACTUAL_WRITTEN_APPROVAL_REFERENCE"
        plan["known_devices"][0]["name"] = "ACTUAL_DEVICE_NAME"
        plan["known_devices"][1]["device_type"] = "ANOTHER_ACTUAL_DEVICE_TYPE"
        errors = " ".join(self.check(plan, mode="accuracy"))
        self.assertIn("site.owner needs a real value", errors)
        self.assertIn("approval.reference needs a real value", errors)
        self.assertIn("known_devices[0] needs a real name", errors)
        self.assertIn("known_devices[1] needs a real name", errors)


if __name__ == "__main__":
    unittest.main()
