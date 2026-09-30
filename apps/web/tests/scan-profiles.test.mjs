import assert from "node:assert/strict";
import { test } from "node:test";

import {
  NETWORK_SERVICE_TCP_PORTS,
  NETWORK_SERVICE_UDP_PORTS,
  SCAN_PROFILE_OPTIONS,
  approvedProfilesForTargets,
  profilePlanLines,
} from "../src/lib/scan-profiles.ts";

test("profile choices state the four distinct coverage modes", () => {
  assert.deepEqual(SCAN_PROFILE_OPTIONS.map((item) => item.value), [
    "inventory", "network_services", "standard", "full_tcp",
  ]);
  assert.equal(NETWORK_SERVICE_TCP_PORTS.length, 8);
  assert.equal(NETWORK_SERVICE_UDP_PORTS.length, 10);
  assert.match(SCAN_PROFILE_OPTIONS[3].hint, /No UDP/);
});

test("saved fixed-port plan renders exact TCP and UDP coverage", () => {
  const lines = profilePlanLines({
    tcp_top_ports: null,
    tcp_all_ports: false,
    tcp_ports: NETWORK_SERVICE_TCP_PORTS,
    udp_ports: NETWORK_SERVICE_UDP_PORTS,
    version_detection: "light",
    os_detection: "not_requested",
    host_timeout_seconds: 720,
    assume_host_up: true,
    open_only_output: true,
  });
  assert.match(lines[0], /TCP 22, 53, 80, 443, 445, 3389, 8080, 8443/);
  assert.match(lines[0], /UDP 53, 67, 69, 123, 137, 161, 500, 4500, 5353, 1900/);
  assert.match(lines[1], /OS fingerprint not requested/);
  assert.match(lines[2], /unlisted ports are not proven closed/);
  assert.match(lines[2], /UDP open\|filtered is inconclusive/);
});

test("Full TCP is not described as all UDP", () => {
  const lines = profilePlanLines({
    tcp_top_ports: null,
    tcp_all_ports: true,
    tcp_ports: [],
    udp_ports: [],
    version_detection: "full",
    os_detection: "when_privileged",
    host_timeout_seconds: 2700,
    assume_host_up: true,
    open_only_output: true,
  });
  assert.match(lines[0], /TCP 1-65535; No UDP ports/);
  assert.match(lines[1], /45 min per host/);
  assert.match(lines[2], /not guaranteed/);
});

test("historical scans do not invent a missing command snapshot", () => {
  assert.match(profilePlanLines(null)[0], /not saved/);
});

test("selected targets only offer profiles approved on every network", () => {
  const scopes = [
    { cidr: "192.168.1.0/24", scan_profiles: ["inventory", "standard", "full_tcp"] },
    { cidr: "192.168.2.0/24", scan_profiles: ["inventory", "network_services"] },
  ];
  assert.deepEqual(approvedProfilesForTargets(scopes, ["192.168.1.0/24"]), ["inventory", "standard", "full_tcp"]);
  assert.deepEqual(approvedProfilesForTargets(scopes, ["192.168.1.0/24", "192.168.2.0/24"]), ["inventory"]);
  assert.deepEqual(approvedProfilesForTargets(scopes, ["192.168.3.0/24"]), []);
  assert.deepEqual(approvedProfilesForTargets(scopes, []), []);
});
