import { test } from "node:test";
import assert from "node:assert/strict";

import { discoveryDeviceName, roleEstimate } from "../src/lib/device-identity.ts";

test("a MAC vendor is not presented as a device hostname", () => {
  assert.equal(discoveryDeviceName({ is_agent: false, hostname: null, snmp_name: null, ip: "192.0.2.10", vendor: "TP-Link Systems" }), "Host 192.0.2.10");
  assert.equal(discoveryDeviceName({ is_agent: false, hostname: "  pc-1  ", snmp_name: null, ip: "192.0.2.10" }), "pc-1");
  assert.equal(discoveryDeviceName({ is_agent: false, hostname: null, snmp_name: "  core-sw  ", ip: "192.0.2.10" }), "core-sw");
  assert.equal(discoveryDeviceName({ is_agent: true, hostname: null, snmp_name: null, ip: "192.0.2.25" }), "ForgeSec collector");
});

test("uncertain or missing role evidence is not presented as verified", () => {
  assert.equal(roleEstimate(null, null), "Role unknown");
  assert.equal(roleEstimate("unknown", 0), "Role unknown");
  assert.equal(roleEstimate("switch", 0.65), "Switch (limited evidence)");
  assert.equal(roleEstimate("router", 0.8), "Router (moderate evidence)");
  assert.equal(roleEstimate("firewall", 0.9), "Firewall (strong evidence)");
});
