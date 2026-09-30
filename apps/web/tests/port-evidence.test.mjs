import assert from "node:assert/strict";
import { test } from "node:test";

import { countPortStates, countScanPortStates, portCpes, portEvidenceSourceLabel, portEvidenceTimeLabel, portServiceLabel } from "../src/lib/port-evidence.ts";

test("confirmed open excludes ambiguous and filtered ports", () => {
  const ports = [
    { port: 22, protocol: "tcp", state: "open" },
    { port: 53, protocol: "udp", state: "open" },
    { port: 161, protocol: "udp", state: "open|filtered" },
    { port: 443, protocol: "tcp", state: "filtered" },
  ];
  assert.deepEqual(countPortStates(ports), {
    open: 2, openFiltered: 1, filtered: 1, tcpOpen: 1, udpOpen: 1,
  });
  assert.deepEqual(countScanPortStates({ results: [{ ports }, { ports: [], status: "timed_out" }] }), {
    open: 2, openFiltered: 1, filtered: 1, tcpOpen: 1, udpOpen: 1,
  });
});

test("port labels keep unknowns and lookup-based service names explicit", () => {
  const port = { service: "ssh", method: "table", cpe: "cpe:/a:example:ssh:1", cpes: ["cpe:/a:example:ssh:1"] };
  assert.equal(portServiceLabel(port), "ssh (port lookup)");
  assert.deepEqual(portCpes(port), ["cpe:/a:example:ssh:1"]);
  assert.equal(portServiceLabel({ service: " " }), "Not identified");
  assert.equal(portEvidenceSourceLabel({}), "Not recorded");
  assert.equal(portEvidenceTimeLabel({}), "Not recorded");
  assert.equal(portEvidenceTimeLabel({ recorded_at: "bad" }), "Not recorded");
  assert.equal(portEvidenceSourceLabel({ evidence_source: "nmap" }), "Nmap");
  assert.equal(portEvidenceTimeLabel({ recorded_at: "2026-09-28T07:24:38.123Z" }), "2026-09-28 07:24:38 UTC");
});
