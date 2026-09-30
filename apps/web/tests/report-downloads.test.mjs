import { test } from "node:test";
import assert from "node:assert/strict";

import { api } from "../src/lib/api.ts";
import { downloadScanJson, serializeScanJson } from "../src/lib/report-downloads.ts";
import { countScanPortStates } from "../src/lib/port-evidence.ts";

test("JSON export preserves the saved scan response", () => {
  const scan = {
    scan_id: "saved-scan",
    scan_origin: {
      agent_id: "probe-1",
      hostname: "WIN-PROBE-01",
      local_ip: "192.0.2.5",
      subnet: "192.0.2.0/24",
      os_name: "Windows 11",
      agent_version: "0.1.0",
      source: "scan_snapshot",
    },
    status: "partial",
    summary: { open_ports: 1, open_filtered_ports: 1, filtered_ports: 1, tcp_ports: 1, udp_ports: 0 },
    results: [{
      ip: "192.0.2.10",
      hostname: "server.example.internal",
      hostname_source: "nmap",
      raw_xml_sha256: "a".repeat(64),
      ports: [
      { port: 22, protocol: "tcp", state: "open" },
      { port: 53, protocol: "udp", state: "open|filtered" },
      { port: 443, protocol: "tcp", state: "filtered" },
      ],
    }],
  };
  const exported = JSON.parse(serializeScanJson(scan));
  assert.deepEqual(exported, scan);
  assert.equal(exported.scan_origin.local_ip, "192.0.2.5");
  assert.equal(exported.scan_origin.source, "scan_snapshot");
  assert.equal(exported.results[0].hostname_source, "nmap");
  assert.equal(exported.results[0].raw_xml_sha256, "a".repeat(64));
  const counts = countScanPortStates(exported);
  assert.deepEqual(
    [exported.summary.open_ports, exported.summary.open_filtered_ports, exported.summary.filtered_ports, exported.summary.tcp_ports, exported.summary.udp_ports],
    [counts.open, counts.openFiltered, counts.filtered, counts.tcpOpen, counts.udpOpen],
  );
});

test("JSON download fetches current server evidence instead of a stale history row", async () => {
  const originalReport = api.scanReport;
  const originalDocument = globalThis.document;
  const originalWindow = globalThis.window;
  const originalCreate = URL.createObjectURL;
  const originalRevoke = URL.revokeObjectURL;
  let savedBlob;
  let savedName;
  let requestedId;
  try {
    api.scanReport = async (scanId) => {
      requestedId = scanId;
      return { scan_id: scanId, status: "completed", results: [{ ip: "192.0.2.20" }] };
    };
    URL.createObjectURL = (blob) => { savedBlob = blob; return "blob:test"; };
    URL.revokeObjectURL = () => {};
    globalThis.window = { setTimeout: () => 0 };
    globalThis.document = {
      body: { appendChild() {} },
      createElement: () => ({
        set href(_) {},
        set download(value) { savedName = value; },
        click() {},
        remove() {},
      }),
    };
    await downloadScanJson("saved-scan");
    assert.equal(requestedId, "saved-scan");
    assert.equal(savedName, "forgesec-scan-saved-scan.json");
    assert.deepEqual(JSON.parse(await savedBlob.text()), {
      scan_id: "saved-scan", status: "completed", results: [{ ip: "192.0.2.20" }],
    });

    savedBlob = undefined;
    api.scanReport = async () => { throw new Error("Report unavailable"); };
    await assert.rejects(downloadScanJson("saved-scan"), /Report unavailable/);
    assert.equal(savedBlob, undefined);
  } finally {
    api.scanReport = originalReport;
    globalThis.document = originalDocument;
    globalThis.window = originalWindow;
    URL.createObjectURL = originalCreate;
    URL.revokeObjectURL = originalRevoke;
  }
});
