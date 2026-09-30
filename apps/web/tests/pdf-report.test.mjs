import { readFileSync, writeFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";
import { inflateSync } from "node:zlib";

import { PDFDocument } from "pdf-lib";

import { createScanPdf } from "../src/lib/pdf-report.ts";

const logo = new Uint8Array(readFileSync(new URL("../public/logos/forge-sec-logo.png", import.meta.url)));

function renderedPageText(pdf, page) {
  const streams = pdf.context.lookup(page.node.Contents());
  return Array.from({ length: streams.size() }, (_, index) => {
    const stream = pdf.context.lookup(streams.get(index));
    const source = inflateSync(stream.contents).toString("latin1");
    return [...source.matchAll(/<([0-9A-F]+)> Tj/g)]
      .map((match) => Buffer.from(match[1], "hex").toString("latin1"))
      .join(" ");
  }).join(" ");
}

function renderedText(pdf) {
  return pdf.getPages().map((page) => renderedPageText(pdf, page)).join(" ");
}

function sampleScan(targetCount) {
  const targets = Array.from({ length: targetCount }, (_, index) => {
    const number = index + 1;
    return {
      device_id: `device-${number}`,
      ip: `172.168.${Math.floor(number / 250) + 1}.${number % 250 + 1}`,
      hostname: number === 1 ? "long-service-hostname-with-extra-identification-for-layout-validation.example.internal" : `host-${number}.example.internal`,
      snmp_name: null,
      snmp_location: number % 7 === 0 ? "Main distribution frame - building 12" : null,
      snmp_interface_count: number % 7 === 0 ? 48 : null,
      vendor: number % 4 === 0 ? "Hewlett Packard Enterprise" : "Example Systems",
      device_type: number % 9 === 0 ? "router" : "server",
      status: "completed",
    };
  });
  const results = targets.map((target, index) => ({
    device_id: target.device_id,
    ip: target.ip,
    status: "completed",
    hostname: target.hostname,
    device_type: target.device_type,
    classification_confidence: 0.83,
    os_matches: [{ name: "Windows Server 2022", accuracy: 94 }],
    ports: [22, 80, 445, 5900].map((port) => ({
      port,
      protocol: "tcp",
      state: "open",
      service: port === 445 ? "microsoft-ds" : "http",
      product: "A long product name that should wrap safely in a table cell",
      version: "11.4.7",
      evidence_source: "nmap",
      recorded_at: "2026-09-28T07:24:38Z",
      extrainfo: "Service details with spaces and a longer response banner",
      cpe: "cpe:/a:example:service:11.4.7",
      cpes: ["cpe:/a:example:service:11.4.7"],
    })),
    exposure_flags: index % 3 === 0 ? [{
      code: "test-exposure",
      severity: "medium",
      title: "Management service exposed",
      evidence: "TCP 445 is reachable from the selected probe; verify that access is expected for this network segment.",
    }] : [],
    error: null,
  }));
  return {
    scan_id: "60dd20a8-38b8-4a31-a962-7683746118dd",
    agent_id: "c69e0017-080c-40c2-b0c3-cccd4da2faba",
    scan_origin: {
      agent_id: "c69e0017-080c-40c2-b0c3-cccd4da2faba",
      label: "Windows Network Probe",
      hostname: "PB-SOFT-016",
      local_ip: "172.168.1.248",
      subnet: "172.168.0.0/22",
      site_name: "Head Office",
      os_name: "Windows 11",
      agent_version: "0.1.0",
      discovery_interface: "Ethernet",
      last_heartbeat_at: "2026-09-28T07:11:18Z",
      source: "scan_snapshot",
    },
    profile: "inventory",
    status: "completed",
    total: targetCount,
    queued: 0,
    running: 0,
    completed: targetCount,
    failed: 0,
    cancelled: 0,
    created_at: "2026-09-28T07:11:18Z",
    started_at: "2026-09-28T07:11:21Z",
    completed_at: "2026-09-28T07:24:38Z",
    targets,
    results,
    summary: {
      scanned_hosts: targetCount,
      evidence_hosts: targetCount,
      classified_hosts: targetCount,
      network_devices: Math.floor(targetCount / 9),
      servers: targetCount - Math.floor(targetCount / 9),
      workstations: 0,
      open_ports: targetCount * 4,
      open_filtered_ports: 0,
      filtered_ports: 0,
      tcp_ports: targetCount * 4,
      udp_ports: 0,
      service_fingerprints: targetCount * 4,
      cpes: 1,
      exposure_findings: Math.ceil(targetCount / 3),
      high_exposure_findings: 0,
      management_services: targetCount,
      snmp_enabled: Math.floor(targetCount / 7),
      device_types: [{ label: "server", count: targetCount }],
      vendors: [{ label: "Example Systems", count: targetCount }],
      services: [{ label: "http/tcp", count: targetCount }],
      severity_counts: { high: 0, medium: Math.ceil(targetCount / 3), low: 0, info: 0 },
    },
    action_summary: {
      risk_score: 63,
      risk_level: "medium",
      priority_actions: [{
        priority: "medium",
        category: "network",
        title: "Restrict management service access",
        detail: "Confirm that remote administration is limited to approved management networks and review all exposed endpoints.",
        affected_count: Math.ceil(targetCount / 3),
      }],
    },
    change_summary: {
      baseline_scan_id: "87d46763-4443-4b1b-8954-0d607354690e",
      baseline_created_at: "2026-09-27T07:11:18Z",
      new_host_count: 2,
      missing_host_count: 1,
      opened_port_count: 30,
      closed_port_count: 1,
      new_finding_count: 12,
      resolved_finding_count: 0,
      opened_ports: targets.slice(0, 25).map((target) => ({ ip: target.ip, port: 445, protocol: "tcp", service: "microsoft-ds" })),
      closed_ports: [],
      new_findings: targets.slice(0, 12).map((target) => ({ ip: target.ip, title: "Management service exposed" })),
      resolved_findings: [],
    },
  };
}

test("large scan PDF has multiple complete pages and document metadata", async () => {
  const scan = sampleScan(128);
  const bytes = await createScanPdf(scan, logo);
  const pdf = await PDFDocument.load(bytes);
  assert.ok(pdf.getPageCount() > 10);
  assert.equal(pdf.getTitle(), `ForgeSec network scan - ${scan.scan_id}`);
  for (const page of pdf.getPages()) {
    assert.ok(page.getWidth() > 590);
    assert.ok(page.getHeight() > 840);
  }
  const observedMixPage = pdf.getPages().find((page) => renderedPageText(pdf, page).includes("Observed mix"));
  assert.ok(observedMixPage);
  assert.match(renderedPageText(pdf, observedMixPage), /Device type/);
  if (process.argv[2]) writeFileSync(process.argv[2], bytes);
});

test("queued scan with no host results still exports", async () => {
  const scan = sampleScan(1);
  scan.status = "queued";
  scan.queued = 1;
  scan.completed = 0;
  scan.completed_at = null;
  scan.results = [];
  const bytes = await createScanPdf(scan, logo);
  const pdf = await PDFDocument.load(bytes);
  assert.ok(pdf.getPageCount() >= 1);
});

test("PDF timestamps state UTC and normalize explicit source offsets", async () => {
  const scan = sampleScan(1);
  scan.created_at = "2026-09-28T12:41:18+05:30";
  const pdf = await PDFDocument.load(await createScanPdf(scan, logo));
  const text = renderedText(pdf);
  assert.match(text, /2026-09-28 07:11:18 UTC/);
  assert.match(text, /2026-09-28 07:24:38 UTC/);
  assert.doesNotMatch(text, /12:41:18/);
});

test("legacy scan without a probe snapshot still exports", async () => {
  const scan = sampleScan(1);
  scan.scan_origin = null;
  const bytes = await createScanPdf(scan, logo);
  const pdf = await PDFDocument.load(bytes);
  assert.ok(pdf.getPageCount() >= 1);
  const text = renderedText(pdf);
  assert.match(text, /PROBE ID/);
  assert.match(text, /c69e0017-080c-40c2-b0c3-cccd4da2faba/);
  assert.match(text, /did not record the probe's scan-time hostname or IP/);
});

test("PDF shows the saved probe identity and labels live legacy fallback", async () => {
  const scan = sampleScan(1);
  const saved = renderedText(await PDFDocument.load(await createScanPdf(scan, logo)));
  assert.match(saved, /c69e0017-080c-40c2-b0c3-cccd4da2faba/);
  assert.match(saved, /PB-SOFT-016/);
  assert.match(saved, /172\.168\.1\.248/);
  assert.match(saved, /Windows 11/);
  assert.match(saved, /0\.1\.0/);
  assert.match(saved, /Probe snapshot when queued/);

  scan.scan_origin.source = "current_heartbeat";
  const legacy = renderedText(await PDFDocument.load(await createScanPdf(scan, logo)));
  assert.match(legacy, /Latest probe record \(historical IP unverified\)/);
});

test("PDF identifies parsed host evidence and does not invent a hostname", async () => {
  const scan = sampleScan(1);
  scan.results[0].hostname = null;
  scan.results[0].raw_xml_sha256 = "a".repeat(64);
  const unnamed = renderedText(await PDFDocument.load(await createScanPdf(scan, logo)));
  assert.match(unnamed, /Hostname not reported/);
  assert.doesNotMatch(unnamed, /Hostname source:/);
  assert.match(unnamed, /Raw Nmap XML SHA-256:/);
  assert.match(unnamed, /a{64}/);

  scan.results[0].hostname = "server.example.internal";
  scan.results[0].hostname_source = "nmap";
  const named = renderedText(await PDFDocument.load(await createScanPdf(scan, logo)));
  assert.match(named, /Hostname source: Nmap/);
});

test("mixed port states and a timed-out host export without inflating open counts", async () => {
  const scan = sampleScan(2);
  scan.results[0].ports[1].state = "open|filtered";
  scan.results[0].ports[2].state = "filtered";
  scan.results[1].status = "timed_out";
  scan.results[1].ports = [];
  scan.results[1].error = "Host scan timed out";
  scan.status = "partial";
  scan.completed = 1;
  scan.failed = 1;
  scan.summary.open_ports = 2;
  scan.summary.open_filtered_ports = 1;
  scan.summary.filtered_ports = 1;
  scan.summary.tcp_ports = 2;
  scan.summary.timed_out_hosts = 1;
  const bytes = await createScanPdf(scan, logo);
  const pdf = await PDFDocument.load(bytes);
  assert.ok(pdf.getPageCount() >= 1);
  const text = renderedText(pdf);
  assert.match(text, /Open TCP 2\s+\|\s+Open UDP 0/);
  assert.match(text, /Open\|filtered 1\s+\|\s+Filtered 1/);
  assert.match(text, /Confirmed open: 2/);
  assert.match(text, /Confirmed open: Unknown/);
});

test("PDF retains wrapped origin and host identity while flagging incomplete coverage", async () => {
  const scan = sampleScan(2);
  scan.scan_origin.label = "Windows Network Probe for the Regional Operations and Infrastructure Team FINAL-ORIGIN";
  scan.results[0].hostname = "regional-application-node-with-long-evidence-name.example.internal FINAL-HOST";
  scan.status = "partial";
  scan.completed = 1;
  scan.failed = 1;
  scan.targets[1].status = "timed_out";
  scan.results[1].status = "timed_out";
  scan.results[1].ports = [];
  scan.summary.scanned_hosts = 1;
  scan.summary.evidence_hosts = 1;
  scan.summary.classified_hosts = 1;
  scan.summary.servers = 1;
  scan.change_summary.baseline_scan_id = null;
  const bytes = await createScanPdf(scan, logo);
  const text = renderedText(await PDFDocument.load(bytes));
  assert.match(text, /FINAL-ORIGIN/);
  assert.match(text, /FINAL-HOST/);
  assert.match(text, /Coverage is incomplete/);
  assert.match(text, /zero findings do not establish/);
  if (process.argv[3]) writeFileSync(process.argv[3], bytes);
});

test("oversized service evidence continues on another page without losing its end", async () => {
  const scan = sampleScan(1);
  scan.results[0].ports = [{
    ...scan.results[0].ports[0],
    product: `${"SERVICE ".repeat(300)}ENDMARKER`,
  }];
  const bytes = await createScanPdf(scan, logo);
  const pdf = await PDFDocument.load(bytes);
  assert.ok(pdf.getPageCount() >= 3);
  assert.match(renderedText(pdf), /ENDMARKER/);
  assert.match(renderedText(pdf), /Observed ports - 172\.168\.1\.2 \(continued\)/);
  for (const page of pdf.getPages()) {
    const text = renderedPageText(pdf, page);
    if (text.includes("Observed ports - 172.168.1.2 (continued)")) assert.match(text, /22\/tcp/);
  }
  if (process.argv[4]) writeFileSync(process.argv[4], bytes);
});
