import { CountItem, Scan } from "@/lib/api";

function titleCase(value: string) {
  return value.replaceAll("_", " ").replaceAll("-", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function scanProfileLabel(value: string) {
  if (value === "inventory") return "Inventory";
  if (value === "network_services") return "Network services";
  if (value === "full_tcp") return "Full TCP";
  return titleCase(value);
}

function scanFinishedCount(scan: Scan) {
  return scan.completed + scan.failed + scan.cancelled;
}

function targetInventoryLabel(target: Scan["targets"][number]) {
  const parts = [
    target.snmp_location,
    target.snmp_interface_count != null ? `${target.snmp_interface_count} interfaces` : null,
  ].filter(Boolean);
  return parts.length ? parts.join(" - ") : "No SNMP inventory";
}

function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function downloadScanJson(scan: Scan) {
  saveBlob(
    new Blob([JSON.stringify(scan, null, 2)], { type: "application/json" }),
    `forgesec-scan-${scan.scan_id}.json`,
  );
}

function formatCountItems(items: CountItem[]) {
  return items.length
    ? items.map((item) => `${titleCase(item.label)} (${item.count})`).join(", ")
    : "None recorded";
}

function changeLine(scan: Scan) {
  const changes = scan.change_summary;
  if (!changes.baseline_scan_id) return "No comparable previous scan";
  return [
    `Compared with ${changes.baseline_scan_id}`,
    `${changes.new_host_count} new hosts`,
    `${changes.missing_host_count} missing hosts`,
    `${changes.opened_port_count} opened ports`,
    `${changes.closed_port_count} closed ports`,
    `${changes.new_finding_count} new findings`,
    `${changes.resolved_finding_count} resolved findings`,
  ].join("; ");
}

function reportLines(scan: Scan) {
  const lines = [
    "ForgeSec Network Scan Report",
    "",
    `Scan ID: ${scan.scan_id}`,
    `Profile: ${scanProfileLabel(scan.profile)}`,
    `Status: ${titleCase(scan.status)}`,
    `Created: ${new Date(scan.created_at).toLocaleString()}`,
    `Started: ${scan.started_at ? new Date(scan.started_at).toLocaleString() : "Pending"}`,
    `Completed: ${scan.completed_at ? new Date(scan.completed_at).toLocaleString() : "Pending"}`,
    "",
    "Summary",
    `Targets: ${scan.total}`,
    `Finished: ${scanFinishedCount(scan)} of ${scan.total}`,
    `Queued: ${scan.queued}`,
    `Running: ${scan.running}`,
    `Completed: ${scan.completed}`,
    `Failed: ${scan.failed}`,
    `Cancelled: ${scan.cancelled}`,
    `Open ports: ${scan.summary.open_ports}`,
    `Service fingerprints: ${scan.summary.service_fingerprints}`,
    `Findings: ${scan.summary.exposure_findings} (${scan.summary.high_exposure_findings} high)`,
    "",
    "Network intelligence",
    `Scanned host results: ${scan.summary.scanned_hosts}`,
    `Evidence hosts: ${scan.summary.evidence_hosts}`,
    `Classified hosts: ${scan.summary.classified_hosts}`,
    `Network devices: ${scan.summary.network_devices}`,
    `Servers: ${scan.summary.servers}`,
    `Workstations: ${scan.summary.workstations}`,
    `TCP ports: ${scan.summary.tcp_ports}`,
    `UDP ports: ${scan.summary.udp_ports}`,
    `Management services: ${scan.summary.management_services}`,
    `SNMP-enabled targets: ${scan.summary.snmp_enabled}`,
    `CPEs: ${scan.summary.cpes}`,
    `Severity mix: high ${scan.summary.severity_counts.high}, medium ${scan.summary.severity_counts.medium}, low ${scan.summary.severity_counts.low}, info ${scan.summary.severity_counts.info}`,
    `Device roles: ${formatCountItems(scan.summary.device_types)}`,
    `Vendors: ${formatCountItems(scan.summary.vendors)}`,
    `Services: ${formatCountItems(scan.summary.services.slice(0, 12))}`,
    "",
    "Action plan",
    `Risk score: ${scan.action_summary.risk_score}/100`,
    `Risk level: ${titleCase(scan.action_summary.risk_level)}`,
    ...scan.action_summary.priority_actions.map((action) =>
      `${titleCase(action.priority)} - ${action.title}: ${action.detail} (${action.affected_count} affected)`,
    ),
    "",
    "Change summary",
    changeLine(scan),
    ...scan.change_summary.opened_ports.slice(0, 20).map((port) =>
      `Opened: ${port.ip} ${port.port}/${port.protocol} ${port.service ?? "unknown"}`,
    ),
    ...scan.change_summary.closed_ports.slice(0, 20).map((port) =>
      `Closed: ${port.ip} ${port.port}/${port.protocol} ${port.service ?? "unknown"}`,
    ),
    ...scan.change_summary.new_findings.slice(0, 20).map((finding) =>
      `New finding: ${finding.ip} ${titleCase(finding.severity)} ${finding.title}`,
    ),
    ...scan.change_summary.resolved_findings.slice(0, 20).map((finding) =>
      `Resolved finding: ${finding.ip} ${titleCase(finding.severity)} ${finding.title}`,
    ),
    "",
    "Targets",
    ...scan.targets.map((target) =>
      `${target.ip}  ${target.hostname ?? target.snmp_name ?? "No hostname"}  ${target.device_type ? titleCase(target.device_type) : "Unknown type"}  ${targetInventoryLabel(target)}  ${titleCase(target.status)}`,
    ),
  ];

  const results = scan.results.flatMap((result) => [
    "",
    `Host ${result.ip} - ${titleCase(result.status)}`,
    `Hostname: ${result.hostname ?? "Not reported"}`,
    `Type: ${result.device_type ? `${titleCase(result.device_type)} (${Math.round((result.classification_confidence ?? 0) * 100)}%)` : "Not classified"}`,
    `Ports: ${result.ports.length}`,
    ...result.ports.map((port) =>
      `  ${port.port}/${port.protocol} ${titleCase(port.state)} ${port.service ?? "unknown"} ${[port.product, port.version, port.extrainfo].filter(Boolean).join(" ") || ""}${port.confidence != null ? ` conf:${port.confidence}` : ""}`.trimEnd(),
    ),
    ...(result.exposure_flags.length
      ? [
        "Findings:",
        ...result.exposure_flags.map((flag) =>
          `  ${titleCase(flag.severity)} - ${flag.title}: ${flag.evidence}`,
        ),
      ]
      : ["Findings: none"]),
    ...(result.error ? [`Error: ${result.error}`] : []),
  ]);

  return [...lines, "", "Host Evidence", ...results];
}

function wrapLines(lines: string[], maxChars: number) {
  const wrapped: string[] = [];
  for (const line of lines) {
    if (line.length <= maxChars) {
      wrapped.push(line);
      continue;
    }
    let rest = line;
    while (rest.length > maxChars) {
      const splitAt = Math.max(24, rest.lastIndexOf(" ", maxChars));
      wrapped.push(rest.slice(0, splitAt));
      rest = rest.slice(splitAt).trimStart();
    }
    wrapped.push(rest);
  }
  return wrapped;
}

function pdfEscape(value: string) {
  return value
    .replace(/[^\x09\x0A\x0D\x20-\x7E]/g, "?")
    .replaceAll("\\", "\\\\")
    .replaceAll("(", "\\(")
    .replaceAll(")", "\\)");
}

function createTextPdf(lines: string[]) {
  const pageLines = 47;
  const wrapped = wrapLines(lines, 92);
  const pages: string[][] = [];
  for (let index = 0; index < wrapped.length; index += pageLines) {
    pages.push(wrapped.slice(index, index + pageLines));
  }

  const objects: string[] = [];
  const add = (body: string) => {
    objects.push(body);
    return objects.length;
  };
  const catalogId = add("<< /Type /Catalog /Pages 2 0 R >>");
  const pagesId = add("");
  const fontId = add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
  const pageIds: number[] = [];

  for (const [pageIndex, page] of pages.entries()) {
    const content = [
      "BT",
      "/F1 10 Tf",
      "50 742 Td",
      "14 TL",
      ...page.map((line, lineIndex) =>
        `${lineIndex === 0 ? "" : "T* "}${lineIndex === 0 && pageIndex === 0 ? "/F1 14 Tf " : ""}(${pdfEscape(line)}) Tj`,
      ),
      "ET",
    ].join("\n");
    const contentId = add(`<< /Length ${content.length} >>\nstream\n${content}\nendstream`);
    const pageId = add(`<< /Type /Page /Parent ${pagesId} 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 ${fontId} 0 R >> >> /Contents ${contentId} 0 R >>`);
    pageIds.push(pageId);
  }

  objects[pagesId - 1] = `<< /Type /Pages /Count ${pageIds.length} /Kids [${pageIds.map((id) => `${id} 0 R`).join(" ")}] >>`;

  const chunks = ["%PDF-1.4\n"];
  const offsets = [0];
  for (const [index, body] of objects.entries()) {
    offsets.push(chunks.join("").length);
    chunks.push(`${index + 1} 0 obj\n${body}\nendobj\n`);
  }
  const xrefOffset = chunks.join("").length;
  chunks.push(`xref\n0 ${objects.length + 1}\n`);
  chunks.push("0000000000 65535 f \n");
  for (const offset of offsets.slice(1)) {
    chunks.push(`${offset.toString().padStart(10, "0")} 00000 n \n`);
  }
  chunks.push(`trailer\n<< /Size ${objects.length + 1} /Root ${catalogId} 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`);
  return chunks.join("");
}

export function downloadScanPdf(scan: Scan) {
  saveBlob(
    new Blob([createTextPdf(reportLines(scan))], { type: "application/pdf" }),
    `forgesec-scan-${scan.scan_id}.pdf`,
  );
}
