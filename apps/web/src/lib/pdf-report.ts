import { PDFDocument, PDFImage, PDFPage, PDFFont, StandardFonts, rgb } from "pdf-lib";

import type { Scan } from "./api";
import { hostnameSourceLabel } from "./host-evidence.ts";
import { countPortStates, countScanPortStates, portCpes, portEvidenceSourceLabel, portEvidenceTimeLabel, portServiceLabel } from "./port-evidence.ts";
import { scanCoverageNotice } from "./report-status.ts";
import { profilePlanLines } from "./scan-profiles.ts";

const PAGE_WIDTH = 595.28;
const PAGE_HEIGHT = 841.89;
const MARGIN = 43;
const CONTENT_WIDTH = PAGE_WIDTH - MARGIN * 2;
const CONTENT_TOP = PAGE_HEIGHT - 78;
const CONTENT_BOTTOM = 55;

const COLORS = {
  ink: rgb(0.09, 0.13, 0.19),
  muted: rgb(0.36, 0.41, 0.47),
  line: rgb(0.86, 0.89, 0.91),
  pale: rgb(0.95, 0.97, 0.97),
  white: rgb(1, 1, 1),
  mauve: rgb(0.49, 0.28, 0.43),
  red: rgb(0.79, 0.12, 0.20),
  green: rgb(0.06, 0.47, 0.34),
  amber: rgb(0.62, 0.37, 0.07),
};

type ReportFont = "regular" | "bold";

function clean(value: unknown): string {
  return String(value ?? "")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[\u2010-\u2015]/g, "-")
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u201c\u201d]/g, '"')
    .replace(/[^\x20-\x7e]/g, "?");
}

function titleCase(value: string): string {
  return value.replaceAll("_", " ").replaceAll("-", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function profileLabel(value: string): string {
  if (value === "network_services") return "Network services";
  if (value === "full_tcp") return "Full TCP";
  return titleCase(value);
}

function dateLabel(value: string | null): string {
  if (!value) return "Pending";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : `${date.toISOString().slice(0, 19).replace("T", " ")} UTC`;
}

function countLabel(count: number): string {
  return count.toLocaleString();
}

class ReportCanvas {
  readonly pdf: PDFDocument;
  readonly regular: PDFFont;
  readonly bold: PDFFont;
  readonly logo: PDFImage;
  readonly scanId: string;
  page!: PDFPage;
  y = CONTENT_TOP;

  constructor(pdf: PDFDocument, regular: PDFFont, bold: PDFFont, logo: PDFImage, scanId: string) {
    this.pdf = pdf;
    this.regular = regular;
    this.bold = bold;
    this.logo = logo;
    this.scanId = scanId;
    this.newPage();
  }

  private font(weight: ReportFont): PDFFont {
    return weight === "bold" ? this.bold : this.regular;
  }

  private width(value: string, size: number, weight: ReportFont): number {
    return this.font(weight).widthOfTextAtSize(value, size);
  }

  private splitWord(word: string, maxWidth: number, size: number, weight: ReportFont): string[] {
    const pieces: string[] = [];
    let current = "";
    for (const character of word) {
      if (current && this.width(current + character, size, weight) > maxWidth) {
        pieces.push(current);
        current = character;
      } else {
        current += character;
      }
    }
    if (current) pieces.push(current);
    return pieces;
  }

  wrap(value: unknown, maxWidth: number, size = 9, weight: ReportFont = "regular"): string[] {
    const paragraphs = String(value ?? "").split(/\r?\n/).map((part) => clean(part).trim());
    if (paragraphs.every((part) => !part)) return ["-"];
    const lines: string[] = [];
    for (const paragraph of paragraphs) {
      let line = "";
      for (const word of paragraph.split(/\s+/).filter(Boolean)) {
        for (const part of this.splitWord(word, maxWidth, size, weight)) {
          const candidate = line ? `${line} ${part}` : part;
          if (line && this.width(candidate, size, weight) > maxWidth) {
            lines.push(line);
            line = part;
          } else {
            line = candidate;
          }
        }
      }
      lines.push(line || " ");
    }
    return lines;
  }

  text(value: unknown, x: number, baseline: number, size = 9, weight: ReportFont = "regular", color = COLORS.ink): void {
    this.page.drawText(clean(value), { x, y: baseline, size, font: this.font(weight), color });
  }

  newPage(): void {
    this.page = this.pdf.addPage([PAGE_WIDTH, PAGE_HEIGHT]);
    const ratio = this.logo.width / this.logo.height;
    const logoHeight = 27;
    this.page.drawImage(this.logo, { x: MARGIN, y: PAGE_HEIGHT - 48, width: logoHeight * ratio, height: logoHeight });
    this.text("ForgeSec", MARGIN + logoHeight * ratio + 9, PAGE_HEIGHT - 34, 12, "bold");
    this.text("NETWORK SCAN REPORT", PAGE_WIDTH - MARGIN - 113, PAGE_HEIGHT - 33, 8, "bold", COLORS.mauve);
    this.page.drawLine({ start: { x: MARGIN, y: PAGE_HEIGHT - 59 }, end: { x: PAGE_WIDTH - MARGIN, y: PAGE_HEIGHT - 59 }, thickness: 0.8, color: COLORS.line });
    this.y = CONTENT_TOP;
  }

  ensure(height: number): void {
    if (this.y - height < CONTENT_BOTTOM) this.newPage();
  }

  space(height = 10): void {
    this.y -= height;
  }

  paragraph(value: unknown, options: { size?: number; lineHeight?: number; color?: typeof COLORS.ink; weight?: ReportFont; indent?: number } = {}): void {
    const size = options.size ?? 9;
    const lineHeight = options.lineHeight ?? size + 4;
    const indent = options.indent ?? 0;
    for (const line of this.wrap(value, CONTENT_WIDTH - indent, size, options.weight)) {
      this.ensure(lineHeight);
      this.text(line, MARGIN + indent, this.y - size, size, options.weight, options.color);
      this.y -= lineHeight;
    }
  }

  section(title: string): void {
    this.ensure(42);
    this.y -= 12;
    this.text(title, MARGIN, this.y - 11, 11, "bold");
    this.page.drawLine({ start: { x: MARGIN, y: this.y - 19 }, end: { x: PAGE_WIDTH - MARGIN, y: this.y - 19 }, thickness: 0.8, color: COLORS.line });
    this.y -= 27;
  }

  label(value: string): void {
    this.ensure(23);
    this.text(value.toUpperCase(), MARGIN, this.y - 8, 8, "bold", COLORS.mauve);
    this.y -= 17;
  }

  metricRow(metrics: Array<{ label: string; value: string; detail: string }>): void {
    this.ensure(67);
    const gap = 8;
    const width = (CONTENT_WIDTH - gap * (metrics.length - 1)) / metrics.length;
    for (const [index, metric] of metrics.entries()) {
      const x = MARGIN + index * (width + gap);
      this.page.drawRectangle({ x, y: this.y - 60, width, height: 60, color: COLORS.pale });
      this.text(metric.label.toUpperCase(), x + 9, this.y - 13, 7, "bold", COLORS.muted);
      this.text(metric.value, x + 9, this.y - 34, 17, "bold");
      const detail = this.wrap(metric.detail, width - 18, 7)[0];
      this.text(detail, x + 9, this.y - 48, 7, "regular", COLORS.muted);
    }
    this.y -= 67;
  }

  meta(items: Array<{ label: string; value: string }>): void {
    const gap = 14;
    const width = (CONTENT_WIDTH - gap) / 2;
    for (let index = 0; index < items.length; index += 2) {
      const pair = items.slice(index, index + 2).map((item) => ({
        label: item.label,
        lines: this.wrap(item.value, width, 8.3),
      }));
      const height = 36 + (Math.max(...pair.map((item) => item.lines.length)) - 1) * 11;
      this.ensure(height + 1);
      for (let column = 0; column < 2; column++) {
        const item = pair[column];
        if (!item) continue;
        const x = MARGIN + column * (width + gap);
        this.text(item.label.toUpperCase(), x, this.y - 7, 7, "bold", COLORS.muted);
        item.lines.forEach((line, lineIndex) => this.text(line, x, this.y - 21 - lineIndex * 11, 8.3, "regular"));
      }
      this.y -= height;
    }
  }

  table(title: string, headers: string[], rows: string[][], widths: number[], continuedTitle = title, compact = false): void {
    const headerHeight = compact ? 18 : 22;
    const rowSize = compact ? 7.8 : 8.1;
    const rowLineHeight = compact ? 9.5 : 10.5;
    const firstRowHeight = rows.length
      ? Math.max(compact ? 20 : 25, Math.max(...rows[0].map((value, index) => this.wrap(value, widths[index] - 12, rowSize).length)) * rowLineHeight + (compact ? 7 : 11))
      : 19;
    this.ensure((compact ? 17 : 39) + headerHeight + Math.min(firstRowHeight, 100) + 6);
    if (compact) this.label(title);
    else this.section(title);
    if (!rows.length) {
      this.paragraph("None recorded.", { color: COLORS.muted });
      return;
    }

    const header = () => {
      this.ensure(headerHeight + 2);
      this.page.drawRectangle({ x: MARGIN, y: this.y - headerHeight, width: CONTENT_WIDTH, height: headerHeight, color: COLORS.pale });
      let x = MARGIN;
      for (const [index, label] of headers.entries()) {
        this.text(label.toUpperCase(), x + 6, this.y - (compact ? 12 : 15), 7, "bold", COLORS.muted);
        x += widths[index];
      }
      this.y -= headerHeight;
    };

    header();
    for (const [rowIndex, row] of rows.entries()) {
      const cells = row.map((value, index) => this.wrap(value, widths[index] - 12, rowSize));
      const lineCount = Math.max(...cells.map((lines) => lines.length));
      const padding = compact ? 7 : 11;
      const minimumHeight = compact ? 20 : 25;
      const fullHeight = Math.max(minimumHeight, lineCount * rowLineHeight + padding);
      if (fullHeight <= CONTENT_TOP - CONTENT_BOTTOM - 90 && this.y - fullHeight < CONTENT_BOTTOM) {
        this.newPage();
        this.section(`${continuedTitle} (continued)`);
        header();
      }
      let offset = 0;
      while (offset < lineCount) {
        const available = this.y - CONTENT_BOTTOM;
        const linesFit = Math.floor((available - padding) / rowLineHeight);
        if (linesFit < 1 || available < minimumHeight) {
          this.newPage();
          this.section(`${continuedTitle} (continued)`);
          header();
          continue;
        }
        const chunkSize = Math.min(lineCount - offset, linesFit);
        const height = Math.max(minimumHeight, chunkSize * rowLineHeight + padding);
        let x = MARGIN;
        if (rowIndex % 2 === 1) {
          this.page.drawRectangle({ x: MARGIN, y: this.y - height, width: CONTENT_WIDTH, height, color: COLORS.pale });
        }
        for (const [index, lines] of cells.entries()) {
          const fragment = lines.slice(offset, offset + chunkSize);
          if (offset > 0 && index < 3 && fragment.length === 0 && lines.length > 0) fragment.push(lines[0]);
          fragment.forEach((line, lineIndex) => {
            this.text(line, x + 6, this.y - (compact ? 11 : 13) - lineIndex * rowLineHeight, rowSize, index === 0 ? "bold" : "regular");
          });
          x += widths[index];
        }
        this.page.drawLine({ start: { x: MARGIN, y: this.y - height }, end: { x: PAGE_WIDTH - MARGIN, y: this.y - height }, thickness: 0.35, color: COLORS.line });
        this.y -= height;
        offset += chunkSize;
        if (offset < lineCount) {
          this.newPage();
          this.section(`${continuedTitle} (continued)`);
          header();
        }
      }
    }
    this.y -= 4;
  }

  hostHeader(ip: string, hostname: string, status: string, index: number, total: number): void {
    const hostnameLines = this.wrap(hostname, CONTENT_WIDTH - 18, 8);
    const height = 27 + hostnameLines.length * 11;
    this.ensure(height + 13);
    this.y -= 7;
    this.page.drawRectangle({ x: MARGIN, y: this.y - height, width: CONTENT_WIDTH, height, color: COLORS.pale });
    this.text(`${index} / ${total}    ${ip}`, MARGIN + 9, this.y - 14, 10, "bold");
    const statusText = titleCase(status);
    this.text(statusText, PAGE_WIDTH - MARGIN - this.width(statusText, 8, "bold") - 9, this.y - 14, 8, "bold", status === "completed" ? COLORS.green : COLORS.amber);
    hostnameLines.forEach((line, lineIndex) => this.text(line, MARGIN + 9, this.y - 27 - lineIndex * 11, 8, "regular", COLORS.muted));
    this.y -= height + 4;
  }

  finish(): void {
    const pages = this.pdf.getPages();
    for (const [index, page] of pages.entries()) {
      page.drawLine({ start: { x: MARGIN, y: 41 }, end: { x: PAGE_WIDTH - MARGIN, y: 41 }, thickness: 0.8, color: COLORS.line });
      page.drawText(`Scan ${this.scanId}`, { x: MARGIN, y: 27, size: 7, font: this.regular, color: COLORS.muted });
      const count = `Page ${index + 1} of ${pages.length}`;
      page.drawText(count, { x: PAGE_WIDTH - MARGIN - this.width(count, 7, "regular"), y: 27, size: 7, font: this.regular, color: COLORS.muted });
    }
  }
}

function actionRows(canvas: ReportCanvas, scan: Scan): void {
  canvas.section("Recommended actions");
  canvas.paragraph(`Rule-based risk score: ${scan.action_summary.risk_score}/100 - ${titleCase(scan.action_summary.risk_level)}. These are exposure signals, not verified CVEs.`, { color: COLORS.muted });
  canvas.space(5);
  if (!scan.action_summary.priority_actions.length) {
    canvas.paragraph("No priority actions were generated for this scan.");
    return;
  }
  for (const action of scan.action_summary.priority_actions) {
    canvas.ensure(37);
    canvas.paragraph(`${titleCase(action.priority)}  ${action.title}  (${countLabel(action.affected_count)} affected)`, { weight: "bold", size: 8.8 });
    canvas.paragraph(action.detail, { size: 8.5, lineHeight: 12, color: COLORS.muted, indent: 11 });
    canvas.space(5);
  }
}

function changeRows(canvas: ReportCanvas, scan: Scan): void {
  const changes = scan.change_summary;
  const noLongerConfirmedCount = changes.no_longer_confirmed_port_count ?? changes.closed_port_count;
  const noLongerConfirmedPorts = changes.no_longer_confirmed_ports ?? changes.closed_ports;
  canvas.section("Changes since previous scan");
  if (!changes.baseline_scan_id) {
    canvas.paragraph("No completed scan with the same site, probe, profile, plan, and selected targets is available.", { color: COLORS.muted });
    return;
  }
  canvas.paragraph(`Baseline: ${changes.baseline_scan_id}  |  ${dateLabel(changes.baseline_created_at)}`, { size: 8.5, color: COLORS.muted });
  canvas.space(5);
  canvas.metricRow([
    { label: "New confirmed open", value: countLabel(changes.opened_port_count), detail: `${countLabel(noLongerConfirmedCount)} no longer confirmed` },
    { label: "New findings", value: countLabel(changes.new_finding_count), detail: `${countLabel(changes.resolved_finding_count)} no longer reported` },
    { label: "Targets compared", value: countLabel(scan.total), detail: "Same selection and profile" },
  ]);
  const rows: string[][] = [
    ...changes.opened_ports.slice(0, 20).map((item) => ["Confirmed open", item.ip, `${item.port}/${item.protocol} ${item.service ?? "unknown"}`]),
    ...noLongerConfirmedPorts.slice(0, 20).map((item) => ["No longer confirmed", item.ip, `${item.port}/${item.protocol} ${item.service ?? "unknown"}`]),
    ...changes.new_findings.slice(0, 20).map((item) => ["New finding", item.ip, item.title]),
    ...changes.resolved_findings.slice(0, 20).map((item) => ["No longer reported", item.ip, item.title]),
  ];
  if (rows.length) canvas.table("Selected changes", ["Change", "Host", "Evidence"], rows, [91, 95, CONTENT_WIDTH - 186]);
  if (changes.opened_port_count > 20 || noLongerConfirmedCount > 20 || changes.new_finding_count > 20 || changes.resolved_finding_count > 20) {
    canvas.paragraph("Change lists show up to 20 entries per category. The JSON export includes exact totals and up to 128 entries per category.", { size: 8, color: COLORS.muted });
  }
}

function inventoryRows(canvas: ReportCanvas, scan: Scan): void {
  const rows = scan.targets.map((target) => {
    const inventory = [target.snmp_location, target.snmp_interface_count != null ? `${target.snmp_interface_count} interfaces` : null].filter(Boolean).join("; ");
    return [
      target.ip,
      target.hostname ?? target.snmp_name ?? "Not reported",
      target.device_type ? titleCase(target.device_type) : "Unknown",
      inventory || target.vendor || "-",
      titleCase(target.status),
    ];
  });
  canvas.table("Target inventory", ["IP address", "Hostname", "Type", "Inventory / vendor", "Status"], rows, [78, 120, 82, 159, CONTENT_WIDTH - 439]);
}

function hostEvidence(canvas: ReportCanvas, scan: Scan): void {
  canvas.ensure(280);
  canvas.section("Host evidence");
  if (!scan.results.length) {
    canvas.paragraph("No host results have been uploaded yet.", { color: COLORS.muted });
    return;
  }
  for (const [index, result] of scan.results.entries()) {
    canvas.ensure(190);
    canvas.hostHeader(result.ip, result.hostname ?? "Hostname not reported", result.status, index + 1, scan.results.length);
    if (result.hostname) canvas.paragraph(`Hostname source: ${hostnameSourceLabel(result.hostname_source)}`, { size: 8.2, color: COLORS.muted });
    if (result.raw_xml_sha256) canvas.paragraph(`Raw Nmap XML SHA-256: ${result.raw_xml_sha256}`, { size: 8.2, color: COLORS.muted });
    const role = result.device_type ? titleCase(result.device_type) : "Not classified";
    const confidence = result.classification_confidence != null ? ` (${Math.round(result.classification_confidence * 100)}% confidence)` : "";
    const os = result.os_matches[0]
      ? `  |  OS estimate: ${result.os_matches[0].name} (${result.os_matches[0].accuracy}% Nmap match)`
      : "  |  OS: Not identified";
    const portCounts = countPortStates(result.ports);
    const openLabel = ["partial", "timed_out", "failed", "cancelled"].includes(result.status) && !result.ports.length ? "Unknown" : String(portCounts.open);
    canvas.paragraph(`Type: ${role}${confidence}  |  Confirmed open: ${openLabel}  |  Open|filtered: ${portCounts.openFiltered}  |  Filtered: ${portCounts.filtered}${os}`, { size: 8.2, color: COLORS.muted });
    if (result.error) canvas.paragraph(`Scan error: ${result.error}`, { size: 8.2, color: COLORS.red });
    if (!result.ports.length) canvas.paragraph("No port-state evidence was returned; this does not establish that ports are closed.", { size: 8.2, color: COLORS.muted });

    const portRows = result.ports.map((port) => [
      `${port.port}/${port.protocol}`,
      port.state,
      portServiceLabel(port),
      `${port.product ?? "Not identified"} / ${port.version ?? "Not identified"}`,
      portCpes(port).join("; ") || "Not observed",
      `${portEvidenceSourceLabel(port)}\n${portEvidenceTimeLabel(port)}`,
    ]);
    canvas.table("Observed ports", ["Port", "State", "Service", "Product / version", "CPE", "Source / end"], portRows, [48, 64, 74, 100, 118, CONTENT_WIDTH - 404], `Observed ports - ${result.ip}`, true);

    const findingRows = result.exposure_flags.map((finding) => [titleCase(finding.severity), finding.title, finding.evidence]);
    if (findingRows.length) canvas.table("Exposure findings", ["Severity", "Finding", "Evidence"], findingRows, [64, 162, CONTENT_WIDTH - 226], `Exposure findings - ${result.ip}`, true);
    canvas.space(7);
  }
}

export async function createScanPdf(scan: Scan, logoBytes: Uint8Array): Promise<Uint8Array> {
  const pdf = await PDFDocument.create();
  pdf.setTitle(`ForgeSec network scan - ${scan.scan_id}`);
  pdf.setAuthor("ForgeSec");
  pdf.setSubject("Network scan evidence report");
  const regular = await pdf.embedFont(StandardFonts.Helvetica);
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
  const logo = await pdf.embedPng(logoBytes);
  const canvas = new ReportCanvas(pdf, regular, bold, logo, scan.scan_id);
  const portCounts = countScanPortStates(scan);
  const timedOutHosts = scan.summary.timed_out_hosts ?? scan.results.filter((result) => result.status === "timed_out").length;
  const failedHosts = scan.summary.failed_hosts ?? scan.results.filter((result) => result.status === "failed").length;

  canvas.paragraph("Network scan report", { size: 21, lineHeight: 26, weight: "bold" });
  canvas.paragraph(`${profileLabel(scan.profile)} profile  |  ${titleCase(scan.status)}  |  ${countLabel(scan.total)} selected targets`, { size: 9, color: COLORS.mauve });
  const coverageNotice = scanCoverageNotice(scan);
  if (coverageNotice) canvas.paragraph(coverageNotice, { size: 8.5, weight: "bold", color: COLORS.amber });
  canvas.space(12);
  canvas.meta([
    { label: "Scan ID", value: scan.scan_id },
    { label: "Created", value: dateLabel(scan.created_at) },
    { label: "Started", value: dateLabel(scan.started_at) },
    { label: "Completed", value: dateLabel(scan.completed_at) },
  ]);
  canvas.section("Scan origin");
  if (scan.scan_origin) {
    const origin = scan.scan_origin;
    canvas.meta([
      { label: "Probe", value: `${origin.label} (${origin.hostname})` },
      { label: "Probe ID", value: origin.agent_id },
      { label: "Probe IP", value: origin.local_ip ?? "Not reported" },
      { label: "Site / network", value: [origin.site_name, origin.subnet].filter(Boolean).join(" / ") || "Not reported" },
      { label: "Interface", value: origin.discovery_interface ?? "Not reported" },
      { label: "OS", value: origin.os_name },
      { label: "Agent version", value: origin.agent_version },
      { label: "Last heartbeat", value: dateLabel(origin.last_heartbeat_at) },
      { label: "Source", value: origin.source === "scan_snapshot" ? "Probe snapshot when queued" : "Latest probe record (historical IP unverified)" },
    ]);
    canvas.paragraph("Probe-reported identity only. This computer is not included in target, port, or finding totals.", { size: 8, color: COLORS.muted });
  } else {
    canvas.meta([{ label: "Probe ID", value: scan.agent_id }]);
    canvas.paragraph("This scan did not record the probe's scan-time hostname or IP. The scanning computer is not included in target totals.", { size: 8, color: COLORS.muted });
  }
  canvas.space(9);
  canvas.section("Requested scan scope");
  for (const line of profilePlanLines(scan.profile_plan)) {
    canvas.paragraph(line, { size: 8, color: COLORS.muted });
  }
  canvas.space(7);
  canvas.metricRow([
    { label: "Targets", value: countLabel(scan.total), detail: `${countLabel(scan.queued)} queued` },
    { label: "Finished", value: `${countLabel(scan.completed + scan.failed + scan.cancelled)}/${countLabel(scan.total)}`, detail: `${countLabel(scan.failed)} failed` },
    { label: "Confirmed open", value: countLabel(portCounts.open), detail: `${countLabel(portCounts.openFiltered)} open|filtered` },
    { label: "Findings", value: countLabel(scan.summary.exposure_findings), detail: `${countLabel(scan.summary.high_exposure_findings)} high` },
  ]);

  canvas.section("Executive summary");
  canvas.paragraph(`${countLabel(scan.summary.evidence_hosts)} hosts produced evidence; ${countLabel(scan.summary.classified_hosts)} were classified. ${countLabel(scan.summary.network_devices)} network devices, ${countLabel(scan.summary.servers)} servers, and ${countLabel(scan.summary.workstations)} workstations were identified.`);
  canvas.space(5);
  canvas.paragraph(`Scan state: ${countLabel(scan.completed)} completed, ${countLabel(scan.failed)} failed (${countLabel(timedOutHosts)} timed out, ${countLabel(failedHosts)} errors), ${countLabel(scan.cancelled)} cancelled, ${countLabel(scan.running)} running. Exposure findings are rule-based observations and require review.`, { color: COLORS.muted });

  canvas.section("Network intelligence");
  canvas.paragraph(`Open TCP ${countLabel(portCounts.tcpOpen)}  |  Open UDP ${countLabel(portCounts.udpOpen)}  |  Open|filtered ${countLabel(portCounts.openFiltered)}  |  Filtered ${countLabel(portCounts.filtered)}`);
  canvas.paragraph(`Management services ${countLabel(scan.summary.management_services)}  |  SNMP targets ${countLabel(scan.summary.snmp_enabled)}  |  CPEs ${countLabel(scan.summary.cpes)}`, { color: COLORS.muted });
  const severity = scan.summary.severity_counts;
  canvas.paragraph(`Severity mix: ${severity.high} high, ${severity.medium} medium, ${severity.low} low, ${severity.info} info.`, { color: COLORS.muted });
  const countRows = [
    ...scan.summary.device_types.map((item) => ["Device type", titleCase(item.label), countLabel(item.count)]),
    ...scan.summary.vendors.map((item) => ["Vendor", item.label, countLabel(item.count)]),
    ...scan.summary.services.slice(0, 12).map((item) => ["Service", titleCase(item.label), countLabel(item.count)]),
  ];
  canvas.table("Observed mix", ["Category", "Name", "Count"], countRows, [110, CONTENT_WIDTH - 174, 64]);

  actionRows(canvas, scan);
  changeRows(canvas, scan);
  inventoryRows(canvas, scan);
  hostEvidence(canvas, scan);
  canvas.finish();
  return pdf.save();
}
