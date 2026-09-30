"use client";

import {
  ArrowLeft,
  Download,
  ExternalLink,
  FileText,
  HardDrive,
  History,
  LoaderCircle,
  Radar,
  Server,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { PortResult, Scan, ScanVulnerabilitySummary, api } from "@/lib/api";
import { nvdDataAge } from "@/lib/nvd-evidence";
import { hostnameSourceLabel } from "@/lib/host-evidence";
import { countPortStates, countScanPortStates, portCpes, portEvidenceSourceLabel, portEvidenceTimeLabel, portServiceLabel } from "@/lib/port-evidence";
import { profilePlanLines } from "@/lib/scan-profiles";
import { downloadScanJson, downloadScanPdf } from "@/lib/report-downloads";
import { scanCoverageNotice } from "@/lib/report-status";

function titleCase(value: string) {
  return value.replaceAll("_", " ").replaceAll("-", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function reportTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString(undefined, { timeZoneName: "short" });
}

function scanProfileLabel(value: string) {
  if (value === "inventory") return "Inventory";
  if (value === "network_services") return "Network services";
  if (value === "full_tcp") return "Full TCP";
  return titleCase(value);
}

function clampPercent(value: number) {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function scanFinishedCount(scan: Scan) {
  return scan.completed + scan.failed + scan.cancelled;
}

type SeverityKey = "high" | "medium" | "low" | "info";

const SEVERITY_KEYS: SeverityKey[] = ["high", "medium", "low", "info"];
const VULNERABILITY_SEVERITY_KEYS = ["critical", "high", "medium", "low", "unknown"] as const;

function targetInventoryLabel(target: Scan["targets"][number]) {
  const parts = [
    target.snmp_location,
    target.snmp_interface_count != null ? `${target.snmp_interface_count} interfaces` : null,
  ].filter(Boolean);
  return parts.length ? parts.join(" - ") : "Not reported";
}

function statusTone(value: string) {
  if (["completed", "online", "up", "open"].includes(value)) return "success";
  if (["queued", "running", "busy", "medium"].includes(value)) return "warning";
  if (["failed", "offline", "cancelled", "high", "critical"].includes(value)) return "danger";
  return "neutral";
}

function Status({ value, label }: { value: string; label?: string }) {
  return <span className={`status ${statusTone(value)}`}><span />{label ?? titleCase(value)}</span>;
}

function PortEvidenceTable({ ports }: { ports: PortResult[] }) {
  const [visible, setVisible] = useState(20);
  return <div className="report-port-evidence">
    <div className="table-scroll"><table><thead><tr><th>Port</th><th>State</th><th>Service</th><th>Product</th><th>Version</th><th>CPE</th><th>Source / scan end</th></tr></thead><tbody>
      {ports.slice(0, visible).map((port) => <tr key={`${port.protocol}-${port.port}`}>
        <td><code>{port.port}/{port.protocol}</code></td>
        <td><Status value={port.state} /></td>
        <td>{portServiceLabel(port)}</td>
        <td>{port.product ?? "Not identified"}</td>
        <td>{port.version ?? "Not identified"}</td>
        <td>{portCpes(port).length ? portCpes(port).map((cpe) => <code className="report-port-cpe" key={cpe}>{cpe}</code>) : "Not observed"}</td>
        <td><strong>{portEvidenceSourceLabel(port)}</strong><small>{portEvidenceTimeLabel(port)}</small></td>
      </tr>)}
    </tbody></table></div>
    {visible < ports.length && <button className="button secondary" type="button" onClick={() => setVisible((count) => count + 100)}>Show more ({Math.min(visible, ports.length)} of {ports.length})</button>}
  </div>;
}

function ReportStat({ label, value, detail }: { label: string; value: string; detail: string }) {
  return <div className="report-stat"><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>;
}

function CountBars({ items, emptyLabel }: { items: Array<{ label: string; count: number }>; emptyLabel: string }) {
  const max = Math.max(1, items[0]?.count ?? 0);
  if (!items.length) return <div className="report-rollup-empty">{emptyLabel}</div>;
  return (
    <div className="report-count-bars">
      {items.slice(0, 6).map((item) => (
        <div key={item.label}>
          <span>{titleCase(item.label)}</span>
          <strong>{item.count}</strong>
          <div><i style={{ width: `${Math.max(7, (item.count / max) * 100)}%` }} /></div>
        </div>
      ))}
    </div>
  );
}

function vulnerabilitySeverityTotal(summary: ScanVulnerabilitySummary) {
  return VULNERABILITY_SEVERITY_KEYS.reduce(
    (total, key) => total + summary.severity_counts[key],
    0,
  );
}

function affectedServiceLabel(item: ScanVulnerabilitySummary["items"][number]) {
  const first = item.affected_services[0];
  if (!first) return "No observed service evidence";
  const host = first.hostname || first.ip;
  const service = first.service || `${first.port}/${first.protocol}`;
  const more = item.affected_service_count > 1
    ? ` +${item.affected_service_count - 1} more`
    : "";
  return `${host} - ${service}${more}`;
}

function changeTotal(scan: Scan) {
  const changes = scan.change_summary;
  return changes.opened_port_count
    + (changes.no_longer_confirmed_port_count ?? changes.closed_port_count)
    + changes.new_finding_count
    + changes.resolved_finding_count;
}

function portChangeLabel(port: Scan["change_summary"]["opened_ports"][number]) {
  const host = port.hostname || port.ip;
  return `${host} - ${port.port}/${port.protocol} ${port.service ?? "unknown"}`;
}

export function ScanReportPage({ scanId }: { scanId: string }) {
  const [scan, setScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [vulnerabilitySummary, setVulnerabilitySummary] = useState<ScanVulnerabilitySummary | null>(null);
  const [vulnerabilityLoading, setVulnerabilityLoading] = useState(false);
  const [vulnerabilityError, setVulnerabilityError] = useState<string | null>(null);
  const [canRefreshIntelligence, setCanRefreshIntelligence] = useState(false);
  const [pdfBusy, setPdfBusy] = useState(false);
  const [jsonBusy, setJsonBusy] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    let sequence = 0;
    let applied = 0;
    async function load() {
      const request = ++sequence;
      try {
        const next = await api.scanReport(scanId);
        if (cancelled || request < applied) return;
        applied = request;
        setScan(next);
        setError(null);
      } catch (cause) {
        if (!cancelled && request >= applied) {
          applied = request;
          setError(cause instanceof Error ? cause.message : "Report could not be loaded");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    void load();
    const timer = window.setInterval(() => void load(), 3000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [scanId, refreshKey]);

  useEffect(() => {
    setVulnerabilitySummary(null);
    setVulnerabilityError(null);
    setVulnerabilityLoading(false);
    let current = true;
    void api.me().then((session) => {
      if (current) setCanRefreshIntelligence(!session.auth_required || (session.user != null && session.user.role !== "viewer"));
    }).catch(() => { if (current) setCanRefreshIntelligence(false); });
    void api.scanVulnerabilities(scanId).then((summary) => {
      if (current) setVulnerabilitySummary(summary);
    }).catch((cause) => {
      if (current) setVulnerabilityError(cause instanceof Error ? cause.message : "Saved CVE assessment could not be loaded");
    });
    return () => { current = false; };
  }, [scanId]);

  async function loadVulnerabilitySummary() {
    setVulnerabilityLoading(true);
    setVulnerabilityError(null);
    try {
      setVulnerabilitySummary(await api.refreshScanVulnerabilities(scanId));
    } catch (cause) {
      setVulnerabilityError(cause instanceof Error ? cause.message : "CVE correlation failed");
    } finally {
      setVulnerabilityLoading(false);
    }
  }

  async function exportJson(item: Scan) {
    if (jsonBusy) return;
    setJsonBusy(true);
    setExportError(null);
    try {
      await downloadScanJson(item.scan_id);
    } catch (cause) {
      setExportError(cause instanceof Error ? cause.message : "JSON export failed");
    } finally {
      setJsonBusy(false);
    }
  }

  async function exportPdf(item: Scan) {
    if (pdfBusy) return;
    setPdfBusy(true);
    setExportError(null);
    try {
      await downloadScanPdf(item.scan_id);
    } catch (cause) {
      setExportError(cause instanceof Error ? cause.message : "PDF export failed");
    } finally {
      setPdfBusy(false);
    }
  }

  const resultByDevice = useMemo(
    () => new Map(scan?.results.map((result) => [result.device_id, result]) ?? []),
    [scan],
  );

  if (loading && !scan) {
    return <main className="report-page"><div className="report-loading"><LoaderCircle className="spin" size={18} />Loading scan report...</div></main>;
  }

  if (error && !scan) {
    return <main className="report-page"><section className="report-error"><ShieldAlert size={20} /><div><strong>Report unavailable</strong><p>{error}</p><a className="button secondary" href="/network-agent#history"><ArrowLeft size={14} />Back to history</a></div></section></main>;
  }

  if (!scan) return null;

  const finished = scanFinishedCount(scan);
  const completion = scan.total ? clampPercent((finished / scan.total) * 100) : 0;
  const findings = scan.summary.exposure_findings;
  const highFindings = scan.summary.high_exposure_findings;
  const portCounts = countScanPortStates(scan);
  const ports = portCounts.open;
  const timedOutHosts = scan.summary.timed_out_hosts ?? scan.results.filter((result) => result.status === "timed_out").length;
  const failedHosts = scan.summary.failed_hosts ?? scan.results.filter((result) => result.status === "failed").length;
  const active = ["queued", "running", "cancelling"].includes(scan.status);
  const coverageNotice = scanCoverageNotice(scan);
  const severityCounts = scan.summary.severity_counts;
  const severityTotal = Math.max(1, findings);
  const serviceRows = scan.summary.services.slice(0, 6);
  const evidenceHosts = scan.summary.evidence_hosts;
  const actionSummary = scan.action_summary;
  const changes = scan.change_summary;
  const totalChanges = changeTotal(scan);
  const evidenceQuality = scan.total ? clampPercent((evidenceHosts / scan.total) * 100) : 0;
  const posture = active
    ? "Evidence collection is still running"
    : coverageNotice
      ? highFindings ? "Incomplete scan; priority review" : findings ? "Incomplete scan; findings need review" : "Incomplete coverage"
    : highFindings
      ? "Priority review required"
      : findings
        ? "Findings need review"
        : scan.status === "completed"
          ? "No rule-based exposure findings"
          : titleCase(scan.status);
  const summaryCopy = active
    ? `${scan.running} host${scan.running === 1 ? "" : "s"} currently running and ${scan.queued} queued. This report refreshes while the agent sends progress.`
    : coverageNotice
      ? `${scan.completed} of ${scan.total} targets completed successfully. ${scan.results.length} host result${scan.results.length === 1 ? "" : "s"} received; findings reflect only the evidence that arrived.`
    : highFindings
      ? `${highFindings} high severity finding${highFindings === 1 ? "" : "s"} should be reviewed before closing this report.`
      : findings
        ? `${findings} finding${findings === 1 ? "" : "s"} were recorded across ${scan.results.length} host result${scan.results.length === 1 ? "" : "s"}.`
        : `ForgeSec stored evidence for ${scan.results.length} host result${scan.results.length === 1 ? "" : "s"} with no exposure rules triggered.`;

  return (
    <main className="report-page">
      <div className="report-shell">
        <section className="report-hero">
          <div className="report-brand-row">
            <span className="report-logo-frame"><img src="/logos/forge-sec-logo.png" alt="ForgeSec" /></span>
            <div><span className="eyebrow">FORGESEC SCAN REPORT</span><h1>Network evidence report</h1><small>{posture}</small></div>
          </div>
          <div className="report-hero-actions">
            <a className="button secondary" href="/network-agent#history"><ArrowLeft size={15} />History</a>
            <div className="report-export-group">
              <button className="button secondary" disabled={jsonBusy} onClick={() => void exportJson(scan)}>{jsonBusy ? <LoaderCircle className="spin" size={15} /> : <Download size={15} />}{jsonBusy ? "Exporting" : "JSON"}</button>
              <button className="button primary" disabled={pdfBusy} onClick={() => void exportPdf(scan)}>{pdfBusy ? <LoaderCircle className="spin" size={15} /> : <FileText size={15} />}{pdfBusy ? "Creating PDF" : "PDF"}</button>
            </div>
          </div>
          {exportError && <div className="inline-error" role="alert"><ShieldAlert size={15} />{exportError}</div>}
          {error && <div className="inline-error" role="alert"><ShieldAlert size={15} />Report refresh failed: {error}. Showing the last loaded snapshot.<button className="button secondary compact" type="button" onClick={() => setRefreshKey((value) => value + 1)}>Retry</button></div>}
          {coverageNotice && <div className="report-intelligence-warning" role="status"><ShieldAlert size={15} /><span>{coverageNotice}</span></div>}
          <p>{scanProfileLabel(scan.profile)} scan for {scan.total} selected target{scan.total === 1 ? "" : "s"}. The page presents the stored evidence in report form; raw JSON is available only from the download action.</p>
          <div className="report-meta">
            <span>Scan ID <strong>{scan.scan_id}</strong></span>
            <span>Created <strong>{reportTime(scan.created_at)}</strong></span>
            <span>Started <strong>{scan.started_at ? reportTime(scan.started_at) : "Pending"}</strong></span>
            <span>Completed <strong>{scan.completed_at ? reportTime(scan.completed_at) : "Pending"}</strong></span>
          </div>
          <details className="report-data-handling"><summary>Data handling</summary><p>Server evidence has no automatic expiry. Downloaded copies remain on your computer and cannot be revoked by ForgeSec. Follow your organization&apos;s retention policy.</p></details>
        </section>

        <section className="report-origin" aria-label="Scan origin">
          <div className="report-origin-heading"><Server size={17} /><div><span className="eyebrow">SCAN ORIGIN</span><h2>{scan.scan_origin?.hostname ?? "Probe snapshot unavailable"}</h2></div></div>
          {scan.scan_origin ? <>
            <dl>
              <div><dt>Probe ID</dt><dd>{scan.scan_origin.agent_id}</dd></div>
              <div><dt>Probe IP</dt><dd>{scan.scan_origin.local_ip ?? "Not reported"}</dd></div>
              <div><dt>Site / network</dt><dd>{[scan.scan_origin.site_name, scan.scan_origin.subnet].filter(Boolean).join(" / ") || "Not reported"}</dd></div>
              <div><dt>Interface</dt><dd>{scan.scan_origin.discovery_interface ?? "Not reported"}</dd></div>
              <div><dt>System</dt><dd>{scan.scan_origin.os_name} / agent v{scan.scan_origin.agent_version}</dd></div>
            </dl>
            <p>{scan.scan_origin.source === "scan_snapshot" ? "Probe-reported at scan creation" : "Latest saved probe record; scan-time IP was not saved"}{scan.scan_origin.last_heartbeat_at ? `, heartbeat ${reportTime(scan.scan_origin.last_heartbeat_at)}` : ""}. Not included in target or finding totals.</p>
          </> : <><dl><div><dt>Probe ID</dt><dd>{scan.agent_id}</dd></div></dl><p>The saved scan identifies this probe, but did not record its scan-time hostname or IP. The scanning computer is not included in target or finding totals.</p></>}
        </section>

        <section className="report-profile-scope" aria-label="Requested scan scope">
          <div><span className="eyebrow">REQUESTED PROFILE</span><h2>{scanProfileLabel(scan.profile)}</h2></div>
          <ul>{profilePlanLines(scan.profile_plan).map((line) => <li key={line}>{line}</li>)}</ul>
        </section>

        <section className="report-stat-grid">
          <ReportStat label="Status" value={titleCase(scan.status)} detail={active ? titleCase(scan.stage ?? scan.status) : `${completion}% finished`} />
          <ReportStat label="Targets" value={String(scan.total)} detail={`${finished} finished`} />
          <ReportStat label="Confirmed open" value={String(ports)} detail={`${portCounts.openFiltered} open|filtered`} />
          <ReportStat label="Findings" value={String(findings)} detail={`${highFindings} high severity`} />
        </section>

        <section className="report-insight-grid">
          <article className="report-summary-card">
            <div><span className="eyebrow">EXECUTIVE SUMMARY</span><h2>{posture}</h2></div>
            <p>{summaryCopy}</p>
            <div className="report-summary-meter"><span style={{ width: `${completion}%` }} /></div>
            <small>{active ? `${completion}% of selected targets have finished processing.` : `${finished} of ${scan.total} targets reached a final state; ${scan.completed} completed successfully.`}</small>
          </article>
          <article className="report-digest-card">
            <div className="report-section-header compact"><div><span className="eyebrow">SEVERITY MIX</span><h2>Exposure findings</h2></div><Status value={highFindings ? "high" : findings ? "medium" : coverageNotice ? "idle" : "completed"} label={findings ? `${findings} observed` : coverageNotice ? "Incomplete" : "No findings"} /></div>
            <div className="report-severity-list">
              {SEVERITY_KEYS.map((key) => <div key={key}><span>{titleCase(key)}</span><strong>{severityCounts[key]}</strong><div><i className={key} style={{ width: `${Math.max(4, (severityCounts[key] / severityTotal) * 100)}%` }} /></div></div>)}
            </div>
          </article>
          <article className="report-digest-card">
            <div className="report-section-header compact"><div><span className="eyebrow">EVIDENCE QUALITY</span><h2>Host coverage</h2></div><Status value={evidenceQuality >= 80 ? "completed" : active ? "running" : "medium"} label={`${evidenceQuality}%`} /></div>
            <div className="report-quality-ring" style={{ background: `conic-gradient(var(--green) ${evidenceQuality * 3.6}deg, #edf1f0 0deg)` }}><strong>{evidenceQuality}%</strong><span>Evidence</span></div>
          </article>
        </section>

        <section className="report-panel">
          <div className="report-section-header"><div><span className="eyebrow">ACTION PLAN</span><h2>Recommended next steps</h2></div><Status value={coverageNotice ? "idle" : actionSummary.risk_level} label={coverageNotice ? "Partial evidence" : `${titleCase(actionSummary.risk_level)} risk`} /></div>
          <div className="report-action-grid">
            <div className="report-risk-score">
              <div className="report-quality-ring" style={{ background: `conic-gradient(var(--brand-mauve) ${actionSummary.risk_score * 3.6}deg, #edf1f0 0deg)` }}><strong>{actionSummary.risk_score}</strong><span>Score</span></div>
              <small>{coverageNotice ? "Risk score reflects only evidence received so far. " : ""}Risk score is derived from exposure findings, scan drift, management services, SNMP visibility, and CPE evidence.</small>
            </div>
            <div className="report-action-list">
              {actionSummary.priority_actions.map((action) => <article key={`${action.category}-${action.title}`}><Status value={action.priority} /><div><strong>{action.title}</strong><span>{action.detail}</span></div><small>{action.affected_count} affected</small></article>)}
            </div>
          </div>
        </section>

        <section className="report-panel">
          <div className="report-section-header"><div><span className="eyebrow">CHANGE SUMMARY</span><h2>Compared with previous scan</h2></div><Status value={changes.baseline_scan_id ? totalChanges ? "medium" : "completed" : "idle"} label={changes.baseline_scan_id ? `${totalChanges} changes` : "No baseline"} /></div>
          {changes.baseline_scan_id ? (
            <div className="report-change-panel">
              <div className="report-change-baseline">
                <History size={17} />
                <div><strong>{scanProfileLabel(changes.baseline_profile ?? scan.profile)} baseline</strong><span>{changes.baseline_created_at ? reportTime(changes.baseline_created_at) : "Previous scan"} - {changes.baseline_scan_id}</span></div>
              </div>
              <div className="report-change-stats">
                <ReportStat label="New confirmed open" value={String(changes.opened_port_count)} detail={`${changes.no_longer_confirmed_port_count ?? changes.closed_port_count} no longer confirmed`} />
                <ReportStat label="New findings" value={String(changes.new_finding_count)} detail={`${changes.resolved_finding_count} no longer reported`} />
                <ReportStat label="Targets compared" value={String(scan.total)} detail="Same selection and profile" />
                <ReportStat label="Total changes" value={String(totalChanges)} detail="Since baseline" />
              </div>
              {totalChanges ? (
                <div className="report-change-grid">
                  <ChangeList title="New confirmed open" items={changes.opened_ports.map(portChangeLabel)} empty="No new confirmed open ports" />
                  <ChangeList title="No longer confirmed open" items={(changes.no_longer_confirmed_ports ?? changes.closed_ports).map(portChangeLabel)} empty="No loss of confirmed-open evidence" />
                  <ChangeList title="New findings" items={changes.new_findings.map((finding) => `${finding.hostname || finding.ip} - ${finding.title}`)} empty="No new findings" />
                  <ChangeList title="Findings no longer reported" items={changes.resolved_findings.map((finding) => `${finding.hostname || finding.ip} - ${finding.title}`)} empty="No findings stopped being reported" />
                </div>
              ) : <div className="report-empty compact"><ShieldCheck size={18} /><strong>No scan drift detected</strong><p>The comparable previous scan reported the same confirmed-open ports and rule-based findings.</p></div>}
            </div>
          ) : <div className="report-empty compact"><History size={18} /><strong>No comparable baseline yet</strong><p>Repeat a completed scan with the same probe, site, profile, and selected targets to compare ports and findings.</p></div>}
        </section>

        <section className="report-panel">
          <div className="report-section-header"><div><span className="eyebrow">NETWORK INTELLIGENCE</span><h2>Inventory rollup</h2></div><span className="quiet-badge">{scan.summary.scanned_hosts} HOST RESULTS</span></div>
          <div className="report-rollup-grid">
            <div className="report-rollup-column">
              <div><strong>Device roles</strong><small>{scan.summary.classified_hosts} classified, {scan.summary.network_devices} network devices</small></div>
              <CountBars items={scan.summary.device_types} emptyLabel="No device role evidence yet" />
            </div>
            <div className="report-rollup-column">
              <div><strong>Vendors</strong><small>{scan.summary.vendors.length ? "From discovery evidence" : "Waiting for discovery evidence"}</small></div>
              <CountBars items={scan.summary.vendors} emptyLabel="No vendor evidence yet" />
            </div>
            <div className="report-rollup-column">
              <div><strong>Evidence surface</strong><small>Ports and inventory signals</small></div>
              <div className="report-surface-grid">
                <div><span>Management</span><strong>{scan.summary.management_services}</strong></div>
                <div><span>SNMP</span><strong>{scan.summary.snmp_enabled}</strong></div>
                <div><span>Open UDP</span><strong>{portCounts.udpOpen}</strong></div>
                <div><span>CPEs</span><strong>{scan.summary.cpes}</strong></div>
                <div><span>Open|filtered</span><strong>{portCounts.openFiltered}</strong></div>
                <div><span>Filtered</span><strong>{portCounts.filtered}</strong></div>
              </div>
            </div>
          </div>
        </section>

        <section className="report-panel">
          <div className="report-section-header"><div><span className="eyebrow">VULNERABILITY TRIAGE</span><h2>CVE correlation</h2></div><span className="quiet-badge">{scan.summary.cpes} CPES</span></div>
          {scan.summary.cpes === 0 ? (
            <div className="report-empty compact"><ShieldCheck size={18} /><strong>No CPE fingerprints</strong><p>Run Inventory, Network services, Standard, or Full TCP scans against fingerprintable services to enable CVE correlation.</p></div>
          ) : (
            <div className="report-vulnerability-panel">
              <div className="report-vulnerability-callout">
                <div>
                  <strong>{vulnerabilitySummary ? vulnerabilitySummary.failed_cpes || vulnerabilitySummary.skipped_cpes || vulnerabilitySummary.partial_cpes ? "Partial CVE assessment" : `${vulnerabilitySummary.total_vulnerabilities} potential CVE matches` : "No saved CVE assessment"}</strong>
                  <span>{vulnerabilitySummary ? `${vulnerabilitySummary.checked_cpes} of ${vulnerabilitySummary.total_cpes} fingerprints assessed on ${reportTime(vulnerabilitySummary.assessed_at)} (${vulnerabilitySummary.cached_lookups} cached). ${vulnerabilitySummary.known_exploited} known exploited match${vulnerabilitySummary.known_exploited === 1 ? "" : "es"}.` : "An operator can correlate detected product/version fingerprints with NVD."}</span>
                </div>
                {canRefreshIntelligence && <button className="button primary" disabled={vulnerabilityLoading} onClick={() => void loadVulnerabilitySummary()}>{vulnerabilityLoading ? <LoaderCircle className="spin" size={15} /> : <ShieldAlert size={15} />}{vulnerabilitySummary ? "Reassess CVEs" : "Correlate CVEs"}</button>}
              </div>
              {vulnerabilityError && <div className="inline-error"><ShieldAlert size={15} /><span>{vulnerabilityError}</span></div>}
              {vulnerabilitySummary && !vulnerabilitySummary.evidence_current && <div className="report-intelligence-warning"><ShieldAlert size={15} /><span>Scan evidence changed after this assessment. Refresh CVEs before using these matches.</span></div>}
              {vulnerabilitySummary && (vulnerabilitySummary.failed_cpes > 0 || vulnerabilitySummary.skipped_cpes > 0 || vulnerabilitySummary.partial_cpes > 0) && <div className="report-intelligence-warning"><ShieldAlert size={15} /><span>{vulnerabilitySummary.failed_cpes} lookups failed; {vulnerabilitySummary.skipped_cpes} fingerprints skipped; {vulnerabilitySummary.partial_cpes ?? 0} NVD result sets capped. Counts and severity cover only returned CVEs.</span></div>}
              {vulnerabilitySummary && (
                <>
                  <div className="report-vulnerability-stats">
                    <ReportStat label="Critical" value={String(vulnerabilitySummary.severity_counts.critical)} detail="Returned matches" />
                    <ReportStat label="High" value={String(vulnerabilitySummary.severity_counts.high)} detail="Returned matches" />
                    <ReportStat label="Known-exploited matches" value={String(vulnerabilitySummary.known_exploited)} detail="Device applicability unverified" />
                    <ReportStat label="Checked" value={String(vulnerabilitySummary.checked_cpes)} detail={`${vulnerabilitySummary.skipped_cpes} skipped by limit`} />
                  </div>
                  <div className="report-severity-list">
                    {VULNERABILITY_SEVERITY_KEYS.map((key) => <div key={key}><span>{titleCase(key)}</span><strong>{vulnerabilitySummary.severity_counts[key]}</strong><div><i className={key} style={{ width: `${Math.max(4, (vulnerabilitySummary.severity_counts[key] / Math.max(1, vulnerabilitySeverityTotal(vulnerabilitySummary))) * 100)}%` }} /></div></div>)}
                  </div>
                  {vulnerabilitySummary.items.length ? <div className="report-vulnerability-list">{vulnerabilitySummary.items.map((item) => (
                    <article key={item.cpe}>
                      <div className="report-vulnerability-heading">
                        <div><code>{item.cpe}</code><small>{affectedServiceLabel(item)}</small></div>
                        {item.highest_severity && <Status value={item.highest_severity} />}
                      </div>
                      {item.error ? <div className="inline-error"><ShieldAlert size={15} /><span>{item.error}</span></div> : (
                        <>
                          <div className="report-vulnerability-meta">
                            <span>{item.returned} returned</span>
                            <span>{item.total} NVD matches{item.truncated ? " (partial)" : ""}</span>
                            <span>{item.known_exploited} KEV signals</span>
                            <span>{item.affected_service_count} observed service{item.affected_service_count === 1 ? "" : "s"}</span>
                            <span title={item.retrieved_at ? reportTime(item.retrieved_at) : "Retrieval time unavailable"}>NVD data {nvdDataAge(item.retrieved_at)}{item.cached ? " (cached)" : ""}</span>
                          </div>
                          {item.top_vulnerabilities.length ? <div className="report-cve-list">{item.top_vulnerabilities.slice(0, 3).map((vulnerability) => <div key={vulnerability.cve_id}><a href={`https://nvd.nist.gov/vuln/detail/${vulnerability.cve_id}`} target="_blank" rel="noreferrer">{vulnerability.cve_id}<ExternalLink size={11} /></a><Status value={vulnerability.severity} />{vulnerability.cvss_score != null && <strong>CVSS {vulnerability.cvss_score.toFixed(1)}</strong>}{vulnerability.known_exploited && <span>Known exploited</span>}</div>)}</div> : <p className="muted">NVD returned no matches for this observed CPE; verify the device separately.</p>}
                        </>
                      )}
                    </article>
                  ))}</div> : <div className="report-empty compact"><ShieldCheck size={18} /><strong>No CVE matches returned</strong><p>{vulnerabilitySummary.notice}</p></div>}
                </>
              )}
            </div>
          )}
        </section>

        <section className="report-panel report-service-panel">
          <div className="report-section-header"><div><span className="eyebrow">SERVICE DIGEST</span><h2>Most common services</h2></div><span className="quiet-badge">{ports} PORTS</span></div>
          {serviceRows.length ? <div className="report-service-list">{serviceRows.map((service) => <div key={service.label}><span>{service.label}</span><strong>{service.count}</strong><div><i style={{ width: `${Math.max(8, (service.count / Math.max(1, serviceRows[0]?.count ?? 1)) * 100)}%` }} /></div></div>)}</div> : <div className="report-empty compact"><History size={18} /><strong>No services recorded</strong><p>Service evidence appears here after completed host scans report open ports.</p></div>}
        </section>

        <section className="report-panel">
          <div className="report-section-header"><div><span className="eyebrow">JOB PROGRESS</span><h2>Scan execution</h2></div><Status value={scan.status} /></div>
          <div className="report-progress-track"><span style={{ width: `${completion}%` }} /></div>
          <div className="report-progress-grid">
            <ReportStat label="Queued" value={String(scan.queued)} detail="Waiting" />
            <ReportStat label="Running" value={String(scan.running)} detail="Active" />
            <ReportStat label="Completed" value={String(scan.completed)} detail="Finished" />
            <ReportStat label="Failed" value={String(scan.failed)} detail={`${timedOutHosts} timed out, ${failedHosts} errors`} />
            <ReportStat label="Cancelled" value={String(scan.cancelled)} detail="Stopped" />
          </div>
        </section>

        <section className="report-panel">
          <div className="report-section-header"><div><span className="eyebrow">HOST EVIDENCE</span><h2>Scanned devices</h2></div><span className="quiet-badge">{scan.results.length} RESULTS</span></div>
          {scan.results.length ? <div className="report-host-list">
            {scan.results.map((result) => (
              <article className="report-host-card" key={result.device_id}>
                <div className="report-host-heading"><span className="device-icon"><HardDrive size={15} /></span><div><strong>{result.hostname ?? result.ip}</strong><small>{result.ip}</small></div><Status value={result.status} /></div>
                {result.hostname && <small className="scan-evidence-reference">Hostname source: {hostnameSourceLabel(result.hostname_source)}</small>}
                {result.raw_xml_sha256 && <small className="scan-evidence-reference">Raw Nmap XML SHA-256: <code className="scan-evidence-hash">{result.raw_xml_sha256}</code></small>}
                <div className="report-host-metrics">
                  <div><span>Type</span><strong>{result.device_type ? titleCase(result.device_type) : "Not classified"}</strong></div>
                  <div><span>Confirmed open</span><strong>{["partial", "timed_out", "failed", "cancelled"].includes(result.status) && !result.ports.length ? "Unknown" : countPortStates(result.ports).open}</strong></div>
                  <div><span>OS estimate</span><strong title={result.os_matches[0] ? "Nmap match score, not a confirmed operating system" : undefined}>{result.os_matches[0] ? `${result.os_matches[0].name} (${result.os_matches[0].accuracy}% match)` : "Not identified"}</strong></div>
                  <div><span>Findings</span><strong>{result.exposure_flags.length}</strong></div>
                </div>
                {result.ports.length > 0 && <PortEvidenceTable ports={result.ports} />}
                {!result.ports.length && <p className="muted">No port-state evidence was returned. This does not establish that the ports are closed.</p>}
                {result.exposure_flags.length > 0 && <div className="report-finding-list">{result.exposure_flags.map((flag) => <div key={`${result.device_id}-${flag.code}`}><Status value={flag.severity} /><strong>{flag.title}</strong><span>{flag.evidence}</span></div>)}</div>}
                {result.error && <div className="inline-error"><ShieldAlert size={15} /><span>{result.error}</span></div>}
              </article>
            ))}
          </div> : <div className="report-empty"><Radar size={18} /><strong>No host results yet</strong><p>This report is still waiting for agent scan output.</p></div>}
        </section>

        <section className="report-panel">
          <div className="report-section-header"><div><span className="eyebrow">TARGET LIST</span><h2>Selected devices</h2></div><span className="quiet-badge">{scan.targets.length} TARGETS</span></div>
          <div className="table-scroll"><table><thead><tr><th>Device</th><th>IP</th><th>Type</th><th>Inventory</th><th>Status</th><th>Result</th></tr></thead><tbody>{scan.targets.map((target) => { const result = resultByDevice.get(target.device_id); const targetType = result?.device_type ?? target.device_type; return <tr key={target.device_id}><td><strong>{target.hostname ?? target.snmp_name ?? target.device_id}</strong><small>{target.device_id}</small></td><td>{target.ip}</td><td>{targetType ? titleCase(targetType) : "Unknown"}</td><td><small>{targetInventoryLabel(target)}</small></td><td><Status value={target.status} /></td><td>{result ? <span className="report-result-link"><ShieldCheck size={14} />Evidence stored</span> : "Pending"}</td></tr>; })}</tbody></table></div>
        </section>
      </div>
    </main>
  );
}

function ChangeList({ title, items, empty }: { title: string; items: string[]; empty: string }) {
  return (
    <div className="report-change-list">
      <strong>{title}</strong>
      {items.length ? items.slice(0, 6).map((item) => <span key={`${title}-${item}`}>{item}</span>) : <small>{empty}</small>}
    </div>
  );
}
