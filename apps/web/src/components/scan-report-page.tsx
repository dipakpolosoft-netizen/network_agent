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
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { PortResult, Scan, ScanVulnerabilitySummary, api } from "@/lib/api";
import { downloadScanJson, downloadScanPdf } from "@/lib/report-downloads";

function titleCase(value: string) {
  return value.replaceAll("_", " ").replaceAll("-", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
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

function portEvidenceLabel(port: PortResult) {
  const service = port.service?.trim() || `${port.port}/${port.protocol}`;
  const fingerprint = [port.product, port.version].filter(Boolean).join(" ");
  const suffix = fingerprint || port.extrainfo || port.devicetype || "";
  return suffix ? `${service} - ${suffix}` : service;
}

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
  if (!first) return "No affected service evidence";
  const host = first.hostname || first.ip;
  const service = first.service || `${first.port}/${first.protocol}`;
  const more = item.affected_service_count > 1
    ? ` +${item.affected_service_count - 1} more`
    : "";
  return `${host} - ${service}${more}`;
}

function changeTotal(scan: Scan) {
  const changes = scan.change_summary;
  return changes.new_host_count
    + changes.missing_host_count
    + changes.opened_port_count
    + changes.closed_port_count
    + changes.new_finding_count
    + changes.resolved_finding_count;
}

function portChangeLabel(port: Scan["change_summary"]["opened_ports"][number]) {
  const host = port.hostname || port.ip;
  return `${host} - ${port.port}/${port.protocol} ${port.service ?? "unknown"}`;
}

function hostChangeLabel(host: Scan["change_summary"]["new_hosts"][number]) {
  return `${host.hostname || host.ip}${host.device_type ? ` - ${titleCase(host.device_type)}` : ""}`;
}

export function ScanReportPage({ scanId }: { scanId: string }) {
  const [scan, setScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [vulnerabilitySummary, setVulnerabilitySummary] = useState<ScanVulnerabilitySummary | null>(null);
  const [vulnerabilityLoading, setVulnerabilityLoading] = useState(false);
  const [vulnerabilityError, setVulnerabilityError] = useState<string | null>(null);
  const [canRefreshIntelligence, setCanRefreshIntelligence] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const next = await api.scanReport(scanId);
        if (cancelled) return;
        setScan(next);
        setError(null);
      } catch (cause) {
        if (!cancelled) setError(cause instanceof Error ? cause.message : "Report could not be loaded");
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
  }, [scanId]);

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
  const ports = scan.summary.open_ports;
  const fingerprints = scan.summary.service_fingerprints;
  const active = ["queued", "running"].includes(scan.status);
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
    : highFindings
      ? "Priority review required"
      : findings
        ? "Findings need review"
        : scan.status === "completed"
          ? "No rule-based exposure findings"
          : titleCase(scan.status);
  const summaryCopy = active
    ? `${scan.running} host${scan.running === 1 ? "" : "s"} currently running and ${scan.queued} queued. This report refreshes while the agent sends progress.`
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
              <button className="button secondary" onClick={() => downloadScanJson(scan)}><Download size={15} />JSON</button>
              <button className="button primary" onClick={() => downloadScanPdf(scan)}><FileText size={15} />PDF</button>
            </div>
          </div>
          <p>{scanProfileLabel(scan.profile)} scan for {scan.total} selected target{scan.total === 1 ? "" : "s"}. The page presents the stored evidence in report form; raw JSON is available only from the download action.</p>
          <div className="report-meta">
            <span>Scan ID <strong>{scan.scan_id}</strong></span>
            <span>Created <strong>{new Date(scan.created_at).toLocaleString()}</strong></span>
            <span>Started <strong>{scan.started_at ? new Date(scan.started_at).toLocaleString() : "Pending"}</strong></span>
            <span>Completed <strong>{scan.completed_at ? new Date(scan.completed_at).toLocaleString() : "Pending"}</strong></span>
          </div>
        </section>

        <section className="report-stat-grid">
          <ReportStat label="Status" value={titleCase(scan.status)} detail={active ? titleCase(scan.stage ?? scan.status) : `${completion}% finished`} />
          <ReportStat label="Targets" value={String(scan.total)} detail={`${finished} finished`} />
          <ReportStat label="Open ports" value={String(ports)} detail={`${fingerprints} fingerprints`} />
          <ReportStat label="Findings" value={String(findings)} detail={`${highFindings} high severity`} />
        </section>

        <section className="report-insight-grid">
          <article className="report-summary-card">
            <div><span className="eyebrow">EXECUTIVE SUMMARY</span><h2>{posture}</h2></div>
            <p>{summaryCopy}</p>
            <div className="report-summary-meter"><span style={{ width: `${completion}%` }} /></div>
            <small>{completion}% of selected targets have finished processing.</small>
          </article>
          <article className="report-digest-card">
            <div className="report-section-header compact"><div><span className="eyebrow">SEVERITY MIX</span><h2>Exposure findings</h2></div><Status value={highFindings ? "high" : findings ? "medium" : "completed"} label={findings ? `${findings} total` : "Clean"} /></div>
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
          <div className="report-section-header"><div><span className="eyebrow">ACTION PLAN</span><h2>Recommended next steps</h2></div><Status value={actionSummary.risk_level} label={`${titleCase(actionSummary.risk_level)} risk`} /></div>
          <div className="report-action-grid">
            <div className="report-risk-score">
              <div className="report-quality-ring" style={{ background: `conic-gradient(var(--brand-mauve) ${actionSummary.risk_score * 3.6}deg, #edf1f0 0deg)` }}><strong>{actionSummary.risk_score}</strong><span>Score</span></div>
              <small>Risk score is derived from exposure findings, scan drift, management services, SNMP visibility, and CPE evidence.</small>
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
                <div><strong>{scanProfileLabel(changes.baseline_profile ?? scan.profile)} baseline</strong><span>{changes.baseline_created_at ? new Date(changes.baseline_created_at).toLocaleString() : "Previous scan"} - {changes.baseline_scan_id}</span></div>
              </div>
              <div className="report-change-stats">
                <ReportStat label="New hosts" value={String(changes.new_host_count)} detail={`${changes.missing_host_count} missing`} />
                <ReportStat label="Opened ports" value={String(changes.opened_port_count)} detail={`${changes.closed_port_count} closed`} />
                <ReportStat label="New findings" value={String(changes.new_finding_count)} detail={`${changes.resolved_finding_count} resolved`} />
                <ReportStat label="Total changes" value={String(totalChanges)} detail="Since baseline" />
              </div>
              {totalChanges ? (
                <div className="report-change-grid">
                  <ChangeList title="New hosts" items={changes.new_hosts.map(hostChangeLabel)} empty="No new hosts" />
                  <ChangeList title="Missing hosts" items={changes.missing_hosts.map(hostChangeLabel)} empty="No missing hosts" />
                  <ChangeList title="Opened ports" items={changes.opened_ports.map(portChangeLabel)} empty="No opened ports" />
                  <ChangeList title="Closed ports" items={changes.closed_ports.map(portChangeLabel)} empty="No closed ports" />
                  <ChangeList title="New findings" items={changes.new_findings.map((finding) => `${finding.hostname || finding.ip} - ${finding.title}`)} empty="No new findings" />
                  <ChangeList title="Resolved findings" items={changes.resolved_findings.map((finding) => `${finding.hostname || finding.ip} - ${finding.title}`)} empty="No resolved findings" />
                </div>
              ) : <div className="report-empty compact"><ShieldCheck size={18} /><strong>No scan drift detected</strong><p>The comparable previous scan reported the same hosts, ports, and rule-based findings.</p></div>}
            </div>
          ) : <div className="report-empty compact"><History size={18} /><strong>No comparable baseline yet</strong><p>Run this same scan profile again for the selected agent to see new hosts, missing hosts, opened ports, closed ports, and finding changes.</p></div>}
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
                <div><span>UDP ports</span><strong>{scan.summary.udp_ports}</strong></div>
                <div><span>CPEs</span><strong>{scan.summary.cpes}</strong></div>
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
                  <strong>{vulnerabilitySummary ? `${vulnerabilitySummary.total_vulnerabilities} potential CVE matches` : "No saved CVE assessment"}</strong>
                  <span>{vulnerabilitySummary ? `${vulnerabilitySummary.checked_cpes} of ${vulnerabilitySummary.total_cpes} fingerprints assessed on ${new Date(vulnerabilitySummary.assessed_at).toLocaleString()} (${vulnerabilitySummary.cached_lookups} cached). ${vulnerabilitySummary.known_exploited} known exploited match${vulnerabilitySummary.known_exploited === 1 ? "" : "es"}.` : "An operator can correlate detected product/version fingerprints with NVD."}</span>
                </div>
                {canRefreshIntelligence && <button className="button primary" disabled={vulnerabilityLoading} onClick={() => void loadVulnerabilitySummary()}>{vulnerabilityLoading ? <LoaderCircle className="spin" size={15} /> : <ShieldAlert size={15} />}{vulnerabilitySummary ? "Reassess CVEs" : "Correlate CVEs"}</button>}
              </div>
              {vulnerabilityError && <div className="inline-error"><ShieldAlert size={15} /><span>{vulnerabilityError}</span></div>}
              {vulnerabilitySummary && !vulnerabilitySummary.evidence_current && <div className="report-intelligence-warning"><ShieldAlert size={15} /><span>Scan evidence changed after this assessment. Refresh CVEs before using these matches.</span></div>}
              {vulnerabilitySummary && (vulnerabilitySummary.failed_cpes > 0 || vulnerabilitySummary.skipped_cpes > 0) && <div className="report-intelligence-warning"><ShieldAlert size={15} /><span>{vulnerabilitySummary.failed_cpes} lookups failed; {vulnerabilitySummary.skipped_cpes} fingerprints were skipped by the request limit. This is a partial assessment.</span></div>}
              {vulnerabilitySummary && (
                <>
                  <div className="report-vulnerability-stats">
                    <ReportStat label="Critical" value={String(vulnerabilitySummary.severity_counts.critical)} detail="Returned CVEs" />
                    <ReportStat label="High" value={String(vulnerabilitySummary.severity_counts.high)} detail="Returned CVEs" />
                    <ReportStat label="Known exploited" value={String(vulnerabilitySummary.known_exploited)} detail="CISA KEV signal" />
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
                            <span>{item.total} total</span>
                            <span>{item.known_exploited} known exploited</span>
                            <span>{item.affected_service_count} affected service{item.affected_service_count === 1 ? "" : "s"}</span>
                          </div>
                          {item.top_vulnerabilities.length ? <div className="report-cve-list">{item.top_vulnerabilities.slice(0, 3).map((vulnerability) => <div key={vulnerability.cve_id}><a href={`https://nvd.nist.gov/vuln/detail/${vulnerability.cve_id}`} target="_blank" rel="noreferrer">{vulnerability.cve_id}<ExternalLink size={11} /></a><Status value={vulnerability.severity} />{vulnerability.cvss_score != null && <strong>CVSS {vulnerability.cvss_score.toFixed(1)}</strong>}{vulnerability.known_exploited && <span>Known exploited</span>}</div>)}</div> : <p className="muted">No NVD CVE matched this exact CPE version.</p>}
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
            <ReportStat label="Failed" value={String(scan.failed)} detail="Errors" />
            <ReportStat label="Cancelled" value={String(scan.cancelled)} detail="Stopped" />
          </div>
        </section>

        <section className="report-panel">
          <div className="report-section-header"><div><span className="eyebrow">HOST EVIDENCE</span><h2>Scanned devices</h2></div><span className="quiet-badge">{scan.results.length} RESULTS</span></div>
          {scan.results.length ? <div className="report-host-list">
            {scan.results.map((result) => (
              <article className="report-host-card" key={result.device_id}>
                <div className="report-host-heading"><span className="device-icon"><HardDrive size={15} /></span><div><strong>{result.hostname ?? result.ip}</strong><small>{result.ip}</small></div><Status value={result.status} /></div>
                <div className="report-host-metrics">
                  <div><span>Type</span><strong>{result.device_type ? titleCase(result.device_type) : "Not classified"}</strong></div>
                  <div><span>Ports</span><strong>{result.ports.length}</strong></div>
                  <div><span>OS evidence</span><strong>{result.os_matches.length}</strong></div>
                  <div><span>Findings</span><strong>{result.exposure_flags.length}</strong></div>
                </div>
                {result.ports.length > 0 && <div className="report-port-list">{result.ports.slice(0, 12).map((port) => <code key={`${result.device_id}-${port.protocol}-${port.port}`}>{port.port}/{port.protocol} {portEvidenceLabel(port)}</code>)}{result.ports.length > 12 && <span>+{result.ports.length - 12} more</span>}</div>}
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
