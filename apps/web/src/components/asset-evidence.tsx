"use client";

import { ExternalLink, FileSearch, LoaderCircle, RefreshCw } from "lucide-react";
import { useEffect, useState } from "react";

import { type AssetEvidence, api } from "@/lib/api";

type EvidenceItem = AssetEvidence["items"][number];

const REVIEW_LABELS: Record<EvidenceItem["review_status"], string> = {
  unreviewed: "Not reviewed",
  investigating: "Investigating",
  confirmed: "Confirmed by reviewer",
  false_positive: "False positive",
  accepted_risk: "Risk accepted",
};

const SOURCE_LABELS = {
  host_scan: "Host scan",
  nvd: "NVD match",
  nuclei: "Web check",
  greenbone: "Greenbone",
  ssh_inventory: "SSH inventory",
};

const CLASS_LABELS = {
  exposure_signal: "Exposure signal",
  potential_cve: "Potential CVE",
  configuration_observation: "Configuration observation",
  scanner_finding: "Scanner finding",
};

function when(value: string) {
  return new Date(value).toLocaleString();
}

function ReviewControl({ assetId, item, canOperate, onSaved }: { assetId: string; item: EvidenceItem; canOperate: boolean; onSaved: (item: EvidenceItem) => void }) {
  const [status, setStatus] = useState(item.review_status);
  const [note, setNote] = useState(item.review_note ?? "");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setStatus(item.review_status);
    setNote(item.review_note ?? "");
  }, [item.review_status, item.review_note]);

  async function save() {
    if ((status === "false_positive" || status === "accepted_risk") && !note.trim()) {
      setError("Add a reason for this decision.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      onSaved(await api.reviewAssetEvidence(assetId, item.review_id, status, note));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Review could not be saved");
    } finally {
      setSaving(false);
    }
  }

  return <details className="asset-evidence-review" key={item.review_id}>
    <summary>Review: {REVIEW_LABELS[item.review_status]}{item.reviewed_at ? ` - ${when(item.reviewed_at)}` : ""}</summary>
    {canOperate ? <div className="asset-evidence-review-form">
      <label>Disposition<select aria-label={`Review ${item.title}`} value={status} onChange={(event) => setStatus(event.target.value as EvidenceItem["review_status"])}>{Object.entries(REVIEW_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
      <label>Review note<textarea aria-label={`Review note for ${item.title}`} maxLength={1000} rows={2} value={note} onChange={(event) => setNote(event.target.value)} /></label>
      <button className="button secondary compact" type="button" disabled={saving || (status === item.review_status && note === (item.review_note ?? ""))} onClick={() => void save()}>{saving ? <LoaderCircle size={13} className="spin" /> : null}Save review</button>
      {error && <span className="inline-error" role="alert">{error}</span>}
    </div> : <p>{item.review_note || "No review note recorded."}</p>}
  </details>;
}

export function AssetEvidencePanel({ assetId, canOperate }: { assetId: string; canOperate: boolean }) {
  const [data, setData] = useState<AssetEvidence | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [source, setSource] = useState("all");
  const [history, setHistory] = useState(false);
  const [shown, setShown] = useState(30);
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const result = await api.assetEvidence(assetId);
        if (active) { setData(result); setError(null); setLoading(false); }
      } catch (cause) {
        if (active) { setError(cause instanceof Error ? cause.message : "Evidence could not be loaded"); setLoading(false); }
      }
    }
    void load();
    const timer = window.setInterval(() => void load(), 15000);
    return () => { active = false; window.clearInterval(timer); };
  }, [assetId, refresh]);

  const visible = data?.items.filter((item) => (history || item.current) && (source === "all" || item.source === source)) ?? [];
  const currentCount = data?.items.filter((item) => item.current).length ?? 0;
  const historicalCount = (data?.items.length ?? 0) - currentCount;
  const pending = data?.runs.filter((run) => run.status === "queued" || run.status === "leased") ?? [];
  const failed = data?.runs.filter((run) => run.status === "failed") ?? [];

  function onSaved(updated: EvidenceItem) {
    setData((current) => current && ({ ...current, items: current.items.map((item) => item.review_id === updated.review_id ? updated : item) }));
  }

  return <section className="asset-evidence" aria-label="Unified asset evidence">
    <div className="asset-section-head"><h3>Evidence &amp; vulnerability triage</h3><button className="icon-button small" type="button" title="Refresh evidence" aria-label="Refresh evidence" onClick={() => setRefresh((value) => value + 1)}><RefreshCw size={14} /></button></div>
    <div className="asset-evidence-summary"><strong>{currentCount} latest-source signals</strong><span>{historicalCount} historical</span><span>{data?.runs.length ?? 0} worker runs</span></div>
    <div className="asset-evidence-filters"><label>Source<select aria-label="Evidence source" value={source} onChange={(event) => setSource(event.target.value)}><option value="all">All sources</option><option value="host_scan">Host scan</option><option value="nvd">NVD matches</option><option value="nuclei">Web checks</option><option value="greenbone">Greenbone</option></select></label><label className="asset-evidence-history"><input type="checkbox" checked={history} onChange={(event) => setHistory(event.target.checked)} />Show historical</label></div>
    {loading && !data ? <p className="asset-muted"><LoaderCircle className="spin" size={14} /> Loading evidence</p> : null}
    {error && <p className="inline-error" role="alert">{error}</p>}
    {pending.length > 0 && <p className="asset-evidence-notice">{pending.length} assessment {pending.length === 1 ? "is" : "are"} queued or running. Results are not yet evidence.</p>}
    {failed.length > 0 && <p className="asset-evidence-notice">{failed.length} worker {failed.length === 1 ? "run failed" : "runs failed"}; a failed run does not mean the host is clear.</p>}
    {data?.runs.length ? <details className="asset-evidence-runs"><summary>Worker run status ({data.runs.length})</summary><div>{data.runs.map((run) => <p key={run.job_id}><strong>{SOURCE_LABELS[run.source]} - {run.status}</strong><span>{when(run.completed_at ?? run.created_at)}{run.current ? " - Linked to latest scan" : " - Historical"}</span>{run.summary && <small>{run.summary}</small>}</p>)}</div></details> : null}
    {data?.latest_inventory && <div className="asset-evidence-inventory"><strong>Credentialed inventory</strong><span>{data.latest_inventory.os_name}{data.latest_inventory.os_version ? ` ${data.latest_inventory.os_version}` : ""} - {data.latest_inventory.hostname}</span><small>{data.latest_inventory.package_count}{data.latest_inventory.packages_truncated ? "+" : ""} packages recorded - {when(data.latest_inventory.observed_at)}{data.latest_inventory.current ? "" : " - Historical"}</small></div>}
    {visible.length ? <div className="asset-evidence-list">{visible.slice(0, shown).map((item) => <article key={item.review_id} className="asset-evidence-item"><div className="asset-evidence-item-head"><span className={`asset-evidence-severity ${item.severity}`}>{item.severity}</span><strong>{item.title}</strong></div><small>{SOURCE_LABELS[item.source]} - {CLASS_LABELS[item.classification]} - {when(item.observed_at)}{item.current ? "" : " - Historical"} - <span title={item.source_id}>{item.source === "host_scan" || item.source === "nvd" ? "Scan" : "Job"} {item.source_id.slice(0, 8)}</span></small><p>{item.detail}</p><div className="asset-evidence-reference"><span>{[item.target, item.reference].filter(Boolean).join(" - ")}</span>{item.scan_id && <a href={`/network-agent/reports/${item.scan_id}`} title="Open source scan report">{item.source === "host_scan" || item.source === "nvd" ? "Scan report" : "Source scan"} <ExternalLink size={11} /></a>}</div><ReviewControl assetId={assetId} item={item} canOperate={canOperate} onSaved={onSaved} /></article>)}</div> : data && <div className="asset-evidence-empty"><FileSearch size={16} /><span>{data.items.length ? !history && currentCount === 0 ? "No latest-scan evidence. Historical records remain available." : "No evidence matches these filters." : "No saved findings yet. Discovery alone does not assess vulnerabilities."}</span></div>}
    {visible.length > shown && <button className="button secondary compact asset-more" type="button" onClick={() => setShown((value) => value + 30)}>Show more ({visible.length - shown})</button>}
    {data?.truncated && <p className="asset-evidence-notice">This view is bounded. Open source reports and worker histories for older or additional results.</p>}
    <p className="asset-evidence-disclaimer">Latest-source means linked to the latest saved scan/IP, not live host status. NVD matches are potential, not confirmed; scanner findings require validation. No result here proves exploitation.</p>
  </section>;
}
