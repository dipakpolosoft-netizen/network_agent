"use client";

import { ExternalLink, LoaderCircle, RefreshCw, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";

import { type AssetEvidence, api } from "@/lib/api";

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

export function AssetEvidencePanel({ assetId }: { assetId: string }) {
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

  return <section className="asset-evidence" aria-label="Unified asset evidence">
    <div className="asset-section-head"><h3>Evidence &amp; vulnerability triage</h3><button className="icon-button small" type="button" title="Refresh evidence" aria-label="Refresh evidence" onClick={() => setRefresh((value) => value + 1)}><RefreshCw size={14} /></button></div>
    <div className="asset-evidence-summary"><strong>{currentCount} latest-source signals</strong><span>{historicalCount} historical</span><span>{data?.runs.length ?? 0} worker runs</span></div>
    <div className="asset-evidence-filters"><label>Source<select aria-label="Evidence source" value={source} onChange={(event) => setSource(event.target.value)}><option value="all">All sources</option><option value="host_scan">Host scan</option><option value="nvd">NVD matches</option><option value="nuclei">Web checks</option><option value="greenbone">Greenbone</option></select></label><label className="asset-evidence-history"><input type="checkbox" checked={history} onChange={(event) => setHistory(event.target.checked)} />Show historical</label></div>
    {loading && !data ? <p className="asset-muted"><LoaderCircle className="spin" size={14} /> Loading evidence</p> : null}
    {error && <p className="inline-error" role="alert">{error}</p>}
    {pending.length > 0 && <p className="asset-evidence-notice">{pending.length} assessment {pending.length === 1 ? "is" : "are"} queued or running. Results are not yet evidence.</p>}
    {failed.length > 0 && <p className="asset-evidence-notice">{failed.length} worker {failed.length === 1 ? "run failed" : "runs failed"}; a failed run does not mean the host is clear.</p>}
    {data?.latest_inventory && <div className="asset-evidence-inventory"><strong>Credentialed inventory</strong><span>{data.latest_inventory.os_name}{data.latest_inventory.os_version ? ` ${data.latest_inventory.os_version}` : ""} - {data.latest_inventory.hostname}</span><small>{data.latest_inventory.package_count}{data.latest_inventory.packages_truncated ? "+" : ""} packages recorded - {when(data.latest_inventory.observed_at)}{data.latest_inventory.current ? "" : " - Historical"}</small></div>}
    {visible.length ? <div className="asset-evidence-list">{visible.slice(0, shown).map((item, index) => <article key={`${item.source}-${item.source_id}-${item.reference ?? item.title}-${index}`} className="asset-evidence-item"><div className="asset-evidence-item-head"><span className={`asset-evidence-severity ${item.severity}`}>{item.severity}</span><strong>{item.title}</strong></div><small>{SOURCE_LABELS[item.source]} - {CLASS_LABELS[item.classification]} - {when(item.observed_at)}{item.current ? "" : " - Historical"} - <span title={item.source_id}>{item.source === "host_scan" || item.source === "nvd" ? "Scan" : "Job"} {item.source_id.slice(0, 8)}</span></small><p>{item.detail}</p><div className="asset-evidence-reference"><span>{[item.target, item.reference].filter(Boolean).join(" - ")}</span>{item.scan_id && <a href={`/network-agent/reports/${item.scan_id}`} title="Open source scan report">{item.source === "host_scan" || item.source === "nvd" ? "Scan report" : "Source scan"} <ExternalLink size={11} /></a>}</div></article>)}</div> : data && <div className="asset-evidence-empty"><ShieldCheck size={16} /><span>{data.items.length ? "No evidence matches these filters." : "No saved findings yet. Discovery alone does not assess vulnerabilities."}</span></div>}
    {visible.length > shown && <button className="button secondary compact asset-more" type="button" onClick={() => setShown((value) => value + 30)}>Show more ({visible.length - shown})</button>}
    {data?.truncated && <p className="asset-evidence-notice">This view is bounded. Open source reports and worker histories for older or additional results.</p>}
    <p className="asset-evidence-disclaimer">Latest-source means linked to the latest saved scan/IP, not live host status. NVD matches are potential, not confirmed; scanner findings require validation. No result here proves exploitation.</p>
  </section>;
}
