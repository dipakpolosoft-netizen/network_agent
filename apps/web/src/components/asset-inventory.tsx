"use client";

import {
  ChevronLeft,
  ChevronRight,
  HardDrive,
  KeyRound,
  LoaderCircle,
  Network,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  X,
} from "lucide-react";
import { type FormEvent, useEffect, useState } from "react";

import { type Asset, type AssetList, type AssetObservation, type WorkerJob, type WorkerJobDetail, type Site, api } from "@/lib/api";
import { AssetTopology } from "@/components/asset-topology";
import { AssetEvidencePanel } from "@/components/asset-evidence";
import { AssetDeviceDepth } from "@/components/asset-device-profile";

const PAGE_SIZE = 50;
const ASSET_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function seenAt(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "Not observed";
}

function assetName(asset: Asset): string {
  return asset.display_name || asset.hostname || asset.last_ip;
}

export function AssetInventory({ sites, canOperate, canAdmin }: { sites: Site[]; canOperate: boolean; canAdmin: boolean }) {
  const [view, setView] = useState<"inventory" | "topology">("inventory");
  const [siteId, setSiteId] = useState("");
  const [query, setQuery] = useState("");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [refreshKey, setRefreshKey] = useState(0);
  const [data, setData] = useState<AssetList | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<Asset | null>(null);
  const [observations, setObservations] = useState<AssetObservation[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

  useEffect(() => {
    function syncSelectedAsset() {
      const id = new URLSearchParams(window.location.search).get("asset");
      setSelectedId(id && ASSET_ID.test(id) ? id : null);
    }
    syncSelectedAsset();
    window.addEventListener("popstate", syncSelectedAsset);
    return () => window.removeEventListener("popstate", syncSelectedAsset);
  }, []);

  function openAsset(assetId: string) {
    const url = new URL(window.location.href);
    url.searchParams.set("asset", assetId);
    window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}#assets`);
    setDetail(null);
    setObservations([]);
    setSelectedId(assetId);
  }

  function closeAsset() {
    const url = new URL(window.location.href);
    url.searchParams.delete("asset");
    window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}#assets`);
    setSelectedId(null);
  }

  useEffect(() => {
    const timer = window.setTimeout(() => { setPage(0); setSearch(query.trim()); }, 250);
    return () => window.clearTimeout(timer);
  }, [query]);

  useEffect(() => {
    if (view !== "inventory") return;
    let current = true;
    setLoading(true);
    api.assets(siteId, search, PAGE_SIZE, page * PAGE_SIZE).then((result) => {
      if (!current) return;
      setData(result);
      setError(null);
    }).catch((cause) => {
      if (current) setError(cause instanceof Error ? cause.message : "Assets could not be loaded");
    }).finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [siteId, search, page, refreshKey, view]);

  useEffect(() => {
    if (!selectedId) return;
    let current = true;
    Promise.all([api.asset(selectedId), api.assetObservations(selectedId)]).then(([asset, history]) => {
      if (!current) return;
      setDetail(asset);
      setObservations(history);
    }).catch((cause) => {
      if (current) {
        setError(cause instanceof Error ? cause.message : "Asset details could not be loaded");
        const url = new URL(window.location.href);
        url.searchParams.delete("asset");
        window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}#assets`);
        setSelectedId(null);
      }
    });
    return () => { current = false; };
  }, [selectedId, refreshKey]);

  async function loadMoreHistory() {
    if (!selectedId) return;
    setLoadingHistory(true);
    try {
      const more = await api.assetObservations(selectedId, observations.length);
      setObservations((current) => [...current, ...more]);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Evidence history could not be loaded");
    } finally {
      setLoadingHistory(false);
    }
  }

  async function save(assetId: string, changes: Parameters<typeof api.updateAsset>[1]) {
    const updated = await api.updateAsset(assetId, changes);
    setDetail(updated);
    setData((current) => current ? { ...current, items: current.items.map((item) => item.asset_id === assetId ? updated : item) } : current);
  }

  return <div className="asset-view">
    <div className="asset-toolbar">
      <div className="asset-toolbar-heading"><div className="asset-view-switch" role="tablist" aria-label="Asset view"><button type="button" role="tab" aria-selected={view === "inventory"} className={view === "inventory" ? "active" : ""} onClick={() => setView("inventory")}><HardDrive size={14} />Inventory</button><button type="button" role="tab" aria-selected={view === "topology"} className={view === "topology" ? "active" : ""} disabled={sites.length === 0} onClick={() => { if (!siteId) setSiteId(sites[0].site_id); setView("topology"); }}><Network size={14} />Topology</button></div><span>{view === "inventory" ? `${data?.total ?? 0} assets` : sites.find((site) => site.site_id === siteId)?.name ?? "Site topology"}</span></div>
      <div className="asset-filters">
        <label className="asset-site-filter"><span>Site</span><select value={siteId} onChange={(event) => { setSiteId(event.target.value); setPage(0); }}><option value="" disabled={view === "topology"}>All sites</option>{sites.map((site) => <option key={site.site_id} value={site.site_id}>{site.name}</option>)}</select></label>
        {view === "inventory" && <><label className="search-box"><Search size={14} /><input aria-label="Search assets" placeholder="Search assets" value={query} onChange={(event) => setQuery(event.target.value)} /></label><button className="icon-button" type="button" title="Refresh assets" aria-label="Refresh assets" onClick={() => { setLoading(true); setRefreshKey((value) => value + 1); }}><RefreshCw size={15} /></button></>}
      </div>
    </div>
    {error && <div className="inline-error asset-error" role="alert">{error}<button className="icon-button small" aria-label="Dismiss error" onClick={() => setError(null)}><X size={13} /></button></div>}
    {view === "inventory" ? <section className="panel" aria-label="Asset inventory">
      <div className="table-scroll"><table className="asset-table"><thead><tr><th>Asset</th><th>Site</th><th>Last IP / MAC</th><th>Type / Vendor</th><th>Last scan</th><th>Last observed</th><th aria-label="Open asset" /></tr></thead><tbody>
        {loading && !data ? <tr><td colSpan={7} className="asset-empty"><LoaderCircle className="spin" size={17} />Loading assets</td></tr> : data?.items.length ? data.items.map((asset) => <tr key={asset.asset_id}><td><div className="device-name"><span className="device-icon"><HardDrive size={15} /></span><div><strong>{assetName(asset)}</strong><small>{asset.owner ?? asset.hostname ?? "Unassigned"}</small></div></div></td><td><strong>{sites.find((site) => site.site_id === asset.site_id)?.name ?? "Site"}</strong><small>{asset.criticality} criticality</small></td><td><strong>{asset.last_ip}</strong><small>{asset.mac ?? "MAC not observed"}</small></td><td><strong>{asset.device_type ?? "Unclassified"}</strong><small>{asset.vendor ?? "Vendor unknown"}</small></td><td><strong>{asset.last_scan_status ?? "Not scanned"}</strong><small>{asset.last_scan_at ? seenAt(asset.last_scan_at) : ""}</small></td><td><strong>{seenAt(asset.last_seen)}</strong><small>{asset.observation_count} observations</small></td><td><button className="icon-button small" type="button" title={`View ${assetName(asset)}`} aria-label={`View ${assetName(asset)}`} onClick={() => openAsset(asset.asset_id)}><ChevronRight size={16} /></button></td></tr>) : <tr><td colSpan={7} className="asset-empty"><HardDrive size={18} /><strong>No assets found</strong><span>{search || siteId ? "Change the search or site filter." : "Assets appear after an approved network discovery."}</span></td></tr>}
      </tbody></table></div>
      <div className="asset-pagination"><span>{data?.total ? `${page * PAGE_SIZE + 1}-${Math.min((page + 1) * PAGE_SIZE, data.total)} of ${data.total}` : "0 assets"}</span><div><button className="icon-button small" aria-label="Previous page" title="Previous page" disabled={page === 0} onClick={() => { setPage((value) => value - 1); setLoading(true); }}><ChevronLeft size={16} /></button><button className="icon-button small" aria-label="Next page" title="Next page" disabled={!data || (page + 1) * PAGE_SIZE >= data.total} onClick={() => { setPage((value) => value + 1); setLoading(true); }}><ChevronRight size={16} /></button></div></div>
    </section> : siteId ? <AssetTopology siteId={siteId} onOpenAsset={openAsset} /> : null}
    {selectedId && <AssetDetailDrawer asset={detail} siteName={sites.find((site) => site.site_id === detail?.site_id)?.name ?? "Site"} observations={observations} loadingHistory={loadingHistory} canOperate={canOperate} canAdmin={canAdmin} onLoadMore={() => void loadMoreHistory()} onClose={closeAsset} onSave={save} />}
  </div>;
}

function AssetDetailDrawer({ asset, siteName, observations, loadingHistory, canOperate, canAdmin, onLoadMore, onClose, onSave }: { asset: Asset | null; siteName: string; observations: AssetObservation[]; loadingHistory: boolean; canOperate: boolean; canAdmin: boolean; onLoadMore: () => void; onClose: () => void; onSave: (assetId: string, changes: Parameters<typeof api.updateAsset>[1]) => Promise<void> }) {
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [displayName, setDisplayName] = useState("");
  const [owner, setOwner] = useState("");
  const [criticality, setCriticality] = useState<Asset["criticality"]>("medium");
  const [tags, setTags] = useState("");

  useEffect(() => {
    if (!asset) return;
    setDisplayName(asset.display_name ?? "");
    setOwner(asset.owner ?? "");
    setCriticality(asset.criticality);
    setTags(asset.tags.join(", "));
  }, [asset]);

  useEffect(() => {
    function closeOnEscape(event: KeyboardEvent) { if (event.key === "Escape") onClose(); }
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!asset) return;
    setSaving(true);
    setFormError(null);
    try {
      await onSave(asset.asset_id, { display_name: displayName.trim() || null, owner: owner.trim() || null, criticality, tags: tags.split(",").map((tag) => tag.trim()).filter(Boolean) });
      setEditing(false);
    } catch (cause) {
      setFormError(cause instanceof Error ? cause.message : "Asset could not be updated");
    } finally { setSaving(false); }
  }

  return <div className="drawer-backdrop" role="presentation"><aside className="drawer asset-drawer" role="dialog" aria-modal="true" aria-label={asset ? `Asset ${assetName(asset)}` : "Asset details"}>
    <div className="modal-header"><div><span className="eyebrow">ASSET INVENTORY</span><h2>{asset ? assetName(asset) : "Loading asset"}</h2></div><button className="icon-button" type="button" title="Close" aria-label="Close asset details" onClick={onClose}><X size={17} /></button></div>
    {!asset ? <div className="asset-loading"><LoaderCircle className="spin" size={18} />Loading evidence</div> : <>
      <div className="detail-summary"><span>{asset.device_type ?? "Unclassified"}</span><span>{asset.criticality} criticality</span><span>{asset.observation_count} observations</span></div>
      <dl><dt>Site</dt><dd>{siteName}</dd><dt>Last IP</dt><dd>{asset.last_ip}</dd><dt>IP history</dt><dd>{asset.ip_history.join(", ")}</dd><dt>MAC</dt><dd>{asset.mac ?? "Not observed"}</dd><dt>Hostname</dt><dd>{asset.hostname ?? "Not reported"}</dd><dt>Vendor</dt><dd>{asset.vendor ?? "Unknown"}</dd><dt>Operating system</dt><dd>{asset.os_name ? `${asset.os_name}${asset.os_accuracy != null ? ` (${asset.os_accuracy}% match)` : ""}` : "Not fingerprinted"}</dd><dt>First observed</dt><dd>{seenAt(asset.first_seen)}</dd><dt>Last observed</dt><dd>{seenAt(asset.last_seen)}</dd><dt>Owner</dt><dd>{asset.owner ?? "Unassigned"}</dd><dt>Tags</dt><dd>{asset.tags.join(", ") || "None"}</dd></dl>
      <AssetDeviceDepth key={`depth-${asset.asset_id}`} assetId={asset.asset_id} />
      {canOperate && <div className="asset-annotation"><div className="asset-section-head"><h3>Ownership</h3><button className="button secondary compact" type="button" onClick={() => setEditing((value) => !value)}>{editing ? "Cancel" : "Edit"}</button></div>{editing && <form onSubmit={(event) => void submit(event)}><label>Display name<input maxLength={128} value={displayName} onChange={(event) => setDisplayName(event.target.value)} /></label><label>Owner<input maxLength={128} value={owner} onChange={(event) => setOwner(event.target.value)} /></label><label>Criticality<select value={criticality} onChange={(event) => setCriticality(event.target.value as Asset["criticality"])}><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></label><label>Tags<input value={tags} onChange={(event) => setTags(event.target.value)} /></label>{formError && <div className="inline-error" role="alert">{formError}</div>}<button className="button primary" disabled={saving}>{saving ? <LoaderCircle className="spin" size={14} /> : null}Save</button></form>}</div>}
      <div className="asset-section-head"><h3>Observed services</h3><span>{asset.open_port_count} open ports in latest scan</span></div>
      {asset.ports.length ? <div className="port-list">{asset.ports.map((port) => <div key={`${port.protocol}-${port.port}`}><code>{port.port}/{port.protocol}</code><span>{[port.service, port.product, port.version].filter(Boolean).join(" ") || "Unknown service"}</span></div>)}</div> : <p className="asset-muted">No open-port evidence stored for this asset.</p>}
      <AssetEvidencePanel key={`evidence-${asset.asset_id}`} assetId={asset.asset_id} />
      <details className="asset-assessment-tools"><summary>Assessment tools</summary>
        <NucleiChecks key={`nuclei-${asset.asset_id}`} asset={asset} canOperate={canOperate} />
        <GreenboneAssessment key={`greenbone-${asset.asset_id}`} asset={asset} canAdmin={canAdmin} />
        <SshInventory key={`ssh-${asset.asset_id}`} asset={asset} canAdmin={canAdmin} />
      </details>
      <div className="asset-section-head"><h3>Evidence history</h3><span>{asset.observation_count} observations</span></div>
      {observations.length ? <div className="asset-timeline">{observations.map((item) => <div key={item.observation_id}><span className="asset-timeline-dot" /><div><strong>{item.source_type === "scan" ? "Host scan" : "Discovery"}</strong><small>{seenAt(item.observed_at)} - {item.ip} - {item.status}</small>{item.source_type === "scan" && <a href={`/network-agent/reports/${item.source_id}`}>View report</a>}</div></div>)}</div> : <p className="asset-muted">No observations recorded.</p>}
      {observations.length < asset.observation_count && <button className="button secondary compact asset-more" type="button" disabled={loadingHistory} onClick={onLoadMore}>{loadingHistory ? "Loading" : "Load more history"}</button>}
    </>}
  </aside></div>;
}

const WEB_PORTS = new Set([80, 443, 8000, 8008, 8080, 8443, 8888, 9443]);

function NucleiChecks({ asset, canOperate }: { asset: Asset; canOperate: boolean }) {
  const webPorts = asset.ports.filter((port) =>
    port.protocol === "tcp" && (port.service?.toLowerCase().includes("http") || WEB_PORTS.has(port.port)));
  const [port, setPort] = useState(webPorts[0]?.port ?? 0);
  const [scheme, setScheme] = useState<"http" | "https">(webPorts[0] && (webPorts[0].service?.includes("https") || [443, 8443, 9443].includes(webPorts[0].port)) ? "https" : "http");
  const [confirmed, setConfirmed] = useState(false);
  const [working, setWorking] = useState(false);
  const [ready, setReady] = useState(false);
  const [jobs, setJobs] = useState<WorkerJob[]>([]);
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);
  const [detail, setDetail] = useState<WorkerJobDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let current = true;
    async function refresh() {
      try {
        const [workers, history] = await Promise.all([api.scannerWorkers(), api.assetWorkerJobs(asset.asset_id)]);
        const checks = history.filter((job) => job.template_profile === "http_baseline");
        const selected = checks.find((job) => job.job_id === selectedJobId) ?? checks[0];
        const newest = selected ? await api.workerJob(selected.job_id) : null;
        if (!current) return;
        setReady(workers.some((worker) => worker.site_id === asset.site_id && worker.status === "online" && worker.available_capabilities.includes("vulnerability_assessment")));
        setJobs(checks);
        setDetail(newest);
        setError(null);
      } catch (cause) {
        if (current) setError(cause instanceof Error ? cause.message : "Web checks could not be loaded");
      }
    }
    void refresh();
    const timer = window.setInterval(() => void refresh(), 5000);
    return () => { current = false; window.clearInterval(timer); };
  }, [asset.asset_id, asset.site_id, selectedJobId]);

  const target = `${scheme}://${asset.last_ip}:${port}`;
  const pending = jobs.some((job) => job.target_port === port && job.target_scheme === scheme && ["queued", "leased"].includes(job.status));

  async function run() {
    setWorking(true);
    setError(null);
    try {
      const job = await api.enqueueNuclei(asset.asset_id, port, scheme);
      setJobs((current) => [job, ...current]);
      setSelectedJobId(job.job_id);
      setDetail(await api.workerJob(job.job_id));
      setConfirmed(false);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Web check could not be queued");
    } finally {
      setWorking(false);
    }
  }

  return <section className="nuclei-checks" aria-label="Web configuration checks">
    <div className="asset-section-head"><h3><ShieldCheck size={15} /> Web checks</h3><span>{jobs.length} recent jobs</span></div>
    {webPorts.length ? <>
      {canOperate && <div className="nuclei-controls">
        <div className="nuclei-target"><label>Observed port<select value={port} onChange={(event) => { const next = webPorts.find((item) => item.port === Number(event.target.value)); setPort(Number(event.target.value)); setScheme(next && (next.service?.includes("https") || [443, 8443, 9443].includes(next.port)) ? "https" : "http"); setConfirmed(false); }}>{webPorts.map((item) => <option key={item.port} value={item.port}>{item.port}/tcp {item.service || "HTTP"}</option>)}</select></label><label>Protocol<select value={scheme} onChange={(event) => { setScheme(event.target.value as "http" | "https"); setConfirmed(false); }}><option value="http">HTTP</option><option value="https">HTTPS</option></select></label></div>
        <code className="nuclei-url">{target}</code>
        <label className="nuclei-confirm"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />I am authorized to check this site's web service.</label>
        <div className="nuclei-action"><button className="button primary compact" type="button" disabled={!ready || !confirmed || working || pending || !asset.last_scan_id} onClick={() => void run()}>{working ? <LoaderCircle size={14} className="spin" /> : <ShieldCheck size={14} />}Run web check</button><span>{!asset.last_scan_id ? "Host scan required" : !ready ? "Central worker offline" : pending ? "Check in progress" : "Baseline HTTP header check"}</span></div>
      </div>}
    </> : <p className="asset-muted">No observed HTTP port in the latest scan sample.</p>}
    {error && <div className="inline-error" role="alert">{error}</div>}
    {jobs.length > 1 && <label className="nuclei-history">Previous checks<select aria-label="Select web check" value={selectedJobId ?? jobs[0].job_id} onChange={(event) => setSelectedJobId(event.target.value)}>{jobs.slice(0, 20).map((job) => <option key={job.job_id} value={job.job_id}>{seenAt(job.created_at)} - {job.target_port}/{job.target_scheme} - {job.status}</option>)}</select></label>}
    {detail && <div className="nuclei-result" aria-live="polite"><div className="nuclei-result-head"><strong>{detail.status === "leased" ? "Running" : detail.status === "completed" ? "Completed" : detail.status === "failed" ? "Failed" : detail.status === "cancelled" ? "Cancelled" : "Queued"}</strong><span>{seenAt(detail.updated_at)}</span></div><small>{detail.target_scheme}://{detail.target_ip}:{detail.target_port}</small>{detail.summary && <p>{detail.summary}</p>}{detail.status === "completed" && (detail.evidence?.engine === "nuclei" && detail.evidence.findings.length ? <div className="nuclei-findings">{detail.evidence.findings.map((finding) => <div key={finding.template_id}><span>{finding.severity}</span><strong>{finding.title}</strong><small>{finding.matched_at}</small></div>)}</div> : <p>No baseline header finding reported.</p>)}</div>}
  </section>;
}

function GreenboneAssessment({ asset, canAdmin }: { asset: Asset; canAdmin: boolean }) {
  const [confirmed, setConfirmed] = useState(false);
  const [working, setWorking] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [ready, setReady] = useState(false);
  const [jobs, setJobs] = useState<WorkerJob[]>([]);
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);
  const [detail, setDetail] = useState<WorkerJobDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let current = true;
    async function refresh() {
      try {
        const [workers, history] = await Promise.all([api.scannerWorkers(), api.assetWorkerJobs(asset.asset_id)]);
        const assessments = history.filter((job) => job.assessment_profile === "greenbone_single_host");
        const selected = assessments.find((job) => job.job_id === selectedJobId) ?? assessments[0];
        const result = selected ? await api.workerJob(selected.job_id) : null;
        if (!current) return;
        setReady(workers.some((worker) => worker.site_id === asset.site_id && worker.status === "online" && worker.available_capabilities.includes("greenbone_assessment")));
        setJobs(assessments);
        setDetail(result);
        setError(null);
      } catch (cause) {
        if (current) setError(cause instanceof Error ? cause.message : "Advanced assessments could not be loaded");
      }
    }
    void refresh();
    const timer = window.setInterval(() => void refresh(), 10000);
    return () => { current = false; window.clearInterval(timer); };
  }, [asset.asset_id, asset.site_id, selectedJobId]);

  async function run() {
    setWorking(true);
    setError(null);
    try {
      const job = await api.enqueueGreenbone(asset.asset_id);
      setJobs((current) => [job, ...current]);
      setSelectedJobId(job.job_id);
      setDetail(await api.workerJob(job.job_id));
      setConfirmed(false);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Advanced assessment could not be queued");
    } finally {
      setWorking(false);
    }
  }

  async function stop(jobId: string) {
    setStopping(true);
    setError(null);
    try {
      const job = await api.cancelWorkerJob(jobId);
      setJobs((current) => current.map((item) => item.job_id === jobId ? job : item));
      setDetail(await api.workerJob(jobId));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Advanced assessment could not be stopped");
    } finally {
      setStopping(false);
    }
  }

  const pending = jobs.some((job) => job.status === "queued" || job.status === "leased");
  const coolingDown = jobs.some((job) => job.status === "cancelled" && Date.now() - new Date(job.updated_at).getTime() < 120000);
  const evidence = detail?.evidence?.engine === "greenbone" ? detail.evidence : null;
  if (!canAdmin && jobs.length === 0) return null;
  return <section className="nuclei-checks greenbone-assessment" aria-label="Advanced assessment">
    <div className="asset-section-head"><h3><ShieldAlert size={15} /> Advanced assessment</h3><span>{jobs.length} recent jobs</span></div>
    {canAdmin && <div className="nuclei-controls">
      <code className="nuclei-url">{asset.last_ip}</code>
      <label className="nuclei-confirm"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />I confirm this host is authorized and the maintenance window is approved.</label>
      <div className="nuclei-action"><button className="button primary compact" type="button" disabled={!ready || !confirmed || working || pending || coolingDown || !asset.last_scan_id} onClick={() => void run()}>{working ? <LoaderCircle size={14} className="spin" /> : <ShieldAlert size={14} />}Run advanced scan</button>{detail && (detail.status === "queued" || detail.status === "leased") && <button className="button secondary compact" type="button" disabled={stopping} onClick={() => void stop(detail.job_id)}>{stopping ? <LoaderCircle size={14} className="spin" /> : null}Stop</button>}<span>{!asset.last_scan_id ? "Host scan required" : !ready ? "Greenbone worker offline" : pending ? "Assessment in progress" : coolingDown ? "Cooling down after stop" : "One host, central Greenbone"}</span></div>
    </div>}
    {error && <div className="inline-error" role="alert">{error}</div>}
    {jobs.length > 1 && <label className="nuclei-history">Previous assessments<select aria-label="Select advanced assessment" value={selectedJobId ?? jobs[0].job_id} onChange={(event) => setSelectedJobId(event.target.value)}>{jobs.slice(0, 20).map((job) => <option key={job.job_id} value={job.job_id}>{seenAt(job.created_at)} - {job.status}</option>)}</select></label>}
    {detail && <div className="nuclei-result" aria-live="polite"><div className="nuclei-result-head"><strong>{detail.status === "leased" ? detail.phase ?? "Running" : detail.status === "completed" ? "Completed" : detail.status === "failed" ? "Failed" : detail.status === "cancelled" ? "Cancelled" : "Queued"}</strong><span>{detail.progress != null ? `${detail.progress}%` : seenAt(detail.updated_at)}</span></div>{detail.progress != null && detail.status === "leased" && <progress className="greenbone-progress" value={detail.progress} max={100} aria-label="Advanced assessment progress" />}<small>{detail.target_ip} - {seenAt(detail.updated_at)}</small>{detail.summary && <p>{detail.summary}</p>}{evidence && <><p>{evidence.findings.length} findings shown{evidence.truncated ? " (more in Greenbone)" : ""}</p>{evidence.findings.length > 0 && <div className="nuclei-findings">{evidence.findings.map((finding) => <div key={finding.result_id}><span>Severity {finding.severity.toFixed(1)}</span><strong>{finding.name}</strong><small>{finding.port}{finding.cves.length ? ` - ${finding.cves.join(", ")}` : ""}</small></div>)}</div>}</>}</div>}
  </section>;
}

function SshInventory({ asset, canAdmin }: { asset: Asset; canAdmin: boolean }) {
  const [confirmed, setConfirmed] = useState(false);
  const [working, setWorking] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [ready, setReady] = useState(false);
  const [jobs, setJobs] = useState<WorkerJob[]>([]);
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);
  const [detail, setDetail] = useState<WorkerJobDetail | null>(null);
  const [packageQuery, setPackageQuery] = useState("");
  const [error, setError] = useState<string | null>(null);
  const hasSsh = asset.ports.some((port) => port.protocol === "tcp" && port.port === 22);

  useEffect(() => {
    let current = true;
    async function refresh() {
      try {
        const [workers, history] = await Promise.all([api.scannerWorkers(), api.assetWorkerJobs(asset.asset_id)]);
        const inventoryJobs = history.filter((job) => job.inventory_profile === "linux_ssh_readonly");
        const selected = inventoryJobs.find((job) => job.job_id === selectedJobId) ?? inventoryJobs[0];
        const latest = selected ? await api.workerJob(selected.job_id) : null;
        if (!current) return;
        setReady(workers.some((worker) => worker.site_id === asset.site_id && worker.status === "online" && worker.available_capabilities.includes("credentialed_inventory")));
        setJobs(inventoryJobs);
        setDetail(latest);
        setError(null);
      } catch (cause) {
        if (current) setError(cause instanceof Error ? cause.message : "SSH inventory could not be loaded");
      }
    }
    void refresh();
    const timer = window.setInterval(() => void refresh(), 10000);
    return () => { current = false; window.clearInterval(timer); };
  }, [asset.asset_id, asset.site_id, selectedJobId]);

  async function run() {
    setWorking(true);
    setError(null);
    try {
      const job = await api.enqueueInventory(asset.asset_id);
      setJobs((current) => [job, ...current]);
      setSelectedJobId(job.job_id);
      setDetail(await api.workerJob(job.job_id));
      setConfirmed(false);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "SSH inventory could not be queued");
    } finally { setWorking(false); }
  }

  async function stop(jobId: string) {
    setStopping(true);
    setError(null);
    try {
      const job = await api.cancelWorkerJob(jobId);
      setJobs((current) => current.map((item) => item.job_id === jobId ? job : item));
      setDetail(await api.workerJob(jobId));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "SSH inventory could not be stopped");
    } finally { setStopping(false); }
  }

  const pending = jobs.some((job) => job.status === "queued" || job.status === "leased");
  const evidence = detail?.evidence?.engine === "ssh_inventory" ? detail.evidence : null;
  const filteredPackages = evidence?.packages.filter((item) => `${item.name} ${item.version}`.toLowerCase().includes(packageQuery.toLowerCase())) ?? [];
  if ((!canAdmin && jobs.length === 0) || (!hasSsh && jobs.length === 0)) return null;

  return <section className="nuclei-checks ssh-inventory" aria-label="Credentialed inventory">
    <div className="asset-section-head"><h3><KeyRound size={15} /> Credentialed inventory</h3><span>{jobs.length} recent jobs</span></div>
    {canAdmin && hasSsh && <div className="nuclei-controls">
      <code className="nuclei-url">SSH  {asset.last_ip}:22</code>
      <label className="nuclei-confirm"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />I authorize read-only SSH access to this host.</label>
      <div className="nuclei-action"><button className="button primary compact" type="button" disabled={!ready || !confirmed || working || pending || !asset.last_scan_id} onClick={() => void run()}>{working ? <LoaderCircle size={14} className="spin" /> : <KeyRound size={14} />}Collect inventory</button>{detail && (detail.status === "queued" || detail.status === "leased") && <button className="button secondary compact" type="button" disabled={stopping} onClick={() => void stop(detail.job_id)}>{stopping ? <LoaderCircle size={14} className="spin" /> : null}Stop</button>}<span>{!asset.last_scan_id ? "Host scan required" : !ready ? "SSH worker offline" : pending ? "Inventory in progress" : "Linux host"}</span></div>
    </div>}
    {error && <div className="inline-error" role="alert">{error}</div>}
    {jobs.length > 1 && <label className="nuclei-history">Previous inventories<select aria-label="Select SSH inventory" value={selectedJobId ?? jobs[0].job_id} onChange={(event) => { setSelectedJobId(event.target.value); setPackageQuery(""); }}>{jobs.slice(0, 20).map((job) => <option key={job.job_id} value={job.job_id}>{seenAt(job.created_at)} - {job.status}</option>)}</select></label>}
    {detail && <div className="nuclei-result" aria-live="polite">
      <div className="nuclei-result-head"><strong>{detail.status === "leased" ? detail.phase ?? "Collecting" : detail.status === "completed" ? "Completed" : detail.status === "failed" ? "Failed" : detail.status === "cancelled" ? "Cancelled" : "Queued"}</strong><span>{detail.progress != null ? `${detail.progress}%` : seenAt(detail.updated_at)}</span></div>
      {detail.progress != null && detail.status === "leased" && <progress className="greenbone-progress" value={detail.progress} max={100} aria-label="SSH inventory progress" />}
      <small>{detail.target_ip} - {seenAt(detail.updated_at)}</small>{detail.summary && <p>{detail.summary}</p>}
      {evidence && <><dl className="inventory-facts"><dt>Hostname</dt><dd>{evidence.hostname}</dd><dt>Operating system</dt><dd>{evidence.os_name}</dd><dt>Kernel</dt><dd>{evidence.kernel} ({evidence.architecture})</dd><dt>Packages</dt><dd>{evidence.packages.length}{evidence.packages_truncated ? "+" : ""} via {evidence.package_manager}</dd></dl>
        {evidence.packages.length > 0 && <details className="inventory-packages"><summary>Installed packages</summary><label className="search-box"><Search size={14} /><input aria-label="Search installed packages" placeholder="Search packages" value={packageQuery} onChange={(event) => setPackageQuery(event.target.value)} /></label><div className="inventory-package-list">{filteredPackages.length ? filteredPackages.map((item) => <div key={item.name}><strong>{item.name}</strong><code>{item.version}</code></div>) : <p className="asset-muted">No matching packages</p>}</div>{evidence.packages_truncated && <small>Showing the first 200 packages.</small>}</details>}
      </>}
    </div>}
  </section>;
}
