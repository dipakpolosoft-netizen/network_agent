"use client";

import { Check, Clipboard, LoaderCircle, Plus, Server, ShieldX, X } from "lucide-react";
import { type FormEvent, useEffect, useState } from "react";

import { api, type ProvisionedScannerWorker, type ScannerWorker, type Site } from "@/lib/api";

const CAPABILITIES = [
  { value: "vulnerability_assessment", label: "Web checks (Nuclei)" },
  { value: "greenbone_assessment", label: "Advanced assessment (Greenbone)" },
  { value: "credentialed_inventory", label: "Linux SSH inventory" },
] as const;

function capabilityLabel(value: string): string {
  return CAPABILITIES.find((item) => item.value === value)?.label ?? value.replaceAll("_", " ");
}

export function WorkerManagement({ sites, defaultSiteId, onClose }: { sites: Site[]; defaultSiteId: string; onClose: () => void }) {
  const [workers, setWorkers] = useState<ScannerWorker[]>([]);
  const [siteId, setSiteId] = useState(defaultSiteId || sites[0]?.site_id || "");
  const [label, setLabel] = useState("");
  const [capability, setCapability] = useState<string>(CAPABILITIES[0].value);
  const [provisioned, setProvisioned] = useState<ProvisionedScannerWorker | null>(null);
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let current = true;
    async function refresh() {
      try {
        const list = await api.scannerWorkers();
        if (current) { setWorkers(list); setError(null); }
      } catch (cause) {
        if (current) setError(cause instanceof Error ? cause.message : "Workers could not be loaded");
      }
    }
    void refresh();
    const timer = window.setInterval(() => void refresh(), 10000);
    return () => { current = false; window.clearInterval(timer); };
  }, []);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!siteId || !label.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const worker = await api.provisionScannerWorker(siteId, label.trim(), capability);
      setProvisioned(worker);
      setWorkers((current) => [worker, ...current]);
      setLabel("");
      setCopied(false);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Worker could not be provisioned");
    } finally { setBusy(false); }
  }

  async function revoke(worker: ScannerWorker) {
    if (!window.confirm(`Revoke ${worker.label}? Active jobs will lose this worker lease.`)) return;
    setBusy(true);
    setError(null);
    try {
      const updated = await api.revokeScannerWorker(worker.worker_id);
      setWorkers((current) => current.map((item) => item.worker_id === updated.worker_id ? updated : item));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Worker could not be revoked");
    } finally { setBusy(false); }
  }

  function close() {
    if (provisioned && !window.confirm("This credential is shown only once. Close worker setup?")) return;
    onClose();
  }

  return <div className="modal-backdrop" role="presentation"><section className="modal worker-modal" role="dialog" aria-modal="true" aria-labelledby="workers-title">
    <div className="modal-header"><div><span className="eyebrow">CENTRAL WORKERS</span><h2 id="workers-title">Scanner workers</h2></div><button className="icon-button" type="button" title="Close" aria-label="Close worker management" onClick={close}><X size={17} /></button></div>
    {provisioned ? <div className="worker-credential" role="status">
      <strong>{provisioned.label} provisioned</strong><small>Credential is shown once. Store it on the central worker host.</small>
      <span>Worker ID</span><code>{provisioned.worker_id}</code>
      <span>Worker credential</span><div className="copy-field"><code>{provisioned.credential}</code><button type="button" title="Copy worker credential" aria-label="Copy worker credential" onClick={() => void navigator.clipboard.writeText(provisioned.credential).then(() => setCopied(true)).catch(() => setError("Clipboard unavailable; select the credential to copy it."))}>{copied ? <Check size={15} /> : <Clipboard size={15} />}</button></div>
      <button className="button secondary compact" type="button" onClick={() => { setProvisioned(null); setCopied(false); }}>Done</button>
    </div> : <form className="worker-form" onSubmit={(event) => void submit(event)}>
      <label>Site<select value={siteId} required onChange={(event) => setSiteId(event.target.value)}>{sites.map((site) => <option key={site.site_id} value={site.site_id}>{site.name}</option>)}</select></label>
      <label>Worker label<input required maxLength={128} value={label} onChange={(event) => setLabel(event.target.value)} placeholder="Central scanner" /></label>
      <label>Capability<select value={capability} onChange={(event) => setCapability(event.target.value)}>{CAPABILITIES.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}</select></label>
      <button className="button primary" type="submit" disabled={busy || !siteId || !label.trim()}>{busy ? <LoaderCircle className="spin" size={14} /> : <Plus size={14} />}Provision worker</button>
    </form>}
    {error && <div className="inline-error" role="alert">{error}</div>}
    <div className="worker-list-head"><strong>Provisioned workers</strong><span>{workers.filter((item) => !item.revoked_at).length} active identities</span></div>
    <div className="worker-list">{workers.length ? workers.map((worker) => <div className="worker-row" key={worker.worker_id}>
      <Server size={16} /><div><strong>{worker.label}</strong><small>{sites.find((site) => site.site_id === worker.site_id)?.name ?? "Site"} / {worker.capabilities.map(capabilityLabel).join(", ")}</small><small>{worker.last_heartbeat_at ? `Last heartbeat ${new Date(worker.last_heartbeat_at).toLocaleString()}` : "No heartbeat yet"}</small><small>{worker.available_capabilities.length ? `Engine ready: ${worker.available_capabilities.map(capabilityLabel).join(", ")}` : "No engine capability reported"}</small></div>
      <span className={`quiet-badge ${worker.status === "online" && worker.available_capabilities.length ? "" : "danger"}`}>{worker.status === "online" ? worker.available_capabilities.length ? "Ready" : "No engine" : worker.status}</span>
      {!worker.revoked_at && <button className="icon-button small" type="button" title={`Revoke ${worker.label}`} aria-label={`Revoke ${worker.label}`} disabled={busy} onClick={() => void revoke(worker)}><ShieldX size={14} /></button>}
    </div>) : <p className="asset-muted">No scanner workers provisioned.</p>}</div>
  </section></div>;
}
