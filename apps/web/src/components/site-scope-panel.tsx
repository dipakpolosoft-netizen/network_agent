"use client";

import { Plus, ShieldCheck, Trash2 } from "lucide-react";
import { type FormEvent, useEffect, useState } from "react";

import { type Agent, type ApprovedScope, type ScanProfile, type Site } from "@/lib/api";

const PROFILES: ScanProfile[] = ["inventory", "network_services", "standard", "full_tcp"];

type Props = {
  sites: Site[];
  siteId: string;
  scopes: ApprovedScope[];
  probe?: Agent;
  busy: boolean;
  editable: boolean;
  onSelectSite: (siteId: string) => void;
  onCreateSite: (name: string, owner: string, description: string) => Promise<boolean>;
  onApprove: (scope: { cidr: string; label: string; description: string; exclusions: string[]; scan_profiles: ScanProfile[] }) => Promise<boolean>;
  onRemove: (scopeId: string) => Promise<void>;
};

export function SiteScopePanel({ sites, siteId, scopes, probe, busy, editable, onSelectSite, onCreateSite, onApprove, onRemove }: Props) {
  const [siteFormOpen, setSiteFormOpen] = useState(false);
  const [name, setName] = useState("");
  const [owner, setOwner] = useState("");
  const [siteDescription, setSiteDescription] = useState("");
  const [cidr, setCidr] = useState("");
  const [label, setLabel] = useState("");
  const [description, setDescription] = useState("");
  const [exclusions, setExclusions] = useState("");
  const [profiles, setProfiles] = useState<ScanProfile[]>(PROFILES);

  useEffect(() => {
    if (!cidr && probe?.site_id === siteId && probe.discovery_recommended_scope) setCidr(probe.discovery_recommended_scope);
  }, [cidr, probe?.site_id, probe?.discovery_recommended_scope, siteId]);

  async function createSite(event: FormEvent) {
    event.preventDefault();
    if (!await onCreateSite(name, owner, siteDescription)) return;
    setName("");
    setOwner("");
    setSiteDescription("");
    setSiteFormOpen(false);
  }

  async function approve(event: FormEvent) {
    event.preventDefault();
    if (!await onApprove({
      cidr: cidr.trim(), label: label.trim(), description: description.trim(),
      exclusions: exclusions.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean),
      scan_profiles: profiles,
    })) return;
    setLabel("");
    setDescription("");
    setExclusions("");
  }

  return <section className="site-scope-panel" aria-label="Site and approved networks">
    <div className="site-scope-heading">
      <div><span className="eyebrow">SITE POLICY</span><h2>Sites and approved networks</h2></div>
      {editable && <button className="button secondary" type="button" onClick={() => setSiteFormOpen((current) => !current)}><Plus size={15} />Site</button>}
    </div>
    {editable && siteFormOpen && <form className="site-form" onSubmit={(event) => void createSite(event)}>
      <label>Site name<input required maxLength={128} value={name} onChange={(event) => setName(event.target.value)} placeholder="Head Office" /></label>
      <label>Owner<input maxLength={128} value={owner} onChange={(event) => setOwner(event.target.value)} placeholder="Network team" /></label>
      <label>Description<input maxLength={512} value={siteDescription} onChange={(event) => setSiteDescription(event.target.value)} placeholder="Main office network" /></label>
      <button className="button primary" disabled={busy || !name.trim()} type="submit">Create site</button>
    </form>}
    {sites.length ? <>
      <div className="site-policy-context">
        <label>Site<select value={siteId} onChange={(event) => onSelectSite(event.target.value)}>{sites.map((site) => <option key={site.site_id} value={site.site_id}>{site.name}</option>)}</select></label>
        <span>{probe?.site_id === siteId ? `Active probe: ${probe.label}` : probe ? `Managing site policy; active probe belongs to ${probe.site_name ?? "another site"}` : "Enroll a probe for this site"}</span>
        <strong>{scopes.length} approved {scopes.length === 1 ? "network" : "networks"}</strong>
      </div>
      <div className="approved-scope-list">
        {scopes.length === 0 && <p>No networks approved for this site. Add the exact CIDR before discovery.</p>}
        {scopes.map((scope) => <div className="approved-scope" key={scope.scope_id}>
          <ShieldCheck size={16} />
          <div><strong>{scope.label} <code>{scope.cidr}</code></strong><small>{scope.description ? `${scope.description} | ` : ""}{scope.scan_profiles.join(", ")}{scope.exclusions.length ? ` | Excludes ${scope.exclusions.join(", ")}` : ""}</small></div>
          {editable && <button className="icon-button small" type="button" title={`Remove approval for ${scope.cidr}`} aria-label={`Remove approval for ${scope.cidr}`} disabled={busy} onClick={() => { if (window.confirm(`Remove approval for ${scope.cidr}? Queued scans for this network will be cancelled.`)) void onRemove(scope.scope_id); }}><Trash2 size={15} /></button>}
        </div>)}
      </div>
      {editable && <form className="scope-approval-form" onSubmit={(event) => void approve(event)}>
        <label>Network CIDR<input required value={cidr} onChange={(event) => setCidr(event.target.value)} placeholder="192.168.10.0/24" /></label>
        <label>Label<input required maxLength={128} value={label} onChange={(event) => setLabel(event.target.value)} placeholder="Employee LAN" /></label>
        <label>Description<input maxLength={512} value={description} onChange={(event) => setDescription(event.target.value)} placeholder="Optional" /></label>
        <label>Exclusions<input value={exclusions} onChange={(event) => setExclusions(event.target.value)} placeholder="192.168.10.1/32" /></label>
        <div className="scope-profile-options" role="group" aria-label="Allowed scan profiles">{PROFILES.map((profile) => <label key={profile}><input type="checkbox" checked={profiles.includes(profile)} onChange={() => setProfiles((current) => current.includes(profile) ? current.filter((item) => item !== profile) : [...current, profile])} />{profile.replaceAll("_", " ")}</label>)}</div>
        <button className="button primary" type="submit" disabled={busy || !cidr.trim() || !label.trim() || profiles.length === 0}><Plus size={15} />Approve network</button>
      </form>}
    </> : <p className="site-empty">Create a site to manage its approved networks.</p>}
  </section>;
}
