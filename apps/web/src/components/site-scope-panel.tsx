"use client";

import { Plus, ShieldAlert, ShieldCheck, Trash2 } from "lucide-react";
import { type FormEvent, useMemo, useState } from "react";

import { type Agent, type ApprovedScope, type ScanProfile, type ScopeApproval, type Site } from "@/lib/api";

const PROFILE_PRESETS: { label: string; profiles: ScanProfile[] }[] = [
  { label: "Inventory only", profiles: ["inventory"] },
  { label: "Inventory + Standard", profiles: ["inventory", "standard"] },
  { label: "Inventory + Network services", profiles: ["inventory", "network_services"] },
  { label: "Inventory + Standard + Network services", profiles: ["inventory", "standard", "network_services"] },
  { label: "All profiles (includes Full TCP)", profiles: ["inventory", "network_services", "standard", "full_tcp"] },
];

type Props = {
  sites: Site[];
  siteId: string;
  scopes: ApprovedScope[];
  probe?: Agent;
  busy: boolean;
  editable: boolean;
  onSelectSite: (siteId: string) => void;
  onCreateSite: (name: string, owner: string, description: string) => Promise<boolean>;
  onApprove: (scope: ScopeApproval) => Promise<boolean>;
  onRemove: (scopeId: string) => Promise<void>;
};

export function SiteScopePanel({ sites, siteId, scopes, probe, busy, editable, onSelectSite, onCreateSite, onApprove, onRemove }: Props) {
  const [siteFormOpen, setSiteFormOpen] = useState(false);
  const [name, setName] = useState("");
  const [owner, setOwner] = useState("");
  const [siteDescription, setSiteDescription] = useState("");
  const [cidr, setCidr] = useState("");
  const [description, setDescription] = useState("");
  const [exclusions, setExclusions] = useState("");
  const [profilePreset, setProfilePreset] = useState(0);
  const [approvalOwner, setApprovalOwner] = useState<string | null>(null);
  const [approvalReference, setApprovalReference] = useState("");
  const [approvedBy, setApprovedBy] = useState("");
  const [expiresOn, setExpiresOn] = useState("");
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [publicRangeAuthorized, setPublicRangeAuthorized] = useState(false);
  const [addNetworkOpen, setAddNetworkOpen] = useState(false);
  const scopeOptions = useMemo(() => {
    if (probe?.site_id !== siteId) return [];
    const reported = probe.discovery_scope_options ?? [];
    const choices = probe.discovery_recommended_scope
      ? [probe.discovery_recommended_scope, ...reported]
      : reported;
    return [...new Set(choices)].filter((scope) => scope.endsWith("/24") && !scopes.some((approved) => approved.cidr === scope && approved.approval_status === "active"));
  }, [probe, scopes, siteId]);
  const selectedCidr = scopeOptions.includes(cidr) ? cidr : scopeOptions[0] ?? "";
  const currentSite = sites.find((site) => site.site_id === siteId);
  const existingScope = scopes.find((scope) => scope.cidr === selectedCidr);
  const ownerValue = approvalOwner ?? currentSite?.owner ?? "";
  const publicRange = Boolean(probe?.discovery_requires_authorization);
  const activeCount = scopes.filter((scope) => scope.approval_status === "active").length;

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
    if (!selectedCidr || !authorizationConfirmed || (publicRange && !publicRangeAuthorized)) return;
    if (!await onApprove({
      cidr: selectedCidr,
      label: existingScope?.label ?? `${(currentSite?.name ?? "Site").slice(0, 124)} LAN`,
      description: description.trim(),
      exclusions: exclusions.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean),
      scan_profiles: PROFILE_PRESETS[profilePreset].profiles,
      owner: ownerValue.trim(),
      approval_reference: approvalReference.trim(),
      approved_by: approvedBy.trim(),
      expires_on: expiresOn,
      authorization_confirmed: true,
      public_range_authorized: publicRange && publicRangeAuthorized,
    })) return;
    setDescription("");
    setExclusions("");
    setProfilePreset(0);
    setAuthorizationConfirmed(false);
    setPublicRangeAuthorized(false);
    setAddNetworkOpen(false);
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
        <label>Site<select aria-label="Site" value={siteId} onChange={(event) => onSelectSite(event.target.value)}>{sites.map((site) => <option key={site.site_id} value={site.site_id}>{site.name}</option>)}</select></label>
        <span>{probe?.site_id === siteId ? `Active probe: ${probe.label}` : probe ? `Managing site policy; active probe belongs to ${probe.site_name ?? "another site"}` : "Enroll a probe for this site"}</span>
        <strong>{activeCount} active {activeCount === 1 ? "network" : "networks"}</strong>
      </div>
      {scopes.length > 0 && <div className="approved-scope-list">
        {scopes.map((scope) => <div className="approved-scope" key={scope.scope_id}>
          {scope.approval_status === "active" ? <ShieldCheck size={16} /> : <ShieldAlert size={16} />}
          <div><strong>{scope.label} <code>{scope.cidr}</code> <span className={`scope-status ${scope.approval_status}`}>{scope.approval_status === "active" ? "Active" : scope.approval_status === "expired" ? "Expired" : "Needs review"}</span></strong><small>{scope.approval_reference ? `Ref ${scope.approval_reference} | ` : ""}{scope.owner ? `Owner ${scope.owner} | ` : ""}{scope.expires_on ? `Through ${scope.expires_on} UTC | ` : ""}{scope.scan_profiles.map((profile) => profile.replaceAll("_", " ")).join(", ")}{scope.exclusions.length ? ` | Excludes ${scope.exclusions.join(", ")}` : ""}</small></div>
          {editable && <button className="icon-button small" type="button" title={`Remove approval for ${scope.cidr}`} aria-label={`Remove approval for ${scope.cidr}`} disabled={busy} onClick={() => { if (window.confirm(`Remove approval for ${scope.cidr}? Queued scans for this network will be cancelled.`)) void onRemove(scope.scope_id); }}><Trash2 size={15} /></button>}
        </div>)}
      </div>}
      {editable && activeCount > 0 && scopeOptions.length > 0 && !addNetworkOpen && <button className="button secondary scope-add-button" type="button" onClick={() => setAddNetworkOpen(true)}><Plus size={15} />Approve or renew network</button>}
      {editable && (activeCount === 0 || addNetworkOpen) && (scopeOptions.length ? <form className="scope-approval-form" onSubmit={(event) => void approve(event)}>
        <div className="scope-approval-row">
          <label>Connected network<select aria-label="Connected network" required value={selectedCidr} onChange={(event) => setCidr(event.target.value)}>{scopeOptions.map((scope) => <option key={scope} value={scope}>{scope}{scope === probe?.discovery_recommended_scope ? " - Current segment" : ""}</option>)}</select></label>
          <label>Allowed scans<select aria-label="Allowed scans" value={profilePreset} onChange={(event) => setProfilePreset(Number(event.target.value))}>{PROFILE_PRESETS.map((preset, index) => <option key={preset.label} value={index}>{preset.label}</option>)}</select></label>
        </div>
        <div className="scope-authorization-fields">
          <label>Network owner<input required maxLength={128} value={ownerValue} onChange={(event) => setApprovalOwner(event.target.value)} placeholder="Responsible person or team" /></label>
          <label>Written approval reference<input required maxLength={256} value={approvalReference} onChange={(event) => setApprovalReference(event.target.value)} placeholder="Ticket or document ID" /></label>
          <label>Approved by<input required maxLength={128} value={approvedBy} onChange={(event) => setApprovedBy(event.target.value)} placeholder="Approver's name" /></label>
          <label>Expires on (UTC)<input required type="date" value={expiresOn} onChange={(event) => setExpiresOn(event.target.value)} /></label>
        </div>
        {publicRange && <p className="site-scope-warning" role="note"><ShieldAlert size={15} /><span>This is public-range address space. The written approval must explicitly cover this CIDR.</span></p>}
        <div className="scope-authorization-actions">
          <label><input type="checkbox" checked={authorizationConfirmed} onChange={(event) => setAuthorizationConfirmed(event.target.checked)} />I have verified written authorization for this network and these profiles.</label>
          {publicRange && <label><input type="checkbox" checked={publicRangeAuthorized} onChange={(event) => setPublicRangeAuthorized(event.target.checked)} />The approval explicitly covers this public-range CIDR.</label>}
          <button className="button primary" type="submit" disabled={busy || !selectedCidr || !ownerValue.trim() || !approvalReference.trim() || !approvedBy.trim() || !expiresOn || !authorizationConfirmed || (publicRange && !publicRangeAuthorized)}><Plus size={15} />{existingScope ? "Renew approval" : "Approve network"}</button>
        </div>
        <details className="scope-advanced"><summary>Advanced settings</summary><div className="scope-advanced-fields">
          <label>Description<input maxLength={512} value={description} onChange={(event) => setDescription(event.target.value)} placeholder="Optional context" /></label>
          <label>Exclusions<input value={exclusions} onChange={(event) => setExclusions(event.target.value)} placeholder="CIDRs to exclude, separated by commas" /></label>
        </div></details>
      </form> : <p className="site-empty">{probe?.site_id === siteId ? "No connected /24 network available from this probe." : "Select a site with an enrolled probe to approve a network."}</p>)}
    </> : <p className="site-empty">Create a site to manage its approved networks.</p>}
  </section>;
}
