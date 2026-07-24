"use client";

import {
  Activity,
  Bell,
  Bot,
  Check,
  ChevronRight,
  Clipboard,
  Download,
  ExternalLink,
  HardDrive,
  History,
  LoaderCircle,
  MonitorDot,
  Network,
  Plus,
  Radar,
  RefreshCw,
  Search,
  Server,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Square,
  Terminal,
  X,
} from "lucide-react";
import { type FormEvent, type ReactNode, useCallback, useEffect, useMemo, useState } from "react";

import {
  AGENT_SERVER_URL,
  Agent as AgentRecord,
  Device,
  Discovery,
  Enrollment,
  HostResult,
  Scan,
  VulnerabilityLookup,
  api,
} from "@/lib/api";

function timeAgo(value: string | null) {
  if (!value) return "Never";
  const seconds = Math.max(0, Math.round((Date.now() - Date.parse(value)) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  return `${Math.floor(seconds / 3600)}h ago`;
}

function titleCase(value: string) {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function legacyScopeCheck(subnet: string | null | undefined) {
  if (!subnet) return { ready: false, error: "Waiting for an active network scope." };
  const [address, prefixText] = subnet.split("/");
  const octets = address?.split(".").map(Number) ?? [];
  const prefix = Number(prefixText);
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255) || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    return { ready: false, error: `${subnet} is not a valid IPv4 network.` };
  }
  const privateNetwork = octets[0] === 10
    || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31)
    || (octets[0] === 192 && octets[1] === 168);
  const addresses = 2 ** (32 - prefix);
  if (!privateNetwork) return { ready: false, error: `${subnet} is not a private IPv4 network.` };
  if (addresses > 256) return { ready: false, error: `${subnet} contains ${addresses.toLocaleString()} addresses; the discovery limit is 256.` };
  return { ready: true, error: null };
}

function elapsedLabel(value: string | null) {
  if (!value) return "00:00";
  const seconds = Math.max(0, Math.floor((Date.now() - Date.parse(value)) / 1000));
  const minutes = Math.floor(seconds / 60).toString().padStart(2, "0");
  return `${minutes}:${(seconds % 60).toString().padStart(2, "0")}`;
}

export function NetworkAgentDashboard() {
  const [agents, setAgents] = useState<AgentRecord[]>([]);
  const [selectedAgentId, setSelectedAgentId] = useState<string>("");
  const [discoveries, setDiscoveries] = useState<Discovery[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [selectedScope, setSelectedScope] = useState("");
  const [discoveryMode, setDiscoveryMode] = useState<"selected" | "all">("selected");
  const [profile, setProfile] = useState<"standard" | "full_tcp">("standard");
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const [authorizeOpen, setAuthorizeOpen] = useState(false);
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null);
  const [detail, setDetail] = useState<Device | null>(null);

  const load = useCallback(async () => {
    try {
      const nextAgents = await api.agents();
      setAgents(nextAgents);
      const agentId = selectedAgentId || nextAgents[0]?.agent_id || "";
      if (!selectedAgentId && agentId) setSelectedAgentId(agentId);
      if (agentId) {
        const [nextDiscoveries, nextScans] = await Promise.all([
          api.discoveries(agentId),
          api.scans(agentId),
        ]);
        setDiscoveries(nextDiscoveries);
        setScans(nextScans);
      } else {
        setDiscoveries([]);
        setScans([]);
      }
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Unable to load Telesec");
    } finally {
      setLoading(false);
    }
  }, [selectedAgentId]);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 3000);
    return () => window.clearInterval(timer);
  }, [load]);

  const selectedAgent = agents.find((item) => item.agent_id === selectedAgentId);
  const scopeOptions = useMemo(() => {
    if (selectedAgent?.discovery_scope_options?.length) {
      return selectedAgent.discovery_scope_options;
    }
    const legacy = legacyScopeCheck(selectedAgent?.subnet);
    return legacy.ready && selectedAgent?.subnet ? [selectedAgent.subnet] : [];
  }, [selectedAgent]);
  const recommendedScope = selectedAgent?.discovery_recommended_scope
    ?? scopeOptions[0]
    ?? "";
  useEffect(() => {
    setSelectedScope((current) => (
      scopeOptions.includes(current) ? current : recommendedScope
    ));
  }, [recommendedScope, scopeOptions]);
  const discovery = discoveries[0];
  const scan = scans[0];
  const resultByDevice = useMemo(
    () => new Map(scan?.results.map((result) => [result.device_id, result]) ?? []),
    [scan],
  );
  const filteredDevices = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return discovery?.devices ?? [];
    return (discovery?.devices ?? []).filter((device) =>
      [device.hostname, device.ip, device.mac, device.vendor]
        .filter(Boolean)
        .some((value) => value!.toLowerCase().includes(normalized)),
    );
  }, [discovery, query]);
  const selectableDeviceIds = useMemo(
    () => filteredDevices.filter((device) => !device.is_agent).map((device) => device.device_id),
    [filteredDevices],
  );
  const allVisibleSelected = selectableDeviceIds.length > 0
    && selectableDeviceIds.every((id) => selectedIds.includes(id));
  const exposureCount = scan?.results.reduce(
    (total, result) => total + result.exposure_flags.length,
    0,
  ) ?? 0;
  const onlineCount = agents.filter((item) => item.status !== "offline").length;
  const selectedAgentOffline = selectedAgent?.status === "offline";
  const scannerReady = Boolean(selectedAgent?.nmap_version)
    && selectedAgent?.npcap_status === "available";
  const scannerSetupRequired = Boolean(
    selectedAgent && !selectedAgentOffline && !scannerReady,
  );
  const legacyScope = legacyScopeCheck(selectedAgent?.subnet);
  const scopeReady = Boolean(
    scopeOptions.length && (selectedAgent?.discovery_ready ?? legacyScope.ready),
  );
  const scopeError = selectedAgent?.discovery_error ?? legacyScope.error;
  const scopeSetupRequired = Boolean(
    selectedAgent && !selectedAgentOffline && scannerReady && !scopeReady,
  );
  const discoveryActive = Boolean(
    discovery && ["queued", "running", "cancelling"].includes(discovery.status),
  );
  const canDiscover = Boolean(
    selectedAgent && !selectedAgentOffline && scannerReady && scopeReady
      && !discoveryActive && !busy,
  );

  function selectAgent(agentId: string) {
    setSelectedAgentId(agentId);
    setSelectedIds([]);
  }

  function toggleDevice(device: Device) {
    if (device.is_agent) return;
    setSelectedIds((current) => {
      if (current.includes(device.device_id)) {
        return current.filter((id) => id !== device.device_id);
      }
      return [...current, device.device_id];
    });
  }

  function toggleAllVisible() {
    setSelectedIds((current) => {
      if (allVisibleSelected) {
        return current.filter((id) => !selectableDeviceIds.includes(id));
      }
      return Array.from(new Set([...current, ...selectableDeviceIds]));
    });
  }

  function openDiscovery(mode: "selected" | "all") {
    setDiscoveryMode(mode);
    setAuthorizeOpen(true);
  }

  async function startDiscovery() {
    if (!selectedAgentId) return;
    setBusy(true);
    try {
      await api.discover(
        selectedAgentId,
        discoveryMode === "selected" ? selectedScope : null,
        discoveryMode,
      );
      setSelectedIds([]);
      setAuthorizeOpen(false);
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Discovery could not start");
    } finally {
      setBusy(false);
    }
  }

  async function startScan() {
    if (!discovery || selectedIds.length === 0) return;
    setBusy(true);
    try {
      await api.scan(discovery.discovery_id, selectedIds, profile);
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Scan could not start");
    } finally {
      setBusy(false);
    }
  }

  async function stopDiscovery() {
    if (!discovery || !discoveryActive) return;
    try {
      const updated = await api.cancelDiscovery(discovery.discovery_id);
      setDiscoveries((current) => [
        updated,
        ...current.filter((item) => item.discovery_id !== updated.discovery_id),
      ]);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Discovery could not stop");
    }
  }

  function downloadReport() {
    if (!scan) return;
    const blob = new Blob([JSON.stringify(scan, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `telesec-scan-${scan.scan_id}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><ShieldCheck size={23} /><span>TELESEC</span></div>
        <nav aria-label="Primary navigation">
          <a href="#overview"><MonitorDot size={17} /><span>Overview</span></a>
          <a href="#agents"><Server size={17} /><span>Agent Fleet</span></a>
          <a className="active" href="#devices"><Network size={17} /><span>Network Agent</span></a>
          <a href="#scans"><Radar size={17} /><span>Scan History</span></a>
          <a href="#activity"><Activity size={17} /><span>Activity Log</span></a>
          <a href="#settings"><Settings size={17} /><span>Settings</span></a>
        </nav>
        <div className="sidebar-status"><span className="status-dot" />Local console</div>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div><span className="eyebrow">TELESEC CONTROL</span><h1>Network Agent</h1></div>
          <div className="top-actions">
            <button className="button secondary" onClick={() => setAddOpen(true)}><Plus size={15} />Add agent</button>
            <button className="button primary" title={scannerSetupRequired ? "Install Nmap and Npcap before discovery" : scopeSetupRequired ? scopeError ?? "Connect an eligible IPv4 network" : discoveryActive ? "Discovery is already running" : "Discover the selected scope"} disabled={!canDiscover} onClick={() => openDiscovery("selected")}><Radar size={15} />Discover</button>
            <button className="icon-button" title="Refresh" onClick={() => void load()}><RefreshCw size={16} /></button>
            <button className="icon-button" title="Notifications"><Bell size={16} /></button>
            <div className="local-user"><span>LC</span><div><strong>Local Console</strong><small>No human login</small></div></div>
          </div>
        </header>

        {error && <div className="error-banner"><ShieldAlert size={17} /><span>{error}</span><button title="Dismiss" onClick={() => setError(null)}><X size={15} /></button></div>}

        <section className="metrics" id="overview">
          <Metric icon={<Bot size={18} />} label="Agents online" value={`${onlineCount} / ${agents.length}`} tone={onlineCount > 0 ? "green" : "red"} />
          <Metric icon={<Network size={18} />} label="Devices discovered" value={String(discovery?.device_count ?? 0)} tone="blue" />
          <Metric icon={<HardDrive size={18} />} label="Selected devices" value={String(selectedIds.length)} tone="cyan" />
          <Metric icon={<ShieldAlert size={18} />} label="Exposure findings" value={String(exposureCount)} tone="red" />
        </section>

        <section className={`connection-band ${selectedAgentOffline ? "offline" : scannerSetupRequired || scopeSetupRequired ? "attention" : ""}`}>
          <div className="connection-copy">
            <span className="eyebrow">NETWORK COLLECTION</span>
            <h2>{selectedAgent ? selectedAgent.label : "Connect a Telesec agent"}</h2>
            <p>{selectedAgent ? `${selectedAgent.site_name ?? "Local site"} · ${selectedAgent.subnet ?? "Network pending"}` : "Install the Windows collector and enroll it with this server."}</p>
            <div className="inline-status"><span className={`status-dot ${selectedAgent?.status ?? "offline"}`} />{selectedAgent ? titleCase(selectedAgent.status) : "No agent connected"}<span>Outbound HTTPS</span><span>{scannerReady ? "Scanner ready" : "Scanner unavailable"}</span><span>{scopeReady ? `${scopeOptions.length} scope${scopeOptions.length === 1 ? "" : "s"} available` : "Scope unavailable"}</span><span>All discovered targets</span></div>
            {selectedAgentOffline && <div className="agent-offline-note"><ShieldAlert size={15} /><span>No heartbeat for {timeAgo(selectedAgent.last_heartbeat_at)}. Discovery and scans resume after this agent reconnects.</span></div>}
            {scannerSetupRequired && <div className="scanner-setup-note"><ShieldAlert size={15} /><span>Nmap and Npcap are required before this agent can discover devices.</span><a href="https://nmap.org/download.html" target="_blank" rel="noreferrer">Get scanner</a></div>}
            {(scopeSetupRequired || selectedAgent?.discovery_requires_authorization) && <div className="scanner-setup-note"><ShieldAlert size={15} /><span>{scopeSetupRequired ? scopeError : `${selectedAgent?.subnet} uses public-range addressing. Each discovery requires explicit authorization.`}</span></div>}
          </div>
          <div className="connection-actions"><a className="button secondary" href="/downloads/agent/Telesec-Network-Agent-Setup.exe" download><Download size={15} />Download agent</a><button className="button primary" onClick={() => setAddOpen(true)}><Plus size={15} />Enrollment token</button></div>
        </section>

        <div className="content-grid">
          <div className="primary-column">
            <section className="panel" id="agents">
              <PanelHeader title="Agent fleet" subtitle="Collectors, heartbeat, dependencies, and connected network." action={<span className={`quiet-badge ${onlineCount === 0 && agents.length > 0 ? "danger" : ""}`}>{onlineCount} ONLINE</span>} />
              <div className="table-scroll"><table><thead><tr><th>Agent</th><th>Site / Network</th><th>OS</th><th>Status</th><th>Heartbeat</th><th aria-label="Action" /></tr></thead><tbody>{agents.length === 0 ? <EmptyRow columns={6} label="No enrolled agents" /> : agents.map((item) => <tr className={item.agent_id === selectedAgentId ? "selected-row" : ""} key={item.agent_id} onClick={() => selectAgent(item.agent_id)}><td><div className="device-name"><span className="device-icon"><Server size={15} /></span><div><strong>{item.label}</strong><small>{item.hostname} · v{item.agent_version}</small></div></div></td><td><strong>{item.site_name ?? "Local site"}</strong><small>{item.subnet ?? "Awaiting heartbeat"}</small></td><td>{item.os_name}</td><td><Status value={item.status} /></td><td>{timeAgo(item.last_heartbeat_at)}</td><td><ChevronRight size={16} /></td></tr>)}</tbody></table></div>
            </section>

            <section className="panel" id="devices">
              <PanelHeader title="Discovered devices" subtitle="Select any discovered devices for detailed inspection." action={<div className="device-tools"><div className="search-box"><Search size={15} /><input aria-label="Search devices" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search devices" /></div><span className="selection-count">{selectedIds.length} selected</span></div>} />
              <ScopeControl agent={selectedAgent} scopeOptions={scopeOptions} selectedScope={selectedScope} discoveryActive={discoveryActive} canDiscover={canDiscover} onScopeChange={setSelectedScope} onDiscover={openDiscovery} />
              <DiscoveryCallout discovery={discovery} scannerSetupRequired={scannerSetupRequired} scopeSetupRequired={scopeSetupRequired} scopeError={scopeError} canDiscover={canDiscover} onDiscover={() => openDiscovery("selected")} onStop={() => void stopDiscovery()} />
              <div className="scan-toolbar"><div className="segmented" aria-label="Scan profile"><button className={profile === "standard" ? "selected" : ""} onClick={() => setProfile("standard")}>Standard</button><button className={profile === "full_tcp" ? "selected" : ""} onClick={() => setProfile("full_tcp")}>Full TCP</button></div><div><button className="button secondary" disabled={selectableDeviceIds.length === 0} onClick={toggleAllVisible}>{allVisibleSelected ? "Unselect visible" : "Select all visible"}</button><button className="button ghost" disabled={selectedIds.length === 0} onClick={() => setSelectedIds([])}>Clear</button><button className="button primary" disabled={selectedIds.length === 0 || busy || selectedAgentOffline || !scannerReady || !discovery || !["completed", "partial"].includes(discovery.status)} onClick={() => void startScan()}>{busy ? <LoaderCircle className="spin" size={15} /> : <Radar size={15} />}Scan {selectedIds.length || "selected"}</button></div></div>
              <div className="table-scroll"><table><thead><tr><th className="check-cell"><input type="checkbox" aria-label="Select all visible devices" checked={allVisibleSelected} disabled={selectableDeviceIds.length === 0} onChange={toggleAllVisible} /></th><th>Device</th><th>IP / MAC</th><th>Scope</th><th>Vendor</th><th>Status</th><th>Scan</th><th aria-label="Details" /></tr></thead><tbody>{loading ? <EmptyRow columns={8} label="Loading devices" /> : filteredDevices.length === 0 ? <EmptyRow columns={8} label={["completed", "partial"].includes(discovery?.status ?? "") ? "Discovery completed; no active devices responded" : discoveryActive ? `${discovery?.found_count ?? 0} active devices found so far` : discovery ? "No matching devices" : "Run discovery to populate devices"} /> : filteredDevices.map((device) => { const checked = selectedIds.includes(device.device_id); const result = resultByDevice.get(device.device_id); return <tr key={device.device_id}><td className="check-cell"><input type="checkbox" aria-label={`Select ${device.hostname ?? device.ip}`} checked={checked} disabled={device.is_agent} onChange={() => toggleDevice(device)} /></td><td><div className="device-name"><span className="device-icon"><HardDrive size={15} /></span><div><strong>{device.hostname ?? "Unnamed device"}</strong><small>{device.is_agent ? "Telesec collector" : device.discovery_reason}</small></div></div></td><td><strong>{device.ip}</strong><small>{device.mac ?? "MAC unavailable"}</small></td><td><code>{device.discovery_scope ?? discovery?.network ?? "Unknown"}</code></td><td>{device.vendor ?? "Unknown"}</td><td><Status value="online" label="Discovered" /></td><td><Status value={result?.status ?? "not_scanned"} /></td><td><button className="icon-button small" title="Device details" onClick={() => setDetail(device)}><ChevronRight size={15} /></button></td></tr>; })}</tbody></table></div>
            </section>

            {scan && <section className="panel scan-progress" id="scans"><PanelHeader title="Latest scan" subtitle={`${titleCase(scan.profile)} · ${scan.total} selected devices`} action={<Status value={scan.status} />} /><div className="progress-grid"><ProgressStat label="Queued" value={scan.queued} /><ProgressStat label="Running" value={scan.running} /><ProgressStat label="Completed" value={scan.completed} /><ProgressStat label="Failed" value={scan.failed} /></div><div className="scan-actions"><span>{titleCase(scan.stage ?? scan.status)}</span><button className="button secondary" onClick={downloadReport}><Download size={15} />JSON report</button>{["queued", "running"].includes(scan.status) && <button className="button danger" disabled={scan.cancel_requested} onClick={() => void api.cancelScan(scan.scan_id).then(load)}><Square size={14} />{scan.cancel_requested ? "Cancelling" : "Cancel"}</button>}</div></section>}
          </div>

          <aside className="health-column">
            <section className={`health-panel ${selectedAgentOffline ? "offline" : scannerSetupRequired || scopeSetupRequired || selectedAgent?.discovery_requires_authorization || discovery?.status === "failed" ? "attention" : ""}`}>
              <span className="eyebrow">NETWORK HEALTH</span>
              <div className="health-score"><strong>{selectedAgentOffline ? "Offline" : scannerSetupRequired ? "Setup required" : scopeSetupRequired ? "Scope unsupported" : selectedAgent?.discovery_requires_authorization ? "Authorization required" : discovery?.status === "failed" ? "Attention" : ["completed", "partial"].includes(discovery?.status ?? "") ? "Ready" : "Pending"}</strong>{selectedAgentOffline || scannerSetupRequired || scopeSetupRequired || selectedAgent?.discovery_requires_authorization || discovery?.status === "failed" ? <ShieldAlert size={21} /> : <ShieldCheck size={21} />}</div>
              <p>{selectedAgent?.subnet ?? "No connected network"}</p>
              <div className="health-meter"><span style={{ width: selectedAgentOffline ? "18%" : scannerSetupRequired || scopeSetupRequired ? "34%" : selectedAgent?.status === "online" ? "86%" : "18%" }} /></div>
              <HealthLine label="Agent" value={selectedAgent ? titleCase(selectedAgent.status) : "Not connected"} />
              <HealthLine label="Nmap" value={selectedAgent?.nmap_version ?? "Missing"} />
              <HealthLine label="Npcap" value={titleCase(selectedAgent?.npcap_status ?? "unknown")} />
              <HealthLine label="Connected network" value={selectedAgent?.subnet ?? "Unavailable"} />
              <HealthLine label="Discovery scope" value={(discovery?.network ?? selectedScope) || "Not selected"} />
              <HealthLine label="Segments" value={discovery ? `${discovery.completed_scopes.length}/${discovery.total_scopes}` : String(scopeOptions.length)} />
              <HealthLine label="Last discovery" value={timeAgo(discovery?.completed_at ?? null)} />
              <HealthLine label="Open findings" value={String(exposureCount)} />
            </section>
            <LiveOperation discovery={discovery} scan={scan} onStop={() => void stopDiscovery()} />
            <section className="guidance" id="activity"><span className="eyebrow">CURRENT ACTIVITY</span><h3>{selectedAgentOffline ? "Agent offline" : scannerSetupRequired ? "Scanner setup required" : scopeSetupRequired ? "Network scope unsupported" : scan?.running ? `${scan.running} devices scanning` : discoveryActive ? "Discovering devices" : discovery?.status === "failed" ? "Discovery needs attention" : "Agent standing by"}</h3><p>{selectedAgentOffline ? "Waiting for the next authenticated heartbeat." : scannerSetupRequired ? "Install Nmap and Npcap to enable network collection." : scopeSetupRequired ? scopeError : scan ? `${scan.completed + scan.failed + scan.cancelled} of ${scan.total} device jobs finished.` : discovery?.status === "failed" ? discovery.error : "Commands are delivered through outbound HTTPS."}</p></section>
          </aside>
        </div>
      </main>

      {addOpen && <EnrollmentModal enrollment={enrollment} busy={busy} onClose={() => { setAddOpen(false); setEnrollment(null); }} onCreate={async (label, site) => { setBusy(true); try { setEnrollment(await api.createEnrollment(label, site)); await load(); } catch (cause) { setError(cause instanceof Error ? cause.message : "Token could not be created"); } finally { setBusy(false); } }} />}
      {authorizeOpen && <AuthorizationModal agent={selectedAgent} scope={discoveryMode === "all" ? selectedAgent?.subnet ?? "Connected network" : selectedScope} mode={discoveryMode} segmentCount={discoveryMode === "all" ? scopeOptions.length : 1} busy={busy} onClose={() => setAuthorizeOpen(false)} onConfirm={() => void startDiscovery()} />}
      {detail && <DeviceDrawer key={detail.device_id} device={detail} result={resultByDevice.get(detail.device_id)} scanId={scan?.scan_id} onClose={() => setDetail(null)} />}
    </div>
  );
}

function ScopeControl({ agent, scopeOptions, selectedScope, discoveryActive, canDiscover, onScopeChange, onDiscover }: { agent?: AgentRecord; scopeOptions: string[]; selectedScope: string; discoveryActive: boolean; canDiscover: boolean; onScopeChange: (scope: string) => void; onDiscover: (mode: "selected" | "all") => void }) {
  if (!agent || scopeOptions.length === 0) return null;
  return <div className="scope-control"><div><span>Connected network</span><strong>{agent.subnet ?? agent.discovery_network}</strong></div><label><span>Discovery scope</span><select value={selectedScope} disabled={discoveryActive} onChange={(event) => onScopeChange(event.target.value)}>{scopeOptions.map((scope) => <option key={scope} value={scope}>{scope}{scope === agent.discovery_recommended_scope ? " - Current segment" : ""}</option>)}</select></label><div className="scope-actions"><button className="button primary" disabled={!canDiscover || !selectedScope} onClick={() => onDiscover("selected")}><Radar size={15} />Discover selected</button>{agent.discovery_all_segments_available && scopeOptions.length > 1 && <button className="button secondary" disabled={!canDiscover} onClick={() => onDiscover("all")}><Network size={15} />Scan all {scopeOptions.length}</button>}</div></div>;
}

function DiscoveryCallout({ discovery, scannerSetupRequired, scopeSetupRequired, scopeError, canDiscover, onDiscover, onStop }: { discovery?: Discovery; scannerSetupRequired: boolean; scopeSetupRequired: boolean; scopeError: string | null; canDiscover: boolean; onDiscover: () => void; onStop: () => void }) {
  if (scannerSetupRequired) return <div className="discovery-callout warning"><span className="discovery-callout-icon"><ShieldAlert size={18} /></span><div><strong>Scanner setup required</strong><span>Install Nmap with its included Npcap driver on this Windows agent.</span></div><a className="button secondary" href="https://nmap.org/download.html" target="_blank" rel="noreferrer"><Download size={15} />Nmap + Npcap</a></div>;
  const active = discovery && ["queued", "running", "cancelling"].includes(discovery.status);
  if (active && discovery) {
    const progress = discovery.progress_percent == null ? null : `${Math.round(discovery.progress_percent)}% checked`;
    const found = `${discovery.found_count} active ${discovery.found_count === 1 ? "device" : "devices"} found so far`;
    const segment = discovery.total_scopes > 1 ? `${Math.min(discovery.total_scopes, discovery.completed_scopes.length + discovery.failed_scopes.length + 1)} of ${discovery.total_scopes} segments` : discovery.current_scope;
    return <div className="discovery-callout active"><span className="discovery-callout-icon"><LoaderCircle className="spin" size={18} /></span><div><strong>{discovery.status === "cancelling" ? "Stopping discovery" : titleCase(discovery.stage)}</strong><span>{[segment, found, progress, `${elapsedLabel(discovery.started_at ?? discovery.created_at)} elapsed`].filter(Boolean).join(" | ")}</span></div><button className="button danger" disabled={discovery.cancel_requested} onClick={onStop}><Square size={14} />{discovery.cancel_requested ? "Stopping" : "Stop"}</button></div>;
  }
  if (discovery?.status === "failed") return <div className="discovery-callout warning"><span className="discovery-callout-icon"><ShieldAlert size={18} /></span><div><strong>Discovery could not start</strong><span>{discovery.error ?? "The discovery command failed before completion."}</span></div><button className="button secondary" disabled={!canDiscover} onClick={onDiscover}><RefreshCw size={14} />Retry</button></div>;
  if (discovery && ["cancelled", "partial"].includes(discovery.status)) return <div className="discovery-callout warning"><span className="discovery-callout-icon"><Square size={16} /></span><div><strong>{discovery.status === "partial" ? "Discovery stopped with partial results" : "Discovery stopped"}</strong><span>{discovery.device_count ? `${discovery.device_count} active devices were retained.` : "No completed host records were available."}</span></div><button className="button secondary" disabled={!canDiscover} onClick={onDiscover}><RefreshCw size={14} />Run again</button></div>;
  if (!scopeSetupRequired) return null;
  return <div className="discovery-callout warning"><span className="discovery-callout-icon"><ShieldAlert size={18} /></span><div><strong>Network scope unsupported</strong><span>{scopeError}</span></div></div>;
}

function LiveOperation({ discovery, scan, onStop }: { discovery?: Discovery; scan?: Scan; onStop: () => void }) {
  const discoveryActive = Boolean(discovery && ["queued", "running", "cancelling"].includes(discovery.status));
  const scanActive = Boolean(scan && ["queued", "running"].includes(scan.status));
  const showDiscovery = discoveryActive || (!scanActive && Boolean(discovery));
  const events = showDiscovery ? discovery?.events?.slice(-5) ?? [] : [];
  const status = discoveryActive ? discovery!.status : scanActive ? scan!.status : discovery?.status ?? scan?.status ?? "idle";
  const title = discoveryActive || (!scanActive && discovery) ? "Network discovery" : scanActive || scan ? "Device scan" : "No active operation";
  const summary = discoveryActive && discovery
    ? `${discovery.found_count} found | ${discovery.completed_scopes.length + discovery.failed_scopes.length} of ${discovery.total_scopes} segments finished | ${discovery.progress_percent == null ? "progress pending" : `${Math.round(discovery.progress_percent)}%`} | ${elapsedLabel(discovery.started_at ?? discovery.created_at)}`
    : scanActive && scan
      ? `${scan.completed + scan.failed + scan.cancelled} of ${scan.total} finished`
      : discovery?.error ?? "The agent is waiting for an authorized command.";
  return <section className="live-operation"><div className="live-operation-header"><div><span className="eyebrow">LIVE OPERATION</span><h3>{title}</h3></div>{discoveryActive && discovery && <button className="icon-button small" title="Stop discovery" disabled={discovery.cancel_requested} onClick={onStop}><Square size={13} /></button>}</div><div className="operation-state"><Status value={status} /><span>{summary}</span></div>{showDiscovery && (discovery?.current_scope ?? discovery?.network) && <code className="operation-command"><Terminal size={13} />nmap -sn --host-timeout 30s --stats-every 2s {discovery?.current_scope ?? discovery?.network}</code>}<div className="operation-events">{events.length ? events.map((event) => <div key={event.event_id}><time>{new Date(event.occurred_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</time><span>{event.message}</span></div>) : <p>{scanActive ? "Device progress is summarized above." : "No operation events yet."}</p>}</div></section>;
}

function Metric({ icon, label, value, tone }: { icon: ReactNode; label: string; value: string; tone: string }) { return <div className="metric"><span className={`metric-icon ${tone}`}>{icon}</span><div><span>{label}</span><strong>{value}</strong></div></div>; }
function PanelHeader({ title, subtitle, action }: { title: string; subtitle: string; action: ReactNode }) { return <div className="panel-header"><div><h2>{title}</h2><p>{subtitle}</p></div>{action}</div>; }
function EmptyRow({ columns, label }: { columns: number; label: string }) { return <tr><td className="empty-row" colSpan={columns}>{label}</td></tr>; }
function Status({ value, label }: { value: string; label?: string }) { const tone = ["online", "completed", "up", "open"].includes(value) ? "success" : ["busy", "running", "queued", "medium"].includes(value) ? "warning" : ["failed", "offline", "cancelled", "timed_out", "critical", "high"].includes(value) ? "danger" : "neutral"; return <span className={`status ${tone}`}><span />{label ?? titleCase(value)}</span>; }
function ProgressStat({ label, value }: { label: string; value: number }) { return <div><span>{label}</span><strong>{value}</strong></div>; }
function HealthLine({ label, value }: { label: string; value: string }) { return <div className="health-line"><span>{label}</span><strong>{value}</strong></div>; }

function EnrollmentModal({ enrollment, busy, onClose, onCreate }: { enrollment: Enrollment | null; busy: boolean; onClose: () => void; onCreate: (label: string, site: string) => Promise<void> }) {
  const [label, setLabel] = useState("Windows Network Agent"); const [site, setSite] = useState("Head Office");
  async function submit(event: FormEvent) { event.preventDefault(); await onCreate(label, site); }
  return <div className="modal-backdrop" role="presentation"><section className="modal" role="dialog" aria-modal="true" aria-labelledby="enrollment-title"><div className="modal-header"><div><span className="eyebrow">ADD AGENT</span><h2 id="enrollment-title">Windows enrollment</h2></div><button className="icon-button" title="Close" onClick={onClose}><X size={17} /></button></div>{enrollment ? <div className="token-result"><span>Server URL</span><div className="copy-field"><code>{AGENT_SERVER_URL}</code><button title="Copy server URL" onClick={() => void navigator.clipboard.writeText(AGENT_SERVER_URL)}><Clipboard size={15} /></button></div><span>One-time token</span><div className="copy-field"><code>{enrollment.enrollment_token}</code><button title="Copy enrollment token" onClick={() => void navigator.clipboard.writeText(enrollment.enrollment_token)}><Clipboard size={15} /></button></div><small>Expires {new Date(enrollment.expires_at).toLocaleString()}</small><a className="button primary full" href="/downloads/agent/Telesec-Network-Agent-Setup.exe" download><Download size={15} />Download Windows agent</a></div> : <form onSubmit={submit}><label>Agent label<input required value={label} onChange={(event) => setLabel(event.target.value)} /></label><label>Site name<input value={site} onChange={(event) => setSite(event.target.value)} /></label><button className="button primary full" disabled={busy}>{busy ? <LoaderCircle className="spin" size={15} /> : <Plus size={15} />}Create enrollment token</button></form>}</section></div>;
}

function AuthorizationModal({ agent, scope, mode, segmentCount, busy, onClose, onConfirm }: { agent?: AgentRecord; scope: string; mode: "selected" | "all"; segmentCount: number; busy: boolean; onClose: () => void; onConfirm: () => void }) { const [confirmed, setConfirmed] = useState(false); return <div className="modal-backdrop"><section className="modal compact" role="dialog" aria-modal="true"><div className="modal-header"><div><span className="eyebrow">DISCOVERY SCOPE</span><h2>{mode === "all" ? "Scan connected network" : "Discover selected scope"}</h2></div><button className="icon-button" title="Close" onClick={onClose}><X size={17} /></button></div><div className="scope-summary"><Server size={18} /><div><strong>{agent?.label}</strong><span>{scope}</span><small>{segmentCount} sequential /24 segment{segmentCount === 1 ? "" : "s"}</small></div></div>{agent?.discovery_requires_authorization && <div className="inline-error"><ShieldAlert size={15} /><span>This connected network uses public-range addressing.</span></div>}<label className="confirmation"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /><span>I confirm that I am authorized to discover every selected network segment.</span></label><button className="button primary full" disabled={!confirmed || busy} onClick={onConfirm}>{busy ? <LoaderCircle className="spin" size={15} /> : <Radar size={15} />}{mode === "all" ? `Scan all ${segmentCount}` : "Start discovery"}</button></section></div>; }

function DeviceDrawer({ device, result, scanId, onClose }: { device: Device; result?: HostResult; scanId?: string; onClose: () => void }) {
  const [lookups, setLookups] = useState<Record<string, VulnerabilityLookup>>({});
  const [selectedCpe, setSelectedCpe] = useState<string | null>(null);
  const [loadingCpe, setLoadingCpe] = useState<string | null>(null);
  const [lookupError, setLookupError] = useState<string | null>(null);
  const cpeCount = new Set(result?.ports.map((port) => port.cpe).filter(Boolean)).size;
  const selectedLookup = selectedCpe ? lookups[selectedCpe] : undefined;

  async function checkVulnerabilities(cpe: string) {
    setSelectedCpe(cpe);
    setLookupError(null);
    if (lookups[cpe] || !scanId) return;
    setLoadingCpe(cpe);
    try {
      const lookup = await api.vulnerabilities(scanId, device.device_id, cpe);
      setLookups((current) => ({ ...current, [cpe]: lookup }));
    } catch (cause) {
      setLookupError(cause instanceof Error ? cause.message : "CVE lookup failed");
    } finally {
      setLoadingCpe(null);
    }
  }

  return <div className="drawer-backdrop" onClick={onClose}>
    <aside className="drawer" onClick={(event) => event.stopPropagation()}>
      <div className="modal-header"><div><span className="eyebrow">DEVICE DETAILS</span><h2>{device.hostname ?? device.ip}</h2></div><button className="icon-button" title="Close" onClick={onClose}><X size={17} /></button></div>
      <div className="detail-summary"><Status value={result?.status ?? "not_scanned"} /><span>{result?.ports.length ?? 0} detected ports</span><span>{cpeCount} service fingerprints</span></div>
      <dl>
        <dt>IP address</dt><dd>{device.ip}</dd>
        <dt>MAC address</dt><dd>{device.mac ?? "Unavailable"}</dd>
        <dt>Vendor</dt><dd>{device.vendor ?? "Unknown"}</dd>
        <dt>Device type</dt><dd>{result?.device_type ? `${titleCase(result.device_type)} (${Math.round((result.classification_confidence ?? 0) * 100)}% confidence)` : "Not classified"}</dd>
        <dt>Latency</dt><dd>{device.latency_ms == null ? "Unavailable" : `${device.latency_ms.toFixed(2)} ms`}</dd>
        <dt>Last seen</dt><dd>{new Date(device.last_seen).toLocaleString()}</dd>
      </dl>

      <h3>Operating system evidence</h3>
      {result?.os_matches.length ? <div className="os-match-list">{result.os_matches.slice(0, 5).map((match) => <div key={`${match.name}-${match.accuracy}`}><span>{match.name}</span><strong>{match.accuracy}%</strong></div>)}</div> : <p className="muted">No operating system fingerprint was detected.</p>}

      <h3>Open ports and services</h3>
      {result?.ports.length ? <div className="port-list detailed">{result.ports.map((port) => <div className="service-row" key={`${port.protocol}-${port.port}`}>
        <div className="service-heading"><code>{port.port}/{port.protocol}</code><Status value={port.state} /><strong>{port.service ?? "Unknown service"}</strong></div>
        <div className="service-details"><span>Product</span><strong>{port.product ?? "Not identified"}</strong><span>Version</span><strong>{port.version ?? "Not identified"}</strong>{port.cpe && <><span>CPE</span><code>{port.cpe}</code></>}</div>
        {port.cpe && scanId && <button className="button secondary cve-button" disabled={loadingCpe === port.cpe} onClick={() => void checkVulnerabilities(port.cpe!)}>{loadingCpe === port.cpe ? <LoaderCircle className="spin" size={14} /> : <ShieldAlert size={14} />}{lookups[port.cpe] ? "View CVEs" : "Check CVEs"}</button>}
      </div>)}</div> : <p className="muted">No detailed port result is available for this device.</p>}

      <h3>Exposure observations</h3>
      {result?.exposure_flags.length ? <div className="finding-list">{result.exposure_flags.map((flag) => <div key={flag.code}><Status value={flag.severity} /><div><strong>{flag.title}</strong><span>{flag.evidence}</span></div></div>)}</div> : <p className="muted">No rule-based exposure observations were reported.</p>}

      <div className="section-heading"><h3>Potential CVE matches</h3>{selectedLookup && <span>{selectedLookup.total} found</span>}</div>
      {lookupError && <div className="inline-error"><ShieldAlert size={15} /><span>{lookupError}</span></div>}
      {!selectedCpe && <p className="muted">{cpeCount ? "Use Check CVEs on a fingerprinted service to correlate its exact product version." : "A precise product version and CPE are required for CVE correlation."}</p>}
      {selectedCpe && loadingCpe === selectedCpe && <div className="lookup-loading"><LoaderCircle className="spin" size={16} />Checking the NVD for this service fingerprint...</div>}
      {selectedLookup && <VulnerabilityResults lookup={selectedLookup} />}
      {result?.error && <div className="inline-error"><ShieldAlert size={15} /><span>{result.error}</span></div>}
    </aside>
  </div>;
}

function VulnerabilityResults({ lookup }: { lookup: VulnerabilityLookup }) {
  return <div className="vulnerability-results">
    <div className="lookup-context"><code>{lookup.cpe}</code><span>{lookup.notice}</span></div>
    {lookup.vulnerabilities.length ? <div className="vulnerability-list">{lookup.vulnerabilities.map((vulnerability) => <article key={vulnerability.cve_id}>
      <div className="vulnerability-heading"><a href={`https://nvd.nist.gov/vuln/detail/${vulnerability.cve_id}`} target="_blank" rel="noreferrer">{vulnerability.cve_id}<ExternalLink size={12} /></a><Status value={vulnerability.severity} />{vulnerability.cvss_score != null && <strong>CVSS {vulnerability.cvss_score.toFixed(1)}</strong>}{vulnerability.known_exploited && <span className="kev-badge">Known exploited</span>}</div>
      <p>{vulnerability.description}</p>
      {vulnerability.vector && <code className="cvss-vector">{vulnerability.vector}</code>}
      {vulnerability.required_action && <div className="required-action"><strong>Required action</strong><span>{vulnerability.required_action}{vulnerability.action_due ? ` Due ${new Date(`${vulnerability.action_due}T00:00:00`).toLocaleDateString()}.` : ""}</span></div>}
      {vulnerability.references.length > 0 && <div className="reference-links">{vulnerability.references.slice(0, 3).map((reference, index) => <a key={`${reference}-${index}`} href={reference} target="_blank" rel="noreferrer"><ExternalLink size={11} />Reference</a>)}</div>}
    </article>)}</div> : <p className="muted result-empty">No NVD CVE matched this exact CPE version.</p>}
    <p className="nvd-attribution">This product uses the NVD API but is not endorsed or certified by the NVD. Retrieved {new Date(lookup.retrieved_at).toLocaleString()}{lookup.cached ? " from cache" : ""}.</p>
  </div>;
}
