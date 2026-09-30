"use client";

import {
  Bot,
  Check,
  ChevronRight,
  Clipboard,
  Download,
  ExternalLink,
  FileText,
  HardDrive,
  History,
  LoaderCircle,
  LogOut,
  MonitorDot,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  Plus,
  Radar,
  RefreshCw,
  Search,
  Server,
  Settings,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Square,
  Terminal,
  Users,
  X,
} from "lucide-react";
import { type FormEvent, type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  AGENT_SERVER_URL,
  API_URL,
  Agent as AgentRecord,
  AgentDiagnostic,
  AgentDiagnosticType,
  Device,
  Discovery,
  Enrollment,
  HostResult,
  PortResult,
  Scan,
  ScanProfile,
  SnmpInterface,
  VulnerabilityLookup,
  ApprovedScope,
  Site,
  OperatorSession,
  WorkerJob,
  api,
} from "@/lib/api";
import { downloadScanJson, downloadScanPdf } from "@/lib/report-downloads";
import { scanResultCoverage } from "@/lib/report-status";
import { countPortStates, countScanPortStates, portCpes, portEvidenceSourceLabel, portEvidenceTimeLabel, portServiceLabel } from "@/lib/port-evidence";
import { discoveryDeviceName, roleEstimate } from "@/lib/device-identity";
import { hostnameSourceLabel } from "@/lib/host-evidence";
import { nvdDataAge } from "@/lib/nvd-evidence";
import { NETWORK_SERVICE_TCP_PORTS, NETWORK_SERVICE_UDP_PORTS, SCAN_PROFILE_OPTIONS, approvedProfilesForTargets, scanProfileLabel } from "@/lib/scan-profiles";
import { SiteScopePanel } from "@/components/site-scope-panel";
import { AssetInventory } from "@/components/asset-inventory";
import { WorkerManagement } from "@/components/worker-management";

function timeAgo(value: string | null) {
  if (!value) return "Never";
  const seconds = Math.max(0, Math.round((Date.now() - Date.parse(value)) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  return `${Math.floor(seconds / 3600)}h ago`;
}

function titleCase(value: string) {
  return value.replaceAll("_", " ").replaceAll("-", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function parseKnownTargets(value: string): { targets: string[]; error: string | null } {
  const targets = value.split(/[,\s]+/).filter(Boolean);
  if (targets.length > 3 || new Set(targets).size !== targets.length) {
    return { targets, error: "Enter up to three distinct IP addresses." };
  }
  for (const target of targets) {
    const octets = target.split(".");
    if (octets.length !== 4 || octets.some((part) => !/^\d{1,3}$/.test(part) || String(Number(part)) !== part || Number(part) > 255)) {
      return { targets, error: "Known hosts must be IPv4 addresses." };
    }
  }
  return { targets, error: null };
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

function elapsedLabel(value: string | null, finishedAt?: string | null) {
  if (!value) return "00:00";
  const seconds = Math.max(0, Math.floor(((finishedAt ? Date.parse(finishedAt) : Date.now()) - Date.parse(value)) / 1000));
  const minutes = Math.floor(seconds / 60).toString().padStart(2, "0");
  return `${minutes}:${(seconds % 60).toString().padStart(2, "0")}`;
}

function clampPercent(value: number) {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function scanFinishedCount(item: Scan) {
  return item.completed + item.failed + item.cancelled;
}

function scanCompletionPercentFor(item: Scan) {
  return item.total ? clampPercent((scanFinishedCount(item) / item.total) * 100) : 0;
}

function scanFindingCount(item: Scan) {
  return item.summary?.exposure_findings ?? item.results.reduce((total, result) => total + result.exposure_flags.length, 0);
}

function scanHighFindingCount(item: Scan) {
  return item.summary?.high_exposure_findings ?? item.results.reduce(
    (total, result) => total + result.exposure_flags.filter((flag) => flag.severity === "high").length,
    0,
  );
}

function scanPortCount(item: Scan) {
  return countScanPortStates(item).open;
}

function scanFingerprintCount(item: Scan) {
  return item.summary?.service_fingerprints ?? item.results.reduce(
    (total, result) => total + new Set(result.ports.filter((port) => port.state === "open").flatMap(portCpes)).size,
    0,
  );
}

function deviceDisplayName(device: Device) {
  return discoveryDeviceName(device);
}

function deviceIdentitySubtitle(device: Device) {
  if (device.is_agent) return "ForgeSec collector";
  return [
    device.device_type ? titleCase(device.device_type) : null,
    device.snmp_description ?? device.discovery_reason,
  ].filter(Boolean).join(" - ");
}

function formatDuration(seconds: number | null | undefined) {
  if (seconds == null) return "Not reported";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function interfaceName(item: SnmpInterface) {
  return item.name || item.description || `Interface ${item.index}`;
}

function interfaceSpeed(item: SnmpInterface) {
  if (item.speed_mbps == null) return "Speed unknown";
  return `${Number.isInteger(item.speed_mbps) ? item.speed_mbps.toFixed(0) : item.speed_mbps.toFixed(3)} Mbps`;
}

type SeverityKey = "high" | "medium" | "low" | "info";

const SEVERITY_KEYS: SeverityKey[] = ["high", "medium", "low", "info"];

function emptySeverityCounts(): Record<SeverityKey, number> {
  return { high: 0, medium: 0, low: 0, info: 0 };
}

function scanSeverityCounts(item: Scan) {
  if (item.summary) return item.summary.severity_counts;
  const counts = emptySeverityCounts();
  for (const result of item.results) {
    for (const flag of result.exposure_flags) {
      counts[flag.severity] += 1;
    }
  }
  return counts;
}

function addSeverityCounts(
  current: Record<SeverityKey, number>,
  next: Record<SeverityKey, number>,
) {
  for (const key of SEVERITY_KEYS) current[key] += next[key];
  return current;
}

type DashboardView = "overview" | "scanner" | "assets" | "history";
type AgentReleaseInfo = { version: string; channel: "development" | "production"; signed: boolean; includes_licensed_scanner: boolean; sha256: string };
const SIDEBAR_COLLAPSED_KEY = "forgesec-sidebar-collapsed";
const QUICK_SCAN_COUNT = 10;
const DIAGNOSTIC_OPTIONS: Array<{
  value: AgentDiagnosticType;
  label: string;
  hint: string;
  maxSeconds: number;
}> = [
  { value: "ping", label: "Ping", hint: "Reachability and packet loss", maxSeconds: 20 },
  { value: "reverse_dns", label: "Reverse DNS", hint: "Hostname lookup", maxSeconds: 20 },
  { value: "arp_cache", label: "ARP cache", hint: "Local MAC table entry", maxSeconds: 10 },
  { value: "powershell_test", label: "PowerShell test", hint: "Windows network route detail", maxSeconds: 35 },
  { value: "inventory_nmap", label: "Inventory Nmap", hint: "Top 200 TCP ports and light versions", maxSeconds: 120 },
  { value: "network_services_nmap", label: "Network services Nmap", hint: "Selected TCP/UDP service ports", maxSeconds: 360 },
  { value: "standard_nmap", label: "Standard Nmap", hint: "Top 1,000 TCP ports and light versions", maxSeconds: 240 },
  { value: "full_tcp_nmap", label: "Full TCP Nmap", hint: "All TCP ports and deeper versions on this host", maxSeconds: 1200 },
];

type PingResult = "reply" | "unreachable" | "timeout" | "no_reply";

function pingResultFor(run: AgentDiagnostic | null): PingResult | null {
  if (!run || run.diagnostic_type !== "ping" || run.status !== "completed") return null;
  const reported = run.details.ping_result;
  if (reported === "reply" || reported === "unreachable" || reported === "timeout" || reported === "no_reply") return reported;

  const output = run.output ?? "";
  const replyPrefix = `reply from ${run.target_ip.toLowerCase()}:`;
  if (output.split(/\r?\n/).some((line) => {
    const normalized = line.trim().toLowerCase();
    return normalized.startsWith(replyPrefix) && /\bbytes\s*=\s*\d+/.test(normalized);
  })) return "reply";
  const normalized = output.toLowerCase();
  if (["unreachable", "general failure", "transmit failed"].some((term) => normalized.includes(term))) return "unreachable";
  if (normalized.includes("timed out")) return "timeout";
  return "no_reply";
}

function diagnosticErrorMessage(cause: unknown) {
  const message = cause instanceof Error ? cause.message : "Diagnostic could not start";
  if (message === "Not Found" || message.includes("HTTP 404")) {
    return "Diagnostic API is not available on the running server. Restart the ForgeSec API, then refresh this page.";
  }
  return message;
}

const VIEW_COPY: Record<DashboardView, { title: string; eyebrow: string }> = {
  overview: {
    eyebrow: "FORGESEC SECURITY CONSOLE",
    title: "Overview",
  },
  scanner: {
    eyebrow: "NETWORK OPERATIONS",
    title: "Network Scanner",
  },
  assets: {
    eyebrow: "NETWORK INVENTORY",
    title: "Assets",
  },
  history: {
    eyebrow: "SCAN EVIDENCE",
    title: "Scan History",
  },
};
function scanProfileOption(profile: ScanProfile | string) {
  return SCAN_PROFILE_OPTIONS.find((item) => item.value === profile)
    ?? { value: profile as ScanProfile, label: titleCase(profile), hint: "Stored scan profile" };
}

function viewFromHash(hash: string): DashboardView {
  const normalized = hash.replace(/^#/, "");
  if (["scanner", "agents", "devices", "activity"].includes(normalized)) {
    return "scanner";
  }
  if (["history", "scans"].includes(normalized)) {
    return "history";
  }
  if (normalized === "assets") return "assets";
  return "overview";
}

export function NetworkAgentDashboard() {
  const [activeView, setActiveView] = useState<DashboardView>("overview");
  const [agents, setAgents] = useState<AgentRecord[]>([]);
  const [sites, setSites] = useState<Site[]>([]);
  const [scopes, setScopes] = useState<ApprovedScope[]>([]);
  const [activeSiteId, setActiveSiteId] = useState("");
  const [selectedAgentId, setSelectedAgentId] = useState<string>("");
  const [discoveries, setDiscoveries] = useState<Discovery[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [workerJobs, setWorkerJobs] = useState<WorkerJob[]>([]);
  const [workerJobsError, setWorkerJobsError] = useState<string | null>(null);
  const [workerJobsLoading, setWorkerJobsLoading] = useState(false);
  const [workerJobsRefresh, setWorkerJobsRefresh] = useState(0);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [selectedScope, setSelectedScope] = useState("");
  const [discoveryMode, setDiscoveryMode] = useState<"selected" | "all">("selected");
  const [knownTargetsText, setKnownTargetsText] = useState("");
  const [authorizationError, setAuthorizationError] = useState<string | null>(null);
  const [profile, setProfile] = useState<ScanProfile>("inventory");
  const [fullTcpOpen, setFullTcpOpen] = useState(false);
  const [scanRequestError, setScanRequestError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dataLoadError, setDataLoadError] = useState<string | null>(null);
  const [pdfExportingId, setPdfExportingId] = useState<string | null>(null);
  const [jsonExportingId, setJsonExportingId] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<AgentRecord | null>(null);
  const [revokeError, setRevokeError] = useState<string | null>(null);
  const [authorizeOpen, setAuthorizeOpen] = useState(false);
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null);
  const [detail, setDetail] = useState<Device | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [workersOpen, setWorkersOpen] = useState(false);
  const [agentRelease, setAgentRelease] = useState<AgentReleaseInfo | null>(null);
  const [session, setSession] = useState<OperatorSession | null>(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const settingsRef = useRef<HTMLDivElement | null>(null);
  const selectionGeneration = useRef(0);
  const loadSequence = useRef(0);
  const appliedLoadSequence = useRef(0);

  const load = useCallback(async () => {
    const generation = selectionGeneration.current;
    const sequence = ++loadSequence.current;
    const current = () => generation === selectionGeneration.current && sequence >= appliedLoadSequence.current;
    try {
      const nextSession = await api.me();
      const [nextAgents, nextSites] = await Promise.all([api.agents(), api.sites()]);
      const eligibleAgents = activeSiteId ? nextAgents.filter((item) => item.site_id === activeSiteId) : nextAgents;
      const agentId = eligibleAgents.find((item) => item.agent_id === selectedAgentId)?.agent_id ?? eligibleAgents[0]?.agent_id ?? "";
      const siteId = activeSiteId || nextAgents.find((item) => item.agent_id === agentId)?.site_id || nextSites[0]?.site_id || "";
      const [nextScopes, nextDiscoveries, nextScans] = await Promise.all([
        siteId ? api.siteScopes(siteId) : Promise.resolve([]),
        agentId ? api.discoveries(agentId) : Promise.resolve([]),
        agentId ? api.scans(agentId) : Promise.resolve([]),
      ]);
      if (!current()) return;
      appliedLoadSequence.current = sequence;
      setSession(nextSession);
      setAgents(nextAgents);
      setSites(nextSites);
      setSelectedAgentId(agentId);
      if (!activeSiteId && siteId) setActiveSiteId(siteId);
      setScopes(nextScopes);
      setDiscoveries(nextDiscoveries);
      setScans(nextScans);
      setDataLoadError(null);
    } catch (cause) {
      if (current()) {
        appliedLoadSequence.current = sequence;
        const message = cause instanceof Error ? cause.message : "Unable to load ForgeSec";
        setDataLoadError(message);
      }
    } finally {
      if (current()) setLoading(false);
    }
  }, [selectedAgentId, activeSiteId]);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 3000);
    return () => window.clearInterval(timer);
  }, [load]);

  useEffect(() => {
    function syncViewFromHash() {
      setActiveView(viewFromHash(window.location.hash));
    }
    syncViewFromHash();
    window.addEventListener("hashchange", syncViewFromHash);
    window.addEventListener("popstate", syncViewFromHash);
    return () => {
      window.removeEventListener("hashchange", syncViewFromHash);
      window.removeEventListener("popstate", syncViewFromHash);
    };
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    fetch("/downloads/agent/release.json", { cache: "no-store", signal: controller.signal })
      .then((response) => response.ok ? response.json() : null)
      .then((release: AgentReleaseInfo | null) => {
        if (release && (release.channel === "development" || release.channel === "production") && release.version && release.sha256) setAgentRelease(release);
      })
      .catch(() => {});
    return () => controller.abort();
  }, []);

  useEffect(() => {
    setSidebarCollapsed(window.localStorage.getItem(SIDEBAR_COLLAPSED_KEY) === "true");
  }, []);

  useEffect(() => {
    window.localStorage.setItem(SIDEBAR_COLLAPSED_KEY, String(sidebarCollapsed));
  }, [sidebarCollapsed]);

  useEffect(() => {
    if (!settingsOpen) return;
    function closeOnOutsidePointer(event: PointerEvent) {
      const target = event.target as Node | null;
      if (target && settingsRef.current?.contains(target)) return;
      setSettingsOpen(false);
    }
    function closeOnEscape(event: KeyboardEvent) {
      if (event.key === "Escape") setSettingsOpen(false);
    }
    window.addEventListener("pointerdown", closeOnOutsidePointer);
    window.addEventListener("keydown", closeOnEscape);
    return () => {
      window.removeEventListener("pointerdown", closeOnOutsidePointer);
      window.removeEventListener("keydown", closeOnEscape);
    };
  }, [settingsOpen]);

  const selectedSiteId = activeSiteId || agents.find((item) => item.agent_id === selectedAgentId)?.site_id || sites[0]?.site_id || "";
  const selectedAgent = agents.find((item) => item.agent_id === selectedAgentId && (item.site_id ?? "") === selectedSiteId);
  const historySiteId = selectedAgent?.site_id || selectedSiteId;
  const historySiteName = sites.find((site) => site.site_id === historySiteId)?.name ?? "Selected site";
  useEffect(() => {
    if (activeView !== "history") return;
    setWorkerJobs([]);
    setWorkerJobsError(null);
    setWorkerJobsLoading(Boolean(historySiteId));
    if (!historySiteId) return;
    let current = true;
    async function refreshJobs() {
      try {
        const jobs = await api.siteWorkerJobs(historySiteId);
        if (current) { setWorkerJobs(jobs); setWorkerJobsError(null); setWorkerJobsLoading(false); }
      } catch (cause) {
        if (current) { setWorkerJobsError(cause instanceof Error ? cause.message : "Central jobs could not be loaded"); setWorkerJobsLoading(false); }
      }
    }
    void refreshJobs();
    const timer = window.setInterval(() => void refreshJobs(), 10000);
    return () => { current = false; window.clearInterval(timer); };
  }, [activeView, historySiteId, workerJobsRefresh]);
  const scopeOptions = useMemo(() => {
    if (selectedAgent?.approved_discovery_scopes?.length) {
      return selectedAgent.approved_discovery_scopes;
    }
    const legacy = legacyScopeCheck(selectedAgent?.subnet);
    return legacy.ready && selectedAgent?.subnet && selectedAgent.approved_scopes.includes(selectedAgent.subnet) ? [selectedAgent.subnet] : [];
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
  const activeScan = scans.find((item) => ["queued", "running", "cancelling"].includes(item.status));
  const scan = activeScan ?? scans[0];
  const resultByDevice = useMemo(
    () => new Map(scan?.results.map((result) => [result.device_id, result]) ?? []),
    [scan],
  );
  const filteredDevices = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return discovery?.devices ?? [];
    return (discovery?.devices ?? []).filter((device) =>
      [
        device.hostname,
        device.snmp_name,
        device.snmp_description,
        device.snmp_contact,
        device.snmp_location,
        device.ip,
        device.mac,
        device.vendor,
        ...(device.snmp_interfaces ?? []).flatMap((item) => [
          item.name,
          item.description,
          item.alias,
        ]),
      ]
        .filter(Boolean)
        .some((value) => value!.toLowerCase().includes(normalized)),
    );
  }, [discovery, query]);
  const allSelectableDeviceIds = useMemo(
    () => (discovery?.devices ?? []).filter((device) => !device.is_agent).map((device) => device.device_id),
    [discovery],
  );
  const selectableDeviceIds = useMemo(
    () => filteredDevices.filter((device) => !device.is_agent).map((device) => device.device_id),
    [filteredDevices],
  );
  const approvedScanProfiles = useMemo(() => {
    const targetScopes = selectedIds.length
      ? (discovery?.devices ?? [])
        .filter((device) => selectedIds.includes(device.device_id))
        .map((device) => device.discovery_scope ?? discovery?.network ?? "")
      : [selectedScope];
    return approvedProfilesForTargets(scopes, targetScopes);
  }, [scopes, selectedIds, discovery, selectedScope]);
  useEffect(() => {
    if (approvedScanProfiles.length && !approvedScanProfiles.includes(profile)) {
      setProfile(approvedScanProfiles[0]);
    }
  }, [approvedScanProfiles, profile]);
  const firstQuickSelectionIds = selectableDeviceIds.slice(0, QUICK_SCAN_COUNT);
  const lastQuickSelectionIds = selectableDeviceIds.slice(-QUICK_SCAN_COUNT);
  const allVisibleSelected = selectableDeviceIds.length > 0
    && selectableDeviceIds.every((id) => selectedIds.includes(id));
  const allDiscoveredSelected = allSelectableDeviceIds.length > 0
    && allSelectableDeviceIds.every((id) => selectedIds.includes(id));
  useEffect(() => {
    setSelectedIds((current) => {
      const next = current.filter((id) => allSelectableDeviceIds.includes(id));
      return next.length === current.length && next.every((id, index) => id === current[index])
        ? current
        : next;
    });
  }, [allSelectableDeviceIds]);
  const exposureCount = scan?.results.reduce(
    (total, result) => total + result.exposure_flags.length,
    0,
  ) ?? 0;
  const onlineCount = agents.filter((item) => item.status !== "offline").length;
  const canOperate = session?.auth_required === false || (session?.user?.role !== "viewer" && Boolean(session?.user));
  const canAdmin = session?.auth_required === false || session?.user?.role === "admin";
  const showDataLoadBanner = Boolean(dataLoadError && (
    activeView === "assets"
      || (activeView === "history" && scans.length > 0)
      || ((activeView === "overview" || activeView === "scanner") && selectedAgent)
  ));
  const selectedAgentOffline = selectedAgent?.status === "offline";
  const scannerReady = Boolean(selectedAgent?.nmap_version)
    && selectedAgent?.npcap_status === "available";
  const scannerSetupRequired = Boolean(
    selectedAgent && !selectedAgentOffline && !scannerReady,
  );
  const legacyScope = legacyScopeCheck(selectedAgent?.subnet);
  const scopeReady = Boolean(
    selectedAgent?.site_id === selectedSiteId
      && scopeOptions.length && (selectedAgent?.discovery_ready ?? legacyScope.ready),
  );
  const scopeApprovalRequired = Boolean(
    selectedAgent?.discovery_ready && scopeOptions.length === 0,
  );
  const scopeError = scopeOptions.length === 0
    ? scopeApprovalRequired
      ? selectedAgent?.discovery_requires_authorization
        ? "Approve the connected /24 under Site policy. Public-range discovery requires explicit authorization."
        : "Approve a connected /24 under Site policy before discovery."
      : selectedAgent?.discovery_error ?? legacyScope.error ?? "No eligible IPv4 discovery scope is available."
    : selectedAgent?.discovery_error ?? legacyScope.error;
  const scopeIssueTitle = scopeApprovalRequired ? "Network approval required" : "Network scope unavailable";
  const scopeHealthLabel = scopeApprovalRequired ? "Approval required" : "Scope unavailable";
  const scopeSetupRequired = Boolean(
    selectedAgent && !selectedAgentOffline && scannerReady && !scopeReady,
  );
  const discoveryActive = Boolean(
    discovery && ["queued", "running", "cancelling"].includes(discovery.status),
  );
  const canDiscover = Boolean(
    canOperate && selectedAgent?.site_id === selectedSiteId
      && !selectedAgentOffline && scannerReady && scopeReady
      && !discoveryActive && !busy && !dataLoadError,
  );
  const discoveredDevices = discovery?.devices ?? [];
  const scanActive = Boolean(activeScan);
  const agentHealthPercent = agents.length ? clampPercent((onlineCount / agents.length) * 100) : 0;
  const scanCompletionPercent = scan ? scanCompletionPercentFor(scan) : 0;
  const scanEvidenceCoverage = scan ? scanResultCoverage(scan) : null;
  const discoveryCompletionPercent = discovery
    ? clampPercent(discovery.progress_percent ?? (
      discovery.total_scopes > 0
        ? ((discovery.completed_scopes.length + discovery.failed_scopes.length) / discovery.total_scopes) * 100
        : ["completed", "partial"].includes(discovery.status) ? 100 : 0
    ))
    : 0;
  const scannerReadinessPercent = clampPercent(
    (selectedAgent ? 20 : 0)
    + (selectedAgent && !selectedAgentOffline ? 20 : 0)
    + (scannerReady ? 25 : 0)
    + (scopeReady ? 20 : 0)
    + (discovery ? 15 : 0),
  );
  const openPortCount = scan ? scanPortCount(scan) : 0;
  const highExposureCount = scan ? scanHighFindingCount(scan) : 0;
  const fingerprintCount = scan ? scanFingerprintCount(scan) : 0;
  const lastActivityAt = scan?.completed_at
    ?? scan?.started_at
    ?? discovery?.completed_at
    ?? discovery?.started_at
    ?? selectedAgent?.last_heartbeat_at
    ?? null;
  const overviewStatus = selectedAgent
    ? selectedAgentOffline
      ? "Probe offline"
      : scannerSetupRequired
        ? "Scanner setup required"
        : scopeSetupRequired
          ? scopeIssueTitle
          : scanActive
            ? "Device scan running"
            : discoveryActive
              ? "Discovery running"
              : "Ready for network operations"
    : dataLoadError ? "Console data unavailable" : "Connect your first ForgeSec probe";
  const overviewSummary = selectedAgent
    ? selectedAgentOffline
      ? "The collector is enrolled but has not sent a recent authenticated heartbeat."
      : scannerSetupRequired
        ? "Install Nmap and Npcap on the Windows collector before discovery can run."
        : scopeSetupRequired
          ? scopeError ?? "The connected network scope needs review before discovery."
          : `${selectedAgent.site_name ?? "Local site"} is connected on ${selectedAgent.subnet ?? "network pending"}.`
    : dataLoadError ? "The console could not refresh sites and probes. Retry after checking the API connection." : "Create an enrollment token, install the Windows probe, and this page will begin showing live network posture.";
  const readinessTone = !selectedAgent || selectedAgentOffline
    ? "var(--red)"
    : scannerSetupRequired || scopeSetupRequired
      ? "var(--amber)"
      : "var(--green)";
  const overviewProgressRows = [
    {
      label: "Probe health",
      value: agents.length ? `${agentHealthPercent}%` : "0%",
      detail: `${onlineCount} of ${agents.length} online`,
      progress: agentHealthPercent,
    },
    {
      label: "Scanner readiness",
      value: `${scannerReadinessPercent}%`,
      detail: scannerReady ? "Nmap and Npcap ready" : "Scanner setup pending",
      progress: scannerReadinessPercent,
    },
    {
      label: "Discovery progress",
      value: discovery ? `${discoveryCompletionPercent}%` : "0%",
      detail: discovery ? `${discovery.device_count} devices discovered` : "No discovery run yet",
      progress: discoveryCompletionPercent,
    },
    {
      label: "Scan completion",
      value: scan ? `${scanCompletionPercent}%` : "0%",
      detail: scan ? `${scan.completed} completed, ${scan.failed} failed${scan.cancelled ? `, ${scan.cancelled} cancelled` : ""}` : "No scan started",
      progress: scanCompletionPercent,
    },
  ];
  const readinessSteps = [
    {
      label: "Probe enrolled",
      detail: selectedAgent ? selectedAgent.label : "Create enrollment token",
      complete: Boolean(selectedAgent),
    },
    {
      label: "Heartbeat authenticated",
      detail: selectedAgent?.last_heartbeat_at ? timeAgo(selectedAgent.last_heartbeat_at) : "Waiting for heartbeat",
      complete: Boolean(selectedAgent && !selectedAgentOffline),
    },
    {
      label: "Scanner tools",
      detail: scannerReady ? selectedAgent?.nmap_version ?? "Nmap detected" : "Nmap and Npcap required",
      complete: scannerReady,
    },
    {
      label: "Scope approved",
      detail: scopeReady ? `${scopeOptions.length} scope${scopeOptions.length === 1 ? "" : "s"} available` : scopeError ?? "Scope pending",
      complete: scopeReady,
    },
    {
      label: "Discovery data",
      detail: discovery ? `${discovery.device_count} devices - ${titleCase(discovery.status)}` : "Run discovery",
      complete: Boolean(discovery && ["completed", "partial"].includes(discovery.status)),
    },
  ];
  const vendorSummary = useMemo(() => {
    const counts = new Map<string, number>();
    for (const device of discovery?.devices ?? []) {
      const label = device.vendor?.trim() || (device.is_agent ? "ForgeSec agent" : "Unknown vendor");
      counts.set(label, (counts.get(label) ?? 0) + 1);
    }
    return Array.from(counts, ([label, count]) => ({ label, count }))
      .sort((left, right) => right.count - left.count)
      .slice(0, 4);
  }, [discovery]);
  const discoveryReadyForScan = Boolean(discovery && ["completed", "partial"].includes(discovery.status));
  const canScanSelected = Boolean(
    canOperate && selectedIds.length > 0
      && selectedAgent?.site_id === selectedSiteId
      && discovery?.agent_id === selectedAgentId
      && discovery?.site_id === selectedSiteId
      && approvedScanProfiles.includes(profile)
      && (profile !== "full_tcp" || selectedIds.length === 1)
      && !busy
      && !scanActive
      && !selectedAgentOffline
      && scannerReady
      && discoveryReadyForScan
      && !dataLoadError,
  );
  const scannerHeroTitle = selectedAgent
    ? selectedAgentOffline
      ? "Reconnect the probe to resume scanning"
        : scannerSetupRequired
          ? "Install scanner tools on this probe"
        : scopeSetupRequired
          ? (scopeApprovalRequired ? "Approve a network for this site" : "Choose an eligible discovery scope")
          : discoveryActive
            ? "Discovery is running"
            : scanActive
              ? "Device scan in progress"
              : selectedIds.length > 0
                ? `${selectedIds.length} targets ready for inspection`
                : discoveryReadyForScan ? "Choose targets to scan" : "Discover devices and select targets"
    : dataLoadError ? "Scanner data unavailable" : "Add a ForgeSec probe to start scanning";
  const scannerHeroCopy = selectedAgent
    ? selectedAgentOffline
      ? "The selected collector is offline. Commands will be available when the next authenticated heartbeat arrives."
      : scannerSetupRequired
        ? "Nmap and Npcap must be present on the Windows collector before the scanner can discover devices."
        : scopeSetupRequired
          ? scopeApprovalRequired
            ? "Choose a connected /24 in Site policy and approve it to enable discovery."
            : scopeError ?? "The connected network does not currently provide a safe discovery scope."
          : activeScan
            ? `${scanFinishedCount(activeScan)} of ${activeScan.total} targets finished. New scans unlock when this job ends.`
            : `Active collector: ${selectedAgent.label} on ${selectedAgent.subnet ?? selectedAgent.discovery_network ?? "network pending"}.`
    : dataLoadError ? "Retry the API connection before starting a new operation." : "Create an enrollment token, install the Windows probe, then return here to run discovery and scans.";
  const scannerStats = [
    { label: "Scope", value: selectedScope || discovery?.network || "Not selected" },
    { label: "Discovered", value: String(discovery?.device_count ?? 0) },
    { label: "Selectable", value: String(selectableDeviceIds.length) },
    { label: "Selected", value: `${selectedIds.length}/${allSelectableDeviceIds.length || 0}` },
  ];
  const selectedProfileOption = scanProfileOption(profile);
  const scanPlanRows = [
    { label: "Scope", value: discovery?.network ?? selectedScope },
    { label: "Selected targets", value: `${selectedIds.length} of ${allSelectableDeviceIds.length || 0}` },
    { label: "Scan profile", value: selectedProfileOption.label },
  ];
  const totalScanTargets = scans.reduce((total, item) => total + item.total, 0);
  const totalScanResults = scans.reduce((total, item) => total + scanResultCoverage(item).saved, 0);
  const completedScanCount = scans.filter((item) => item.status === "completed").length;
  const activeScanCount = scans.filter((item) => ["queued", "running"].includes(item.status)).length;
  const historyCompletionPercent = totalScanTargets
    ? clampPercent((totalScanResults / totalScanTargets) * 100)
    : 0;
  const latestHistoryScan = scans[0];
  const latestHistoryFindings = latestHistoryScan ? scanFindingCount(latestHistoryScan) : 0;
  const historyHeroCopy = latestHistoryScan
    ? `Latest ${scanProfileLabel(latestHistoryScan.profile)} scan: ${titleCase(latestHistoryScan.status)}. ${latestHistoryScan.total} targets, ${latestHistoryFindings} recorded exposure signals.`
    : "Run a scan to create the first saved report. In-progress and failed runs also appear in the timeline.";
  const historyStats = [
    { label: "Total scans", value: String(scans.length) },
    { label: "Completed", value: String(completedScanCount) },
    { label: "Active jobs", value: String(activeScanCount) },
    { label: "Host results", value: `${historyCompletionPercent}%` },
  ];
  const recentTrendScans = scans.slice(0, 8).reverse();
  const maxTrendFindings = Math.max(1, ...recentTrendScans.map(scanFindingCount));
  const scanTrendRows = recentTrendScans.map((item, index) => {
    const findings = scanFindingCount(item);
    return {
      label: `R${index + 1}`,
      value: findings,
      detail: `${item.total} targets`,
      percent: Math.max(8, clampPercent((findings / maxTrendFindings) * 100)),
      status: item.status,
    };
  });
  const historySeverityCounts = scans.reduce(
    (counts, item) => addSeverityCounts(counts, scanSeverityCounts(item)),
    emptySeverityCounts(),
  );
  const historySeverityRows = SEVERITY_KEYS.map((key) => ({
    label: titleCase(key),
    value: historySeverityCounts[key],
    tone: key,
  }));
  const coverageGraphRows = [
    {
      label: "Discovered",
      value: discoveredDevices.length,
      detail: discovery ? titleCase(discovery.status) : "Not run",
      percent: discovery ? Math.max(8, discoveryCompletionPercent) : 0,
      tone: "green",
    },
    {
      label: "Selectable",
      value: selectableDeviceIds.length,
      detail: "Authorized targets",
      percent: discoveredDevices.length ? clampPercent((selectableDeviceIds.length / discoveredDevices.length) * 100) : 0,
      tone: "blue",
    },
    {
      label: "Selected",
      value: selectedIds.length,
      detail: "Ready to scan",
      percent: selectableDeviceIds.length ? clampPercent((selectedIds.length / selectableDeviceIds.length) * 100) : 0,
      tone: "mauve",
    },
    {
      label: "Scanned",
      value: scanEvidenceCoverage?.saved ?? 0,
      detail: scan ? titleCase(scan.status) : "No scan",
      percent: scanEvidenceCoverage?.percent ?? 0,
      tone: "amber",
    },
  ];
  const maxEvidenceValue = Math.max(1, openPortCount, fingerprintCount, exposureCount, highExposureCount);
  const latestEvidenceRows = [
    {
      label: "Confirmed open",
      value: openPortCount,
      detail: "Detected services",
      percent: clampPercent((openPortCount / maxEvidenceValue) * 100),
      tone: "blue",
    },
    {
      label: "Fingerprints",
      value: fingerprintCount,
      detail: "CPE matches",
      percent: clampPercent((fingerprintCount / maxEvidenceValue) * 100),
      tone: "green",
    },
    {
      label: "Findings",
      value: exposureCount,
      detail: "Exposure rules",
      percent: clampPercent((exposureCount / maxEvidenceValue) * 100),
      tone: exposureCount ? "red" : "mauve",
    },
    {
      label: "High",
      value: highExposureCount,
      detail: "Priority findings",
      percent: clampPercent((highExposureCount / maxEvidenceValue) * 100),
      tone: highExposureCount ? "red" : "amber",
    },
  ];
  const viewCopy = VIEW_COPY[activeView];

  function navigateView(view: DashboardView) {
    if (activeView === view) {
      window.scrollTo({ top: 0, behavior: "instant" });
      return;
    }
    setActiveView(view);
    const url = new URL(window.location.href);
    if (view !== "assets") url.searchParams.delete("asset");
    url.hash = view;
    window.history.pushState(null, "", url);
    window.scrollTo({ top: 0, behavior: "instant" });
  }

  function selectAgent(agentId: string) {
    selectionGeneration.current += 1;
    setSelectedAgentId(agentId);
    setActiveSiteId(agents.find((item) => item.agent_id === agentId)?.site_id || "");
    setSelectedIds([]);
    setDiscoveries([]);
    setScans([]);
    setQuery("");
    setDetail(null);
  }

  function selectSite(siteId: string) {
    selectionGeneration.current += 1;
    setActiveSiteId(siteId);
    setScopes([]);
    const siteProbe = agents.find((item) => item.site_id === siteId);
    if (siteProbe) selectAgent(siteProbe.agent_id);
    else {
      setSelectedAgentId("");
      setDiscoveries([]);
      setScans([]);
      setSelectedIds([]);
      setQuery("");
      setDetail(null);
    }
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

  function replaceSelection(deviceIds: string[]) {
    setSelectedIds(Array.from(new Set(deviceIds)));
  }

  function toggleAllVisible() {
    setSelectedIds((current) => {
      if (allVisibleSelected) {
        return current.filter((id) => !selectableDeviceIds.includes(id));
      }
      const additions = selectableDeviceIds.filter((id) => !current.includes(id));
      return Array.from(new Set([...current, ...additions]));
    });
  }

  function toggleAllDiscovered() {
    setSelectedIds((current) => {
      if (allDiscoveredSelected) return [];
      return Array.from(new Set([...current, ...allSelectableDeviceIds]));
    });
  }

  function openDiscovery(mode: "selected" | "all") {
    setDiscoveryMode(mode);
    setKnownTargetsText("");
    setAuthorizationError(null);
    setAuthorizeOpen(true);
  }

  async function startDiscovery() {
    if (!selectedAgentId) return;
    const knownTargets = discoveryMode === "selected" ? parseKnownTargets(knownTargetsText) : { targets: [], error: null };
    if (knownTargets.error) {
      setAuthorizationError(knownTargets.error);
      return;
    }
    setBusy(true);
    try {
      await api.discover(
        selectedAgentId,
        discoveryMode === "selected" ? selectedScope : null,
        discoveryMode,
        knownTargets.targets,
      );
      setSelectedIds([]);
      setAuthorizationError(null);
      await load();
      setAuthorizeOpen(false);
    } catch (cause) {
      setAuthorizationError(cause instanceof Error ? cause.message : "Discovery could not start");
    } finally {
      setBusy(false);
    }
  }

  async function startScan(fullTcpConfirmed = false) {
    if (!discovery || !canScanSelected) return;
    if (profile === "full_tcp" && !fullTcpConfirmed) {
      setScanRequestError(null);
      setFullTcpOpen(true);
      return;
    }
    setBusy(true);
    try {
      await api.scan(discovery.discovery_id, selectedIds, profile, fullTcpConfirmed);
      setScanRequestError(null);
      await load();
      setFullTcpOpen(false);
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : "Scan could not start";
      if (fullTcpConfirmed) setScanRequestError(message);
      else setError(message);
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

  async function downloadScanReport(item: Scan) {
    if (jsonExportingId) return;
    setJsonExportingId(item.scan_id);
    setExportError(null);
    try {
      await downloadScanJson(item.scan_id);
    } catch (cause) {
      setExportError(cause instanceof Error ? cause.message : "JSON export failed");
    } finally {
      setJsonExportingId(null);
    }
  }

  async function cancelActiveScan() {
    if (!activeScan || activeScan.cancel_requested || busy) return;
    setBusy(true);
    try {
      await api.cancelScan(activeScan.scan_id);
      await load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Scan could not be cancelled");
    } finally {
      setBusy(false);
    }
  }

  async function exportScanPdf(item: Scan) {
    if (pdfExportingId) return;
    setPdfExportingId(item.scan_id);
    setExportError(null);
    try {
      await downloadScanPdf(item.scan_id);
    } catch (cause) {
      setExportError(cause instanceof Error ? cause.message : "PDF export failed");
    } finally {
      setPdfExportingId(null);
    }
  }

  function downloadReport() {
    if (!scan) return;
    void downloadScanReport(scan);
  }

  const metricsSection = (
    <section className="metrics" id="overview-metrics">
      <Metric icon={<Bot size={18} />} label="Probes online" value={`${onlineCount} / ${agents.length}`} tone={onlineCount > 0 ? "green" : "red"} />
      <Metric icon={<Network size={18} />} label="Devices discovered" value={String(discovery?.device_count ?? 0)} tone="blue" />
      <Metric icon={<HardDrive size={18} />} label="Selected devices" value={String(selectedIds.length)} tone="cyan" />
      <Metric icon={<ShieldAlert size={18} />} label="Exposure findings" value={String(exposureCount)} tone="red" />
    </section>
  );

  const connectionBand = (
    <section className={`connection-band ${selectedAgentOffline ? "offline" : scannerSetupRequired || scopeSetupRequired ? "attention" : ""}`}>
      <div className="connection-copy">
        <span className="eyebrow">NETWORK COLLECTION</span>
        <h2>{selectedAgent ? selectedAgent.label : "Connect a ForgeSec probe"}</h2>
        <p>{selectedAgent ? `${selectedAgent.site_name ?? "Local site"} - ${selectedAgent.subnet ?? "Network pending"}` : "Create a one-time token, install the Windows collector, and enroll this workstation."}</p>
        <div className="inline-status"><span className={`status-dot ${selectedAgent?.status ?? "offline"}`} />{selectedAgent ? titleCase(selectedAgent.status) : "No agent connected"}<span>Outbound HTTPS</span><span>{scannerReady ? "Scanner ready" : "Scanner unavailable"}</span><span>{scopeReady ? `${scopeOptions.length} scope${scopeOptions.length === 1 ? "" : "s"} available` : "Scope unavailable"}</span><span>All discovered targets</span></div>
        {selectedAgentOffline && <div className="agent-offline-note"><ShieldAlert size={15} /><span>{selectedAgent?.revoked_at ? "Probe access revoked. Create a new enrollment token and reset its local identity to reconnect." : `No heartbeat for ${timeAgo(selectedAgent.last_heartbeat_at)}. Discovery and scans resume after this agent reconnects.`}</span></div>}
        {scannerSetupRequired && <div className="scanner-setup-note"><ShieldAlert size={15} /><span>Nmap and Npcap are required before this agent can discover devices.</span><a href="https://nmap.org/download.html" target="_blank" rel="noreferrer">Get scanner</a></div>}
        {(scopeSetupRequired || selectedAgent?.discovery_requires_authorization) && <div className="scanner-setup-note"><ShieldAlert size={15} /><span>{scopeSetupRequired ? scopeError : `${selectedAgent?.subnet} uses public-range addressing. Each discovery requires explicit authorization.`}</span></div>}
      </div>
      <div className="connection-actions"><a className="button secondary" href="/downloads/agent/ForgeSec-Network-Agent-Setup.exe" download><Download size={15} />Download agent</a><button className="button primary" disabled={!canAdmin} onClick={() => setAddOpen(true)}><Plus size={15} />Enrollment token</button></div>
    </section>
  );

  const overviewHero = (
    <section className={`overview-hero ${selectedAgentOffline ? "offline" : scannerSetupRequired || scopeSetupRequired ? "attention" : ""}`}>
      <div className="overview-hero-main">
        <span className="eyebrow">COMMAND OVERVIEW</span>
        <h2>{overviewStatus}</h2>
        <p>{overviewSummary}</p>
        <div className="overview-context">
          <span><Server size={14} />{selectedAgent?.hostname ?? "No collector"}</span>
          <span><Network size={14} />{(selectedAgent?.subnet ?? selectedScope) || "No scope"}</span>
          <span><Radar size={14} />{lastActivityAt ? timeAgo(lastActivityAt) : "No activity yet"}</span>
        </div>
        <div className="overview-hero-actions">
          {!selectedAgent && dataLoadError ? <button className="button primary" onClick={() => void load()}><RefreshCw size={15} />Retry</button>
            : !selectedAgent ? <button className="button primary" disabled={!canAdmin} onClick={() => setAddOpen(true)}><Plus size={15} />Add probe</button>
            : selectedAgentOffline ? <button className="button primary" onClick={() => navigateView("scanner")}><Server size={15} />View probe</button>
            : scannerSetupRequired ? <a className="button primary" href="https://nmap.org/download.html" target="_blank" rel="noreferrer"><Download size={15} />Get scanner tools</a>
            : scopeSetupRequired ? <button className="button primary" onClick={() => navigateView("scanner")}><ShieldCheck size={15} />Approve network</button>
            : !discoveryReadyForScan ? <button className="button primary" disabled={!canDiscover} onClick={() => openDiscovery("selected")}><Radar size={15} />Run discovery</button>
            : !scan ? <button className="button primary" onClick={() => navigateView("scanner")}><Network size={15} />Select scan targets</button>
            : <button className="button primary" onClick={() => navigateView("assets")}><HardDrive size={15} />Review assets</button>}
          {scan && <a className="button secondary" href={`/network-agent/reports/${scan.scan_id}`}><ExternalLink size={15} />Latest report</a>}
        </div>
      </div>
      <div className="overview-hero-side">
        <div className="overview-gauge" style={{ background: `conic-gradient(${readinessTone} ${scannerReadinessPercent}%, #edf1f0 0)` }}>
          <div><strong>{scannerReadinessPercent}%</strong><span>ready</span></div>
        </div>
        <div className="overview-progress-list">
          {overviewProgressRows.map((row) => (
            <div className="overview-progress-row" key={row.label}>
              <div><span>{row.label}</span><strong>{row.value}</strong></div>
              <small>{row.detail}</small>
              <div className="overview-progress-track"><span style={{ width: `${row.progress}%` }} /></div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );

  const overviewInsights = (
    <div className="overview-grid">
      <section className="overview-card">
        <div className="overview-card-header"><span className="eyebrow">READINESS</span><strong>Operational checklist</strong></div>
        <div className="readiness-list">
          {readinessSteps.map((step) => (
            <div className={`readiness-item ${step.complete ? "complete" : ""}`} key={step.label}>
              <span>{step.complete ? <Check size={13} /> : <ShieldAlert size={13} />}</span>
              <div><strong>{step.label}</strong><small>{step.detail}</small></div>
            </div>
          ))}
        </div>
      </section>

      <section className="overview-card">
        <div className="overview-card-header"><span className="eyebrow">DISCOVERY MIX</span><strong>Device distribution</strong></div>
        {vendorSummary.length ? (
          <div className="vendor-bars">
            {vendorSummary.map((item) => (
              <div className="vendor-row" key={item.label}>
                <div><span>{item.label}</span><strong>{item.count}</strong></div>
                <div className="vendor-track"><span style={{ width: `${Math.max(8, clampPercent((item.count / Math.max(1, discoveredDevices.length)) * 100))}%` }} /></div>
              </div>
            ))}
          </div>
        ) : <EmptyState compact icon={<Network size={18} />} title="No device mix yet" message="Run discovery from a connected agent to see vendors and host distribution." action={<button className="button secondary" disabled={!canDiscover} onClick={() => openDiscovery("selected")}><Radar size={14} />Run discovery</button>} />}
      </section>

      <section className="overview-card">
        <div className="overview-card-header"><span className="eyebrow">SCAN SNAPSHOT</span><strong>Evidence posture</strong></div>
        <div className="scan-snapshot">
          <div className="scan-mini-gauge" style={{ background: `conic-gradient(var(--brand-mauve) ${scanEvidenceCoverage?.percent ?? 0}%, #edf1f0 0)` }}><strong>{scanEvidenceCoverage?.percent ?? 0}%</strong></div>
          <div><strong>{scan ? titleCase(scan.status) : "No scan yet"}</strong><span>{scan ? `${scanEvidenceCoverage?.saved ?? 0} of ${scan.total} targets returned host results` : "Start a scan from Network Scanner."}</span></div>
        </div>
        <div className="overview-evidence-grid">
          <div><span>Confirmed open</span><strong>{openPortCount}</strong></div>
          <div><span>Fingerprints</span><strong>{fingerprintCount}</strong></div>
          <div><span>High findings</span><strong>{highExposureCount}</strong></div>
        </div>
      </section>
    </div>
  );

  const overviewGraphs = (
    <section className="graph-grid" aria-label="Network graph summary">
      <GraphCard eyebrow="SCAN TREND" title="Recent findings">
        <TrendBars rows={scanTrendRows} emptyLabel="Run scans to build finding trend data." />
      </GraphCard>
      <GraphCard eyebrow="DISCOVERY FLOW" title="Discovery funnel">
        <HorizontalGraph rows={coverageGraphRows} emptyLabel="Run discovery to populate the device funnel." />
      </GraphCard>
      <GraphCard eyebrow="LATEST EVIDENCE" title="Ports and findings">
        <HorizontalGraph rows={latestEvidenceRows} emptyLabel="Start a scan to populate evidence graphs." />
      </GraphCard>
    </section>
  );

  const agentFleetPanel = (
    <section className="panel" id="agents">
      <PanelHeader title="Agent fleet" subtitle="Collector identity, heartbeat posture, scanner dependencies, and connected network." action={<div className="fleet-actions"><span className={`quiet-badge ${onlineCount === 0 && agents.length > 0 ? "danger" : ""}`}>{onlineCount} ONLINE</span>{canAdmin && selectedAgent && !selectedAgent.revoked_at && <button className="button secondary" type="button" onClick={() => setRevokeTarget(selectedAgent)}><ShieldX size={14} />Revoke</button>}</div>} />
      <div className="table-scroll"><table><thead><tr><th>Agent</th><th>Site / Network</th><th>OS</th><th>Status</th><th>Heartbeat</th><th aria-label="Action" /></tr></thead><tbody>{agents.length === 0 ? <EmptyRow columns={6} icon={<Server size={18} />} label="No enrolled agents" message="Create an enrollment token, install the ForgeSec Windows agent, and the collector will appear here after its first heartbeat." action={<button className="button primary" onClick={() => setAddOpen(true)}><Plus size={15} />Enrollment token</button>} /> : agents.map((item) => <tr className={item.agent_id === selectedAgentId ? "selected-row" : ""} key={item.agent_id} onClick={() => selectAgent(item.agent_id)}><td><div className="device-name"><span className="device-icon"><Server size={15} /></span><div><strong>{item.label}</strong><small>{item.hostname} - v{item.agent_version}</small></div></div></td><td><strong>{item.site_name ?? "Local site"}</strong><small>{item.subnet ?? "Awaiting heartbeat"}</small></td><td>{item.os_name}</td><td>{item.revoked_at ? <span className="quiet-badge danger">Revoked</span> : <Status value={item.status} />}</td><td>{timeAgo(item.last_heartbeat_at)}</td><td><ChevronRight size={16} /></td></tr>)}</tbody></table></div>
    </section>
  );

  const deviceEmptyState = loading
    ? {
      icon: <LoaderCircle className="spin" size={18} />,
      label: "Loading devices",
      message: "ForgeSec is refreshing discovery data from the selected agent.",
      action: undefined,
    }
    : ["completed", "partial"].includes(discovery?.status ?? "")
      ? {
        icon: <HardDrive size={18} />,
        label: discovery?.device_count ? "No matching devices" : "No hosts responded",
        message: discovery?.device_count ? "Your search or filter has hidden every discovered host. Clear the search to review all devices." : "No response does not prove these hosts are offline. Review the approved scope and network path.",
        action: discovery?.device_count ? <button className="button secondary" onClick={() => setQuery("")}><X size={14} />Clear search</button> : undefined,
      }
      : discoveryActive
        ? {
          icon: <LoaderCircle className="spin" size={18} />,
          label: "Discovery is still running",
          message: `${discovery?.found_count ?? 0} active devices found so far. Results will populate here as the agent reports progress.`,
          action: undefined,
        }
        : discovery?.status === "failed" || discovery?.status === "cancelled"
          ? {
            icon: <ShieldAlert size={18} />,
            label: discovery.status === "failed" ? "Discovery failed" : "Discovery stopped",
            message: discovery.error ?? "No completed host records were available. Review the run status above.",
            action: undefined,
          }
        : discovery
          ? {
            icon: <Search size={18} />,
            label: "No matching devices",
            message: "No discovered host matches the current search text.",
            action: <button className="button secondary" onClick={() => setQuery("")}><X size={14} />Clear search</button>,
          }
          : {
            icon: <Network size={18} />,
            label: "Run discovery to populate devices",
            message: "Select an agent scope and start discovery. Authorized hosts will appear here for scanning.",
            action: <button className="button primary" disabled={!canDiscover} onClick={() => openDiscovery("selected")}><Radar size={15} />Run discovery</button>,
          };

  const devicesPanel = (
    <section className="panel" id="devices">
      <PanelHeader title="Discovered devices" subtitle={discovery ? "Review discovered hosts and select authorized scan targets." : "Choose an approved network and run discovery."} action={discovery?.devices.length ? <div className="device-tools"><div className="search-box"><Search size={15} /><input aria-label="Search devices" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search devices" /></div><span className="selection-count">{selectedIds.length} selected</span></div> : null} />
      <ScopeControl agent={selectedAgent} scopeOptions={scopeOptions} selectedScope={selectedScope} discoveryActive={discoveryActive} canDiscover={canDiscover} onScopeChange={setSelectedScope} onDiscover={openDiscovery} />
      <DiscoveryCallout discovery={discovery} scannerSetupRequired={scannerSetupRequired} scopeSetupRequired={scopeSetupRequired} scopeIssueTitle={scopeIssueTitle} scopeError={scopeError} canOperate={canOperate} onStop={() => void stopDiscovery()} />
      <DiscoveryDelta discovery={discovery} />
      {discovery && <KnownHostResults discovery={discovery} />}
      {allSelectableDeviceIds.length > 0 && <div className="scan-toolbar"><div className="segmented" aria-label="Scan profile">{SCAN_PROFILE_OPTIONS.map((item) => <button key={item.value} className={profile === item.value ? "selected" : ""} title={!approvedScanProfiles.includes(item.value) ? "Not approved for every selected network" : scanActive ? "Wait for the current scan to finish" : item.hint} disabled={scanActive || !approvedScanProfiles.includes(item.value)} onClick={() => setProfile(item.value)}>{item.label}</button>)}</div><div className="scan-selection-actions"><button className="button secondary" disabled={firstQuickSelectionIds.length === 0} onClick={() => replaceSelection(firstQuickSelectionIds)}>First {Math.min(QUICK_SCAN_COUNT, firstQuickSelectionIds.length) || QUICK_SCAN_COUNT}</button><button className="button secondary" disabled={lastQuickSelectionIds.length === 0} onClick={() => replaceSelection(lastQuickSelectionIds)}>Last {Math.min(QUICK_SCAN_COUNT, lastQuickSelectionIds.length) || QUICK_SCAN_COUNT}</button><button className="button secondary" disabled={selectableDeviceIds.length === 0} onClick={toggleAllVisible}>{allVisibleSelected ? "Unselect visible" : `Visible ${selectableDeviceIds.length}`}</button><button className="button secondary" disabled={allSelectableDeviceIds.length === 0} onClick={toggleAllDiscovered}>{allDiscoveredSelected ? "Unselect all" : `All ${allSelectableDeviceIds.length}`}</button><button className="button ghost" disabled={selectedIds.length === 0} onClick={() => setSelectedIds([])}>Clear</button><button className={`button primary scan-launch${scanActive ? " running" : ""}`} title={scanActive ? "A scan is already active for this probe" : approvedScanProfiles.length === 0 && selectedIds.length ? "No scan profile is approved for every selected target" : undefined} disabled={!canScanSelected} onClick={() => void startScan()}>{scanActive || busy ? <LoaderCircle className="spin" size={15} /> : <Radar size={15} />}{activeScan ? `${activeScan.cancel_requested ? "Cancelling" : activeScan.status === "queued" ? "Queued" : "Scanning"} ${scanFinishedCount(activeScan)}/${activeScan.total}` : busy ? "Starting..." : `Scan ${selectedIds.length || "selected"}`}</button></div></div>}
      {selectedIds.length > 0 && approvedScanProfiles.length === 0 && <div className="selection-advice"><ShieldAlert size={14} /><span>No common scan profile is approved for these targets. Select targets from one approved network or update Site policy.</span></div>}
      {activeScan && <div className="scan-active-actions"><span>{activeScan.running ? `${activeScan.running} running` : "Waiting for probe"} | {elapsedLabel(activeScan.started_at ?? activeScan.created_at)} elapsed{activeScan.last_progress_at ? ` | updated ${timeAgo(activeScan.last_progress_at)}` : ""}</span><button className="button danger" disabled={!canOperate || busy || activeScan.cancel_requested} onClick={() => void cancelActiveScan()}><Square size={14} />{activeScan.cancel_requested ? "Cancelling" : "Cancel scan"}</button></div>}
      {allSelectableDeviceIds.length > 0 && profile === "full_tcp" && selectedIds.length > 1 && <div className="selection-advice"><ShieldAlert size={14} /><span>Full TCP is limited to one selected target. Unselect the others before starting.</span></div>}
      {allSelectableDeviceIds.length > QUICK_SCAN_COUNT && <div className="selection-advice"><ShieldAlert size={14} /><span>Discovery found {allSelectableDeviceIds.length} selectable devices. Use First {QUICK_SCAN_COUNT}, Last {QUICK_SCAN_COUNT}, Visible results, or All devices. Large scans run in agent-controlled batches and progress appears below.</span></div>}
      {(discovery || loading) && <div className="table-scroll"><table><thead><tr><th className="check-cell"><input type="checkbox" aria-label="Select visible devices" checked={allVisibleSelected} disabled={selectableDeviceIds.length === 0} onChange={toggleAllVisible} /></th><th>Device</th><th>IP / MAC</th><th>Scope</th><th>Type / Vendor</th><th>Status</th><th>Scan</th><th aria-label="Details" /></tr></thead><tbody>{loading || filteredDevices.length === 0 ? <EmptyRow columns={8} {...deviceEmptyState} /> : filteredDevices.map((device) => { const checked = selectedIds.includes(device.device_id); const result = resultByDevice.get(device.device_id); const name = deviceDisplayName(device); return <tr key={device.device_id}><td className="check-cell"><input type="checkbox" aria-label={`Select ${name}`} checked={checked} disabled={device.is_agent} onChange={() => toggleDevice(device)} /></td><td><div className="device-name"><span className="device-icon"><HardDrive size={15} /></span><div><strong>{name}</strong><small>{deviceIdentitySubtitle(device)}</small></div></div></td><td><strong>{device.ip}</strong><small>{device.mac ?? "MAC unavailable"}</small></td><td><code>{device.discovery_scope ?? discovery?.network ?? "Unknown"}</code></td><td><strong>{device.device_type ? titleCase(device.device_type) : "Unknown"}</strong><small>{device.vendor ?? "Unknown vendor"}</small></td><td><Status value="online" label="Discovered" /></td><td><Status value={result?.status ?? "not_scanned"} /></td><td><button className="icon-button small" title="Device details" onClick={() => setDetail(device)}><ChevronRight size={15} /></button></td></tr>; })}</tbody></table></div>}
    </section>
  );

  const latestScanPanel = (
    <section className="panel scan-progress" id="scans">
      <PanelHeader title="Latest scan" subtitle={scan ? `${scanProfileLabel(scan.profile)} - ${scan.total} selected devices` : "Run a scan from Network Scanner to populate this panel."} action={scan ? <Status value={scan.status} /> : <Status value="idle" />} />
      {scan ? <>
        <div className="progress-grid"><ProgressStat label="Queued" value={scan.queued} /><ProgressStat label="Running" value={scan.running} /><ProgressStat label="Completed" value={scan.completed} /><ProgressStat label="Failed" value={scan.failed} /><ProgressStat label="Cancelled" value={scan.cancelled} /></div>
        {scan.stage === "command_failed" && (scanEvidenceCoverage?.missing ?? 0) > 0 && <div className="discovery-callout warning" role="status"><span className="discovery-callout-icon"><ShieldAlert size={18} /></span><div><strong>Scan command stopped early</strong><span>{scanEvidenceCoverage?.saved} of {scan.total} targets returned host results. {scanEvidenceCoverage?.missing} have no result; do not treat them as scanned or clear.</span></div></div>}
        <div className="scan-actions"><span>{titleCase(scan.stage ?? scan.status)} | {elapsedLabel(scan.started_at ?? scan.created_at, scan.completed_at)} {scan.completed_at ? "duration" : "elapsed"}{scan.last_progress_at ? ` | updated ${timeAgo(scan.last_progress_at)}` : ""}</span><a className="button secondary" href={`/network-agent/reports/${scan.scan_id}`}><ExternalLink size={15} />View</a><button className="button secondary" disabled={jsonExportingId !== null} onClick={downloadReport}>{jsonExportingId === scan.scan_id ? <LoaderCircle className="spin" size={15} /> : <Download size={15} />}{jsonExportingId === scan.scan_id ? "Exporting" : "JSON"}</button><button className="button secondary" disabled={pdfExportingId !== null} onClick={() => void exportScanPdf(scan)}>{pdfExportingId === scan.scan_id ? <LoaderCircle className="spin" size={15} /> : <FileText size={15} />}{pdfExportingId === scan.scan_id ? "Creating" : "PDF"}</button></div>
        <div className="scan-target-status" aria-label="Target progress">{scan.targets.filter((target) => target.status === "running" || ["failed", "timed_out", "cancelled"].includes(target.status)).slice(0, 5).map((target) => { const result = scan.results.find((item) => item.device_id === target.device_id); return <div key={target.device_id}><strong>{target.hostname || target.ip}</strong><Status value={target.status} /><span>{result?.error ?? (target.status === "running" ? "Waiting for this host scan to finish" : "No host result was saved for this target")}</span></div>; })}</div>
      </> : <div className="empty-panel-state"><EmptyState icon={<ShieldCheck size={18} />} title="No scan has been started" message="Use Network Scanner to discover devices, select authorized targets, and create the first evidence report." action={<button className="button primary" onClick={() => navigateView("scanner")}><Radar size={15} />Open scanner</button>} /></div>}
    </section>
  );

  const healthColumn = (
    <aside className="health-column">
      <section className={`health-panel ${selectedAgentOffline ? "offline" : scannerSetupRequired || scopeSetupRequired || selectedAgent?.discovery_requires_authorization || discovery?.status === "failed" ? "attention" : ""}`}>
        <span className="eyebrow">AGENT POSTURE</span>
        <div className="health-score"><strong>{selectedAgentOffline ? "Offline" : scannerSetupRequired ? "Setup required" : scopeSetupRequired ? scopeHealthLabel : selectedAgent?.discovery_requires_authorization ? "Authorization required" : discovery?.status === "failed" ? "Attention" : ["completed", "partial"].includes(discovery?.status ?? "") ? "Ready" : "Pending"}</strong>{selectedAgentOffline || scannerSetupRequired || scopeSetupRequired || selectedAgent?.discovery_requires_authorization || discovery?.status === "failed" ? <ShieldAlert size={21} /> : <ShieldCheck size={21} />}</div>
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
      <LiveOperation discovery={discovery} scan={scan} canOperate={canOperate} onStop={() => void stopDiscovery()} />
      <section className="guidance" id="activity"><span className="eyebrow">OPERATIONS</span><h3>{selectedAgentOffline ? "Agent offline" : scannerSetupRequired ? "Scanner setup required" : scopeSetupRequired ? scopeIssueTitle : scan?.running ? `${scan.running} devices scanning` : discoveryActive ? "Discovering devices" : discovery?.status === "failed" ? "Discovery needs attention" : "Agent standing by"}</h3><p>{selectedAgentOffline ? "Waiting for the next authenticated heartbeat." : scannerSetupRequired ? "Install Nmap and Npcap to enable network collection." : scopeSetupRequired ? scopeError : scan ? `${scan.completed + scan.failed + scan.cancelled} of ${scan.total} device jobs finished.` : discovery?.status === "failed" ? discovery.error : "Commands are delivered through outbound HTTPS."}</p></section>
    </aside>
  );

  const workerJobPanel = (
    <section className="panel history-table-panel" aria-label="Central worker jobs">
      <PanelHeader title="Central jobs" subtitle={`${historySiteName} - Web checks, advanced assessments, and SSH inventory.`} action={<span className="quiet-badge">{workerJobs.length} RECENT</span>} />
      <div className="table-scroll"><table><thead><tr><th>Operation</th><th>Target</th><th>Status</th><th>Updated</th><th>Result</th><th aria-label="Open evidence" /></tr></thead><tbody>{workerJobsLoading ? <EmptyRow columns={6} icon={<LoaderCircle className="spin" size={18} />} label="Loading central jobs" message="Retrieving site worker activity." /> : workerJobsError ? <EmptyRow columns={6} icon={<ShieldAlert size={18} />} label="Central jobs unavailable" message={workerJobsError} action={<button className="button secondary" onClick={() => setWorkerJobsRefresh((value) => value + 1)}><RefreshCw size={14} />Retry</button>} /> : workerJobs.length === 0 ? <EmptyRow columns={6} icon={<Server size={18} />} label="No central jobs for this site" message="Open a scanned asset to request an approved web check, advanced assessment, or SSH inventory." action={<button className="button secondary" onClick={() => navigateView("assets")}><HardDrive size={14} />Open assets</button>} /> : workerJobs.map((job) => <tr key={job.job_id}><td><strong>{job.inventory_profile ? "SSH inventory" : job.assessment_profile ? "Advanced assessment" : job.template_profile ? "Web check" : "Central job"}</strong><small>{job.profile}</small></td><td><strong>{job.target_ip}{job.target_port ? `:${job.target_port}` : ""}</strong><small>{job.target_scheme ?? job.inventory_profile ?? job.assessment_profile ?? job.template_profile ?? ""}</small></td><td><Status value={job.status} /></td><td>{timeAgo(job.updated_at)}</td><td className="worker-job-summary">{job.summary ?? (job.status === "leased" ? job.phase ?? "Running" : "Awaiting worker")}</td><td>{job.source_asset_id && <a className="button secondary compact" href={`/network-agent?asset=${encodeURIComponent(job.source_asset_id)}#assets`}><ExternalLink size={13} />Asset</a>}</td></tr>)}</tbody></table></div>
    </section>
  );

  const historyHero = (
    <section className="history-hero">
      <div className="history-hero-copy">
        <span className="eyebrow">SCAN EVIDENCE</span>
        <h2>{latestHistoryScan ? ["queued", "running", "cancelling"].includes(latestHistoryScan.status) ? "Scan in progress" : "Review saved scans" : dataLoadError ? "History unavailable" : "No scans yet"}</h2>
        <p>{dataLoadError && !latestHistoryScan ? "Check the API connection and retry before interpreting this as an empty history." : historyHeroCopy}</p>
        <div className="history-hero-actions">
          <button className="button primary" onClick={() => navigateView("scanner")}><Radar size={15} />Open scanner</button>
          {latestHistoryScan && <a className="button secondary" href={`/network-agent/reports/${latestHistoryScan.scan_id}`}><ExternalLink size={15} />View latest</a>}
        </div>
      </div>
      <div className="history-hero-stats">
        {historyStats.map((item) => (
          <div key={item.label}><span>{item.label}</span><strong>{item.value}</strong></div>
        ))}
      </div>
    </section>
  );

  const historyGraphs = (
    <section className="graph-grid history-graph-grid" aria-label="Scan history graphs">
      <GraphCard eyebrow="REPORT TREND" title="Findings per scan">
        <TrendBars rows={scanTrendRows} emptyLabel="No scan trend is available yet." />
      </GraphCard>
      <GraphCard eyebrow="SEVERITY MIX" title="All findings">
        <SeverityStack rows={historySeverityRows} emptyLabel="No findings have been recorded." />
      </GraphCard>
    </section>
  );

  const historyTimeline = (
    <section className="history-timeline-panel">
      <div className="scanner-section-header">
        <div><span className="eyebrow">REPORT TIMELINE</span><h2>Stored scan reports</h2></div>
      </div>
      <div className="history-timeline">
        {scans.length === 0 ? (
          <div className="history-empty-state">{dataLoadError ? <EmptyState icon={<ShieldAlert size={18} />} title="Scan history unavailable" message={dataLoadError} action={<button className="button secondary" onClick={() => void load()}><RefreshCw size={14} />Retry</button>} /> : <EmptyState icon={<History size={18} />} title="No scans recorded" message="Start from Network Scanner to create the first saved report." />}</div>
        ) : scans.map((item, index) => {
          const findings = scanFindingCount(item);
          const highFindings = scanHighFindingCount(item);
          const coverage = scanResultCoverage(item);
          const progress = coverage.percent;
          return (
            <article className={`history-card ${index === 0 ? "latest" : ""}`} key={item.scan_id}>
              <div className="history-card-header">
                <div><span>{index === 0 ? "Latest scan" : `Scan ${scans.length - index}`}</span><strong>{scanProfileLabel(item.profile)}</strong><small>{item.scan_id}</small></div>
                <Status value={item.status} />
              </div>
              <div className="history-card-origin">
                <Server size={14} />
                <div>
                  <strong>Scan origin: {item.scan_origin?.hostname ?? "Probe snapshot unavailable"}</strong>
                  {item.scan_origin && <span>{item.scan_origin.local_ip ?? "IP not reported"} | {item.scan_origin.subnet ?? "Subnet not reported"} | {item.scan_origin.os_name} | v{item.scan_origin.agent_version} | heartbeat {item.scan_origin.last_heartbeat_at ? new Date(item.scan_origin.last_heartbeat_at).toLocaleString() : "not recorded"}</span>}
                  {item.scan_origin?.source === "current_heartbeat" && <small>Latest probe record; scan-time IP was not saved.</small>}
                  {!item.scan_origin && <small>Probe ID {item.agent_id} | scan-time hostname and IP not recorded.</small>}
                </div>
              </div>
              <div className="history-card-meta">
                <div><span>Targets</span><strong>{item.total}</strong></div>
                <div><span>Host results</span><strong>{coverage.saved} / {item.total}</strong></div>
                <div><span>Findings</span><strong>{findings}</strong></div>
                <div><span>High</span><strong>{highFindings}</strong></div>
              </div>
              <div className="history-progress"><span style={{ width: `${progress}%` }} /></div>
              <div className="history-card-footer">
                <span>Started {new Date(item.started_at ?? item.created_at).toLocaleString()}</span>
                <span>{item.completed_at ? `Ended ${new Date(item.completed_at).toLocaleString()}` : "Completion pending"}</span>
                <a className="button secondary" href={`/network-agent/reports/${item.scan_id}`}><ExternalLink size={14} />View</a>
                <button className="button secondary" disabled={jsonExportingId !== null} onClick={() => void downloadScanReport(item)}>{jsonExportingId === item.scan_id ? <LoaderCircle className="spin" size={14} /> : <Download size={14} />}{jsonExportingId === item.scan_id ? "Exporting" : "JSON"}</button>
                <button className="button secondary" disabled={pdfExportingId !== null} onClick={() => void exportScanPdf(item)}>{pdfExportingId === item.scan_id ? <LoaderCircle className="spin" size={14} /> : <FileText size={14} />}{pdfExportingId === item.scan_id ? "Creating" : "PDF"}</button>
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );

  const historyView = (
    <div className="view-stack history-view">
      {historyHero}
      {historyGraphs}
      {historyTimeline}
      {workerJobPanel}
    </div>
  );

  const scannerHero = (
    <section className={`scanner-hero ${!discovery && !scan ? "compact" : ""} ${selectedAgentOffline ? "offline" : scannerSetupRequired || scopeSetupRequired ? "attention" : ""}`}>
      <div className="scanner-hero-copy">
        <span className="eyebrow">NETWORK SCANNER</span>
        <h2>{scannerHeroTitle}</h2>
        <p>{scannerHeroCopy}</p>
        {scannerSetupRequired && <div className="scanner-hero-actions"><a className="button primary" href="https://nmap.org/download.html" target="_blank" rel="noreferrer"><Download size={15} />Nmap + Npcap</a></div>}
      </div>
      {(discovery || scan) && <div className="scanner-hero-stats">
        {scannerStats.map((item) => (
          <div key={item.label}>
            <span>{item.label}</span>
            <strong>{item.value}</strong>
          </div>
        ))}
      </div>}
    </section>
  );

  const scannerAgentStrip = (
    <section className="scanner-agent-strip">
      <div className="scanner-section-header">
        <div><span className="eyebrow">PROBE</span><h2>{agents.length > 1 ? "Select the probe for discovery" : "Connected probe"}</h2></div>
      </div>
      {(agents.length > 1 || !selectedAgent) && <div className="scanner-agent-grid">
        {agents.length === 0 ? (
          <div className="scanner-empty-card">{dataLoadError ? <EmptyState icon={<ShieldAlert size={18} />} title="Probes unavailable" message={dataLoadError} action={<button className="button secondary" onClick={() => void load()}><RefreshCw size={14} />Retry</button>} /> : <EmptyState icon={<Server size={18} />} title="No collector enrolled" message="Create a token, download the agent, and install it on a Windows machine. This scanner page will unlock after heartbeat." action={<button className="button primary" disabled={!canAdmin} onClick={() => setAddOpen(true)}><Plus size={15} />Enrollment token</button>} />}</div>
        ) : agents.map((item) => (
          <button className={`agent-card-button ${item.agent_id === selectedAgentId ? "active" : ""} ${item.status === "offline" ? "offline" : ""}`} key={item.agent_id} onClick={() => selectAgent(item.agent_id)}>
            <span className="agent-card-icon"><Server size={16} /></span>
            <span className="agent-card-copy">
              <strong>{item.label}</strong>
              <small>{item.hostname} - {item.subnet ?? "Awaiting network"}</small>
            </span>
            <Status value={item.status} />
          </button>
        ))}
      </div>}
      {selectedAgent && <div className="scanner-origin-line"><Server size={14} /><strong>Scanning from</strong><span>{selectedAgent.hostname}</span><code>{selectedAgent.local_ip ?? "IP not reported"}</code><span>{selectedAgent.site_name ?? "Site pending"} / {selectedAgent.subnet ?? "Network pending"}</span><small>{selectedAgent.os_name} / v{selectedAgent.agent_version} / {selectedAgent.last_heartbeat_at ? `heartbeat ${timeAgo(selectedAgent.last_heartbeat_at)}` : "heartbeat pending"}</small></div>}
    </section>
  );

  const scanPlanPanel = (
    <section className="scan-plan-panel">
      <div className="scanner-section-header compact">
        <div><span className="eyebrow">SCAN PLAN</span><h2>Selected targets</h2></div>
      </div>
      <div className="scan-plan-rows">
        {scanPlanRows.map((item) => (
          <div key={item.label}><span>{item.label}</span><strong>{item.value}</strong></div>
        ))}
      </div>
      <p className="scan-profile-scope">{selectedProfileOption.hint}</p>
      {profile === "network_services" && <details className="scan-profile-ports"><summary>Exact ports</summary><p>TCP: {NETWORK_SERVICE_TCP_PORTS.join(", ")}</p><p>UDP: {NETWORK_SERVICE_UDP_PORTS.join(", ")}</p></details>}
      {profile === "full_tcp" && <p className="scan-profile-scope">One selected target only. A separate confirmation is required. Unlisted ports are not proven closed.</p>}
    </section>
  );

  const scannerView = (
    <div className="view-stack scanner-view">
      {scannerHero}
      <SiteScopePanel
        key={selectedSiteId}
        sites={sites}
        siteId={selectedSiteId}
        scopes={scopes}
        probe={selectedAgent}
        busy={busy}
        editable={canAdmin}
        onSelectSite={selectSite}
        onCreateSite={async (name, owner, description) => {
          setBusy(true);
          try {
            const site = await api.createSite(name, owner, description);
            setSites((current) => [...current, site]);
            selectSite(site.site_id);
            return true;
          } catch (cause) {
            setError(cause instanceof Error ? cause.message : "Site could not be created");
            return false;
          } finally { setBusy(false); }
        }}
        onApprove={async (scope) => {
          if (!selectedSiteId) return false;
          setBusy(true);
          try {
            const approved = await api.approveScope(selectedSiteId, scope);
            setScopes((current) => [...current.filter((item) => item.scope_id !== approved.scope_id), approved]);
            await load();
            return true;
          } catch (cause) {
            setError(cause instanceof Error ? cause.message : "Network could not be approved");
            return false;
          } finally { setBusy(false); }
        }}
        onRemove={async (scopeId) => {
          if (!selectedSiteId) return;
          setBusy(true);
          try {
            await api.removeScope(selectedSiteId, scopeId);
            setScopes((current) => current.filter((item) => item.scope_id !== scopeId));
            await load();
          } catch (cause) {
            setError(cause instanceof Error ? cause.message : "Approval could not be removed");
          } finally { setBusy(false); }
        }}
      />
      {scannerAgentStrip}
      {(scopeReady || discovery || scan) && <div className={`scanner-layout ${selectedIds.length ? "" : "solo"}`}>
        <div className="primary-column">{devicesPanel}{scan && latestScanPanel}</div>
        {selectedIds.length > 0 && <div className="scanner-side">{scanPlanPanel}</div>}
      </div>}
      {agents.length > 0 && <details className="scanner-fleet-details"><summary>Probe fleet and details</summary>{agentFleetPanel}</details>}
    </div>
  );
  const settingsRows = [
    { label: "API endpoint", value: API_URL || "Same origin", copy: API_URL || undefined },
    { label: "Agent server", value: AGENT_SERVER_URL, copy: AGENT_SERVER_URL },
    { label: "Refresh cadence", value: "Every 3 seconds" },
    { label: "Selected agent", value: selectedAgent?.label ?? "No agent selected" },
    { label: "Agent version", value: selectedAgent?.agent_version ?? "Waiting for install" },
  ];
  const settingsMenu = (
    <section className="settings-panel" id="settings-panel" role="dialog" aria-label="Console settings">
      <div className="settings-panel-header">
        <div>
          <span className="eyebrow">SETTINGS</span>
          <h2>Console settings</h2>
        </div>
        <button className="icon-button small" type="button" title="Close settings" onClick={() => setSettingsOpen(false)}><X size={14} /></button>
      </div>
      <div className={`settings-health ${onlineCount > 0 ? "" : "offline"}`}>
        <span className={`status-dot ${onlineCount > 0 ? "" : "offline"}`} />
        <div>
          <strong>{onlineCount > 0 ? "Local control plane online" : "Waiting for an online agent"}</strong>
          <small>{onlineCount} of {agents.length} enrolled agent{agents.length === 1 ? "" : "s"} online</small>
        </div>
      </div>
      <div className="settings-list">
        {settingsRows.map((row) => (
          <div className="settings-row" key={row.label}>
            <span>{row.label}</span>
            <code>{row.value}</code>
            {row.copy && <button type="button" title={`Copy ${row.label}`} onClick={() => { if (row.copy) void navigator.clipboard.writeText(row.copy); }}><Clipboard size={13} /></button>}
          </div>
        ))}
      </div>
      <div className="settings-actions">
        <button className="button secondary" type="button" onClick={() => { void load(); setSettingsOpen(false); }}><RefreshCw size={14} />Refresh</button>
        {canAdmin && <button className="button secondary" type="button" onClick={() => { setAddOpen(true); setSettingsOpen(false); }}><Plus size={14} />Token</button>}
        {canAdmin && session?.auth_required && <a className="button secondary" href="/network-agent/users"><Users size={14} />Users</a>}
        {canAdmin && <button className="button secondary" type="button" onClick={() => { setWorkersOpen(true); setSettingsOpen(false); }}><Server size={14} />Workers</button>}
        {session?.auth_required && <a className="button secondary" href="/network-agent/account"><Settings size={14} />Account</a>}
        <a className="button primary" href="/downloads/agent/ForgeSec-Network-Agent-Setup.exe" download onClick={() => setSettingsOpen(false)}><Download size={14} />Agent</a>
        {session?.auth_required && <button className="button secondary" type="button" onClick={() => void api.logout().then(() => window.location.assign("/login"))}><LogOut size={14} />Sign out</button>}
      </div>
    </section>
  );

  return (
    <div className={`app-shell ${sidebarCollapsed ? "sidebar-collapsed" : ""}`}>
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-logo-frame">
            <img className="brand-logo" src="/logos/forge-sec-logo.png" alt="ForgeSec" />
          </span>
          <span className="brand-copy">
            <span className="brand-title">ForgeSec</span>
            <span className="brand-subtitle">Network Agent</span>
          </span>
          <button
            className="sidebar-toggle"
            type="button"
            aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            aria-pressed={sidebarCollapsed}
            title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            onClick={() => setSidebarCollapsed((current) => !current)}
          >
            {sidebarCollapsed ? <PanelLeftOpen size={15} /> : <PanelLeftClose size={15} />}
          </button>
        </div>
        <nav aria-label="Primary navigation">
          <button className={activeView === "overview" ? "active" : ""} type="button" aria-label="Overview" title="Overview" onClick={() => navigateView("overview")}><MonitorDot size={17} /><span>Overview</span></button>
          <button className={activeView === "scanner" ? "active" : ""} type="button" aria-label="Network Scanner" title="Network Scanner" onClick={() => navigateView("scanner")}><Network size={17} /><span>Network Scanner</span></button>
          <button className={activeView === "assets" ? "active" : ""} type="button" aria-label="Assets" title="Assets" onClick={() => navigateView("assets")}><HardDrive size={17} /><span>Assets</span></button>
          <button className={activeView === "history" ? "active" : ""} type="button" aria-label="Scan History" title="Scan History" onClick={() => navigateView("history")}><History size={17} /><span>Scan History</span></button>
        </nav>
        <div className="sidebar-status"><span className="status-dot" />Local control plane</div>
      </aside>

      <main className="workspace">
        <header className="topbar">
          <div><span className="eyebrow">{viewCopy.eyebrow}</span><h1>{viewCopy.title}</h1></div>
          <div className="top-actions">
            {activeView === "scanner" && agents.length > 0 && canAdmin && <button className="button secondary" type="button" onClick={() => setAddOpen(true)}><Plus size={15} />Add probe</button>}
            {activeView !== "assets" && <button className="icon-button" type="button" title="Refresh" aria-label="Refresh" onClick={() => void load()}><RefreshCw size={16} /></button>}
            <div className="settings-menu" ref={settingsRef}>
              <button className={`icon-button ${settingsOpen ? "active" : ""}`} type="button" title="Settings" aria-haspopup="dialog" aria-expanded={settingsOpen} aria-controls="settings-panel" onClick={() => setSettingsOpen((current) => !current)}><Settings size={16} /></button>
              {settingsOpen && settingsMenu}
            </div>
            <div className="local-user"><span>{session?.user?.email.slice(0, 2).toUpperCase() ?? "OC"}</span><div><strong>{session?.user?.email ?? "Local operator"}</strong><small>{session?.user?.role ?? "Local access"}</small></div></div>
          </div>
        </header>

        {error && <div className="error-banner"><ShieldAlert size={17} /><span>{error}</span><button title="Dismiss" onClick={() => setError(null)}><X size={15} /></button></div>}
        {showDataLoadBanner && <div className="error-banner" role="alert"><ShieldAlert size={17} /><span>Data refresh failed: {dataLoadError}</span><button type="button" title="Retry data refresh" onClick={() => void load()}><RefreshCw size={15} /></button></div>}
        {exportError && <div className="error-banner" role="alert"><ShieldAlert size={17} /><span>{exportError}</span><button title="Dismiss" onClick={() => setExportError(null)}><X size={15} /></button></div>}

        {activeView === "overview" && <div className="view-stack">{metricsSection}{overviewHero}{overviewInsights}{overviewGraphs}<div className="content-grid"><div className="primary-column">{latestScanPanel}</div>{healthColumn}</div></div>}
        {activeView === "scanner" && scannerView}
        {activeView === "assets" && <AssetInventory sites={sites} defaultSiteId={selectedSiteId} canOperate={canOperate} canAdmin={canAdmin} />}
        {activeView === "history" && historyView}
      </main>

      {addOpen && canAdmin && <EnrollmentModal sites={sites} defaultSiteId={selectedSiteId} enrollment={enrollment} release={agentRelease} busy={busy} onClose={() => { setAddOpen(false); setEnrollment(null); }} onCreate={async (label, siteId, newSite) => { setBusy(true); try { let resolvedSiteId = siteId; if (newSite) { const created = await api.createSite(newSite, "", ""); resolvedSiteId = created.site_id; setSites((current) => [...current, created]); selectSite(created.site_id); } setEnrollment(await api.createEnrollment(label, resolvedSiteId)); if (!newSite) await load(); } catch (cause) { setError(cause instanceof Error ? cause.message : "Token could not be created"); } finally { setBusy(false); } }} />}
      {workersOpen && canAdmin && <WorkerManagement sites={sites} defaultSiteId={selectedSiteId} onClose={() => setWorkersOpen(false)} />}
      {revokeTarget && canAdmin && <RevokeAgentModal agent={revokeTarget} busy={busy} error={revokeError} onClose={() => { setRevokeTarget(null); setRevokeError(null); }} onRevoke={async (reason) => { setBusy(true); setRevokeError(null); try { await api.revokeAgent(revokeTarget.agent_id, reason); setRevokeTarget(null); await load(); } catch (cause) { setRevokeError(cause instanceof Error ? cause.message : "Probe could not be revoked"); } finally { setBusy(false); } }} />}
      {authorizeOpen && <AuthorizationModal agent={selectedAgent} scope={discoveryMode === "all" ? selectedAgent?.subnet ?? "Connected network" : selectedScope} mode={discoveryMode} segmentCount={discoveryMode === "all" ? scopeOptions.length : 1} knownTargetsText={knownTargetsText} onKnownTargetsChange={(value) => { setKnownTargetsText(value); setAuthorizationError(null); }} error={authorizationError} busy={busy} onClose={() => setAuthorizeOpen(false)} onConfirm={() => void startDiscovery()} />}
      {fullTcpOpen && selectedIds.length === 1 && <FullTcpModal targetIp={discovery?.devices.find((item) => item.device_id === selectedIds[0])?.ip ?? "Target unavailable"} probeName={selectedAgent?.hostname ?? "Selected probe"} error={scanRequestError} busy={busy} onClose={() => { setFullTcpOpen(false); setScanRequestError(null); }} onConfirm={() => void startScan(true)} />}
      {detail && <DeviceDrawer key={detail.device_id} agentId={selectedAgentId} agentStatus={selectedAgent?.status} device={detail} result={resultByDevice.get(detail.device_id)} scanId={scan?.scan_id} canOperate={canOperate} onClose={() => setDetail(null)} />}
    </div>
  );
}

function ScopeControl({ agent, scopeOptions, selectedScope, discoveryActive, canDiscover, onScopeChange, onDiscover }: { agent?: AgentRecord; scopeOptions: string[]; selectedScope: string; discoveryActive: boolean; canDiscover: boolean; onScopeChange: (scope: string) => void; onDiscover: (mode: "selected" | "all") => void }) {
  if (!agent || scopeOptions.length === 0) return null;
  return <div className="scope-control"><div><span>Connected network</span><strong>{agent.subnet ?? agent.discovery_network}</strong></div><label><span>Approved discovery scope</span><select value={selectedScope} disabled={discoveryActive} onChange={(event) => onScopeChange(event.target.value)}>{scopeOptions.map((scope) => <option key={scope} value={scope}>{scope}{scope === agent.discovery_recommended_scope ? " - Current segment" : ""}</option>)}</select></label><div className="scope-actions"><button className="button primary" disabled={!canDiscover || !selectedScope} onClick={() => onDiscover("selected")}><Radar size={15} />Discover selected</button>{agent.discovery_all_segments_available && scopeOptions.length > 1 && <button className="button secondary" disabled={!canDiscover} onClick={() => onDiscover("all")}><Network size={15} />Discover approved {scopeOptions.length}</button>}</div></div>;
}

function DiscoveryCallout({ discovery, scannerSetupRequired, scopeSetupRequired, scopeIssueTitle, scopeError, canOperate, onStop }: { discovery?: Discovery; scannerSetupRequired: boolean; scopeSetupRequired: boolean; scopeIssueTitle: string; scopeError: string | null; canOperate: boolean; onStop: () => void }) {
  if (scannerSetupRequired) return <div className="discovery-callout warning"><span className="discovery-callout-icon"><ShieldAlert size={18} /></span><div><strong>Scanner setup required</strong><span>Install Nmap with its included Npcap driver on this Windows agent.</span></div><a className="button secondary" href="https://nmap.org/download.html" target="_blank" rel="noreferrer"><Download size={15} />Nmap + Npcap</a></div>;
  const active = discovery && ["queued", "running", "cancelling"].includes(discovery.status);
  if (active && discovery) {
    const progress = discovery.progress_percent == null ? null : `${Math.round(discovery.progress_percent)}% checked`;
    const found = `${discovery.found_count} active ${discovery.found_count === 1 ? "device" : "devices"} found so far`;
    const segment = discovery.total_scopes > 1 ? `${Math.min(discovery.total_scopes, discovery.completed_scopes.length + discovery.failed_scopes.length + 1)} of ${discovery.total_scopes} segments` : discovery.current_scope;
    return <div className="discovery-callout active"><span className="discovery-callout-icon"><LoaderCircle className="spin" size={18} /></span><div><strong>{discovery.status === "cancelling" ? "Stopping discovery" : titleCase(discovery.stage)}</strong><span>{[segment, found, progress, `${elapsedLabel(discovery.started_at ?? discovery.created_at)} elapsed`].filter(Boolean).join(" | ")}</span></div><button className="button danger" disabled={!canOperate || discovery.cancel_requested} onClick={onStop}><Square size={14} />{discovery.cancel_requested ? "Stopping" : "Stop"}</button></div>;
  }
  if (discovery?.status === "failed") return <div className="discovery-callout warning"><span className="discovery-callout-icon"><ShieldAlert size={18} /></span><div><strong>Discovery could not start</strong><span>{discovery.error ?? "The discovery command failed before completion."}</span></div></div>;
  if (discovery && ["cancelled", "partial"].includes(discovery.status)) return <div className="discovery-callout warning"><span className="discovery-callout-icon"><Square size={16} /></span><div><strong>{discovery.status === "partial" ? "Discovery has partial results" : "Discovery stopped"}</strong><span>{discovery.error ?? (discovery.device_count ? `${discovery.device_count} observed devices were retained.` : "No completed host records were available.")}</span></div></div>;
  if (!scopeSetupRequired) return null;
  return <div className="discovery-callout warning"><span className="discovery-callout-icon"><ShieldAlert size={18} /></span><div><strong>{scopeIssueTitle}</strong><span>{scopeError}</span></div></div>;
}

function DiscoveryDelta({ discovery }: { discovery?: Discovery }) {
  const changes = discovery?.change_summary;
  if (!changes?.baseline_discovery_id) return null;
  return <details className="discovery-delta">
    <summary><History size={14} /><strong>Since previous discovery</strong><span>{changes.new_host_count} newly responding, {changes.not_observed_count} not observed</span></summary>
    <div className="discovery-delta-body">
      <small>Same probe and approved scope, compared with {changes.baseline_completed_at ? new Date(changes.baseline_completed_at).toLocaleString() : "the previous completed run"}. No response does not prove a device is offline.</small>
      {changes.new_hosts.length > 0 && <div><strong>Newly responding</strong>{changes.new_hosts.map((host) => <span key={host.ip}>{host.hostname || host.ip} ({host.ip})</span>)}</div>}
      {changes.not_observed_hosts.length > 0 && <div><strong>Not observed this time</strong>{changes.not_observed_hosts.map((host) => <span key={host.ip}>{host.hostname || host.ip} ({host.ip})</span>)}</div>}
    </div>
  </details>;
}

function KnownHostResults({ discovery }: { discovery: Discovery }) {
  if (!discovery.known_targets?.length) return null;
  const terminal = ["completed", "partial", "failed", "cancelled"].includes(discovery.status);
  const checks = discovery.follow_up_checks ?? [];
  const counts = ([
    ["Initial", checks.filter((item) => item.status === "already_discovered").length],
    ["Recovered", checks.filter((item) => item.status === "responsive").length],
    ["No response", checks.filter((item) => item.status === "no_response").length],
    ["Failed", checks.filter((item) => item.status === "error").length],
    [terminal ? "Not checked" : "Pending", Math.max(0, discovery.known_targets.length - checks.length)],
  ] satisfies Array<[string, number]>).filter((item) => item[1] > 0).map(([label, count]) => `${label} ${count}`).join(" | ");
  return <div className="known-host-results" role="region" aria-label="Known-host checks">
    <strong>Known-host checks</strong><small>{counts}</small>
    {discovery.known_targets.map((ip) => {
      const check = discovery.follow_up_checks?.find((item) => item.ip === ip);
      const label = check?.status === "already_discovered" ? "Observed" : check?.status === "responsive" ? "Recovered"
        : check?.status === "no_response" ? "No response"
          : check?.status === "error" ? "Check failed" : terminal ? "Not checked" : "Pending";
      const detail = check
        ? `${check.method === "initial_discovery" ? "Initial discovery" : "Targeted TCP/ICMP"} | ${new Date(check.checked_at).toLocaleString()}${check.reason ? ` | ${check.reason}` : ""}${check.error ? ` | ${check.error}` : ""}`
        : terminal ? "No check result was recorded" : "Waiting for discovery";
      return <div className="known-host-row" key={ip}><code>{ip}</code><Status value={check?.status ?? (terminal ? "not_scanned" : "queued")} label={label} /><span>{detail}{check?.status === "no_response" ? " | Not confirmed offline" : ""}</span></div>;
    })}
  </div>;
}

function LiveOperation({ discovery, scan, canOperate, onStop }: { discovery?: Discovery; scan?: Scan; canOperate: boolean; onStop: () => void }) {
  const discoveryActive = Boolean(discovery && ["queued", "running", "cancelling"].includes(discovery.status));
  const scanActive = Boolean(scan && ["queued", "running", "cancelling"].includes(scan.status));
  const showDiscovery = discoveryActive || (!scanActive && Boolean(discovery));
  const events = showDiscovery ? discovery?.events?.slice(-5) ?? [] : [];
  const status = discoveryActive ? discovery!.status : scanActive ? scan!.status : discovery?.status ?? scan?.status ?? "idle";
  const title = discoveryActive || (!scanActive && discovery) ? "Network discovery" : scanActive || scan ? "Device scan" : "No active operation";
  const summary = discoveryActive && discovery
    ? `${discovery.found_count} found | ${discovery.completed_scopes.length + discovery.failed_scopes.length} of ${discovery.total_scopes} segments finished | ${discovery.progress_percent == null ? "progress pending" : `${Math.round(discovery.progress_percent)}%`} | ${elapsedLabel(discovery.started_at ?? discovery.created_at)}`
    : scanActive && scan
      ? `${scan.completed + scan.failed + scan.cancelled} of ${scan.total} finished | ${elapsedLabel(scan.started_at ?? scan.created_at)} elapsed${scan.last_progress_at ? ` | updated ${timeAgo(scan.last_progress_at)}` : ""}`
      : discovery?.error ?? "The agent is waiting for an authorized command.";
  return <section className="live-operation"><div className="live-operation-header"><div><span className="eyebrow">LIVE OPERATION</span><h3>{title}</h3></div>{discoveryActive && discovery && <button className="icon-button small" title="Stop discovery" disabled={!canOperate || discovery.cancel_requested} onClick={onStop}><Square size={13} /></button>}</div><div className="operation-state"><Status value={status} /><span>{summary}</span></div>{showDiscovery && (discovery?.current_scope ?? discovery?.network) && <code className="operation-command"><Terminal size={13} />nmap -sn --host-timeout 30s --stats-every 2s {discovery?.current_scope ?? discovery?.network}</code>}<div className="operation-events">{events.length ? events.map((event) => <div key={event.event_id}><time>{new Date(event.occurred_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</time><span>{event.message}</span></div>) : <p>{scanActive ? "Device progress is summarized above." : "No operation events yet."}</p>}</div></section>;
}

function Metric({ icon, label, value, tone }: { icon: ReactNode; label: string; value: string; tone: string }) { return <div className="metric"><span className={`metric-icon ${tone}`}>{icon}</span><div><span>{label}</span><strong>{value}</strong></div></div>; }
function PanelHeader({ title, subtitle, action }: { title: string; subtitle: string; action: ReactNode }) { return <div className="panel-header"><div><h2>{title}</h2><p>{subtitle}</p></div>{action}</div>; }
function EmptyRow({ columns, label, message, icon, action }: { columns: number; label: string; message?: string; icon?: ReactNode; action?: ReactNode }) { return <tr><td className="empty-row" colSpan={columns}><EmptyState compact icon={icon ?? <Search size={18} />} title={label} message={message ?? "When data is available it will appear here automatically."} action={action} /></td></tr>; }
function Status({ value, label }: { value: string; label?: string }) { const tone = ["online", "completed", "up", "open", "responsive", "already_discovered"].includes(value) ? "success" : ["busy", "running", "queued", "cancelling", "partial", "medium", "unreachable", "timeout", "no_reply", "no_response"].includes(value) ? "warning" : ["failed", "offline", "cancelled", "timed_out", "critical", "high", "error"].includes(value) ? "danger" : "neutral"; return <span className={`status ${tone}`}><span />{label ?? titleCase(value)}</span>; }
function ProgressStat({ label, value }: { label: string; value: number }) { return <div><span>{label}</span><strong>{value}</strong></div>; }
function HealthLine({ label, value }: { label: string; value: string }) { return <div className="health-line"><span>{label}</span><strong>{value}</strong></div>; }

function EmptyState({ icon, title, message, action, compact }: { icon: ReactNode; title: string; message: string; action?: ReactNode; compact?: boolean }) {
  return <div className={`empty-state ${compact ? "compact" : ""}`}><span className="empty-state-icon">{icon}</span><div><strong>{title}</strong><p>{message}</p></div>{action && <div className="empty-state-actions">{action}</div>}</div>;
}

function GraphEmptyState({ label }: { label: string }) {
  return <div className="graph-empty-state"><EmptyState compact icon={<History size={18} />} title="No graph data yet" message={label} /></div>;
}

type HorizontalGraphRow = {
  label: string;
  value: number;
  detail: string;
  percent: number;
  tone: string;
};

type TrendGraphRow = {
  label: string;
  value: number;
  detail: string;
  percent: number;
  status: string;
};

type SeverityGraphRow = {
  label: string;
  value: number;
  tone: string;
};

function GraphCard({ eyebrow, title, children }: { eyebrow: string; title: string; children: ReactNode }) {
  return <section className="graph-card"><div className="graph-card-header"><span className="eyebrow">{eyebrow}</span><h2>{title}</h2></div>{children}</section>;
}

function HorizontalGraph({ rows, emptyLabel }: { rows: HorizontalGraphRow[]; emptyLabel: string }) {
  if (!rows.some((row) => row.value > 0 || row.percent > 0)) {
    return <GraphEmptyState label={emptyLabel} />;
  }
  return <div className="horizontal-graph">{rows.map((row) => <div className="horizontal-graph-row" key={row.label}><div><span>{row.label}</span><strong>{row.value}</strong></div><small>{row.detail}</small><div className="graph-track"><span className={row.tone} style={{ width: `${Math.max(0, row.percent)}%` }} /></div></div>)}</div>;
}

function TrendBars({ rows, emptyLabel }: { rows: TrendGraphRow[]; emptyLabel: string }) {
  if (rows.length === 0) return <GraphEmptyState label={emptyLabel} />;
  return <div className="trend-chart">{rows.map((row) => <div className="trend-bar" key={`${row.label}-${row.detail}`}><div className="trend-column"><span className={row.status} style={{ height: `${row.percent}%` }} /></div><strong>{row.value}</strong><small>{row.label}</small></div>)}<div className="trend-axis"><span>Oldest</span><span>Newest</span></div></div>;
}

function SeverityStack({ rows, emptyLabel }: { rows: SeverityGraphRow[]; emptyLabel: string }) {
  const total = rows.reduce((sum, row) => sum + row.value, 0);
  if (total === 0) return <GraphEmptyState label={emptyLabel} />;
  return <div className="severity-graph"><div className="severity-stack">{rows.filter((row) => row.value > 0).map((row) => <span className={row.tone} key={row.label} style={{ width: `${Math.max(4, (row.value / total) * 100)}%` }} />)}</div><div className="severity-legend">{rows.map((row) => <div key={row.label}><span className={row.tone} /><strong>{row.value}</strong><small>{row.label}</small></div>)}</div></div>;
}

function useModalKeyboard(onClose: () => void, busy: boolean) {
  const dialogRef = useRef<HTMLElement | null>(null);
  const closeRef = useRef(onClose);
  const busyRef = useRef(busy);
  closeRef.current = onClose;
  busyRef.current = busy;

  useEffect(() => {
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const dialog = dialogRef.current;
    if (dialog && !dialog.contains(document.activeElement)) {
      dialog.querySelector<HTMLElement>("input:not([type='hidden']), button")?.focus();
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape" && !busyRef.current) {
        event.preventDefault();
        closeRef.current();
      }
      if (event.key !== "Tab" || !dialog) return;
      const focusable = Array.from(dialog.querySelectorAll<HTMLElement>(
        "button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])",
      )).filter((element) => element.getClientRects().length > 0);
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (!dialog.contains(document.activeElement) || (event.shiftKey && document.activeElement === first)) {
        event.preventDefault();
        (event.shiftKey ? last : first).focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      if (previousFocus?.isConnected && !previousFocus.matches(":disabled")) previousFocus.focus();
      else document.querySelector<HTMLElement>(".top-actions button:not([disabled])")?.focus();
    };
  }, []);

  return dialogRef;
}

function EnrollmentModal({ sites, defaultSiteId, enrollment, release, busy, onClose, onCreate }: { sites: Site[]; defaultSiteId: string; enrollment: Enrollment | null; release: AgentReleaseInfo | null; busy: boolean; onClose: () => void; onCreate: (label: string, siteId: string, newSite: string) => Promise<void> }) {
  const [label, setLabel] = useState("Windows Network Probe");
  const [siteId, setSiteId] = useState(defaultSiteId || sites[0]?.site_id || "new");
  const [newSite, setNewSite] = useState("");
  const dialogRef = useModalKeyboard(onClose, busy);
  async function submit(event: FormEvent) { event.preventDefault(); await onCreate(label, siteId, siteId === "new" ? newSite.trim() : ""); }
  return <div className="modal-backdrop" role="presentation"><section ref={dialogRef} className="modal" role="dialog" aria-modal="true" aria-labelledby="enrollment-title"><div className="modal-header"><div><span className="eyebrow">ADD PROBE</span><h2 id="enrollment-title">Windows probe enrollment</h2></div><button className="icon-button" title="Close" onClick={onClose} disabled={busy}><X size={17} /></button></div>{enrollment ? <div className="token-result"><span>Server URL</span><div className="copy-field"><code>{AGENT_SERVER_URL}</code><button title="Copy server URL" onClick={() => void navigator.clipboard.writeText(AGENT_SERVER_URL)}><Clipboard size={15} /></button></div><span>One-time token</span><div className="copy-field"><code>{enrollment.enrollment_token}</code><button title="Copy enrollment token" onClick={() => void navigator.clipboard.writeText(enrollment.enrollment_token)}><Clipboard size={15} /></button></div><small>Expires {new Date(enrollment.expires_at).toLocaleString()}</small><a className="button primary full" href="/downloads/agent/ForgeSec-Network-Agent-Setup.exe" download><Download size={15} />Download Windows probe</a><small className={`agent-release-note ${release?.channel === "production" ? "production" : ""}`}>{release?.channel === "production" && release.signed && release.includes_licensed_scanner ? `Production package v${release.version}. Scanner included. SHA-256 ${release.sha256.slice(0, 12)}...` : release?.channel === "development" ? `Development package v${release.version}. Unsigned; install Nmap/Npcap separately.` : "Package metadata unavailable. Verify the installer before deployment."}</small></div> : <form onSubmit={submit}><label>Probe label<input required value={label} onChange={(event) => setLabel(event.target.value)} /></label><label>Site<select value={siteId} onChange={(event) => setSiteId(event.target.value)}>{sites.map((site) => <option key={site.site_id} value={site.site_id}>{site.name}</option>)}<option value="new">Create new site</option></select></label>{siteId === "new" && <label>New site name<input required value={newSite} onChange={(event) => setNewSite(event.target.value)} placeholder="Head Office" /></label>}<button className="button primary full" disabled={busy || (siteId === "new" && !newSite.trim())}>{busy ? <LoaderCircle className="spin" size={15} /> : <Plus size={15} />}Create enrollment token</button></form>}</section></div>;
}

function RevokeAgentModal({ agent, busy, error, onClose, onRevoke }: { agent: AgentRecord; busy: boolean; error: string | null; onClose: () => void; onRevoke: (reason: string) => Promise<void> }) {
  const [reason, setReason] = useState("");
  const dialogRef = useModalKeyboard(onClose, busy);
  async function submit(event: FormEvent) { event.preventDefault(); await onRevoke(reason.trim()); }
  return <div className="modal-backdrop" role="presentation"><section ref={dialogRef} className="modal compact" role="dialog" aria-modal="true" aria-labelledby="revoke-agent-title"><div className="modal-header"><div><span className="eyebrow">PROBE ACCESS</span><h2 id="revoke-agent-title">Revoke {agent.label}</h2></div><button className="icon-button" title="Close" onClick={onClose} disabled={busy}><X size={17} /></button></div><p className="revoke-explanation">This immediately blocks heartbeats, commands, and uploads from {agent.hostname}. To reconnect it later, issue a new enrollment token and reinstall or reset its identity.</p><form onSubmit={(event) => void submit(event)}><label>Reason<input type="text" required minLength={3} maxLength={500} value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Device decommissioned" autoFocus /></label>{error && <div className="inline-error" role="alert"><ShieldAlert size={15} />{error}</div>}<button className="button danger full" type="submit" disabled={busy || reason.trim().length < 3}>{busy ? <LoaderCircle className="spin" size={15} /> : <ShieldX size={15} />}Revoke probe access</button></form></section></div>;
}

function AuthorizationModal({ agent, scope, mode, segmentCount, knownTargetsText, onKnownTargetsChange, error, busy, onClose, onConfirm }: { agent?: AgentRecord; scope: string; mode: "selected" | "all"; segmentCount: number; knownTargetsText: string; onKnownTargetsChange: (value: string) => void; error: string | null; busy: boolean; onClose: () => void; onConfirm: () => void }) {
  const [confirmed, setConfirmed] = useState(false);
  const knownTargets = parseKnownTargets(knownTargetsText);
  const dialogRef = useModalKeyboard(onClose, busy);
  return <div className="modal-backdrop"><section ref={dialogRef} className="modal compact" role="dialog" aria-modal="true" aria-labelledby="discovery-authorization-title">
    <div className="modal-header"><div><span className="eyebrow">DISCOVERY SCOPE</span><h2 id="discovery-authorization-title">{mode === "all" ? "Discover approved networks" : "Discover selected scope"}</h2></div><button className="icon-button" title="Close" onClick={onClose} disabled={busy}><X size={17} /></button></div>
    <div className="scope-summary"><Server size={18} /><div><strong>{agent?.label}</strong><span>{scope}</span><small>{segmentCount} sequential /24 segment{segmentCount === 1 ? "" : "s"}</small></div></div>
    {agent?.discovery_requires_authorization && <div className="inline-error"><ShieldAlert size={15} /><span>This connected network uses public-range addressing.</span></div>}
    {mode === "selected" && <label>Known hosts to verify (optional, up to 3)<input value={knownTargetsText} onChange={(event) => onKnownTargetsChange(event.target.value)} placeholder="IPv4 addresses, separated by commas" aria-invalid={Boolean(knownTargets.error)} /></label>}
    {knownTargets.error && mode === "selected" && <div className="inline-error" role="alert">{knownTargets.error}</div>}
    {error && !knownTargets.error && <div className="inline-error" role="alert">{error}</div>}
    <label className="confirmation"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /><span>I confirm that I am authorized to discover this scope and check any entered hosts.</span></label>
    <button className="button primary full" disabled={!confirmed || busy || Boolean(knownTargets.error)} onClick={onConfirm}>{busy ? <LoaderCircle className="spin" size={15} /> : <Radar size={15} />}{mode === "all" ? `Discover approved ${segmentCount}` : "Start discovery"}</button>
  </section></div>;
}

function FullTcpModal({ targetIp, probeName, error, busy, onClose, onConfirm }: { targetIp: string; probeName: string; error: string | null; busy: boolean; onClose: () => void; onConfirm: () => void }) {
  const [confirmed, setConfirmed] = useState(false);
  const dialogRef = useModalKeyboard(onClose, busy);
  return <div className="modal-backdrop"><section ref={dialogRef} className="modal compact" role="dialog" aria-modal="true" aria-labelledby="full-tcp-title">
    <div className="modal-header"><div><span className="eyebrow">SCAN ESCALATION</span><h2 id="full-tcp-title">Full TCP scan</h2></div><button className="icon-button" title="Close" disabled={busy} onClick={onClose}><X size={17} /></button></div>
    <div className="scope-summary"><Server size={18} /><div><strong>{targetIp}</strong><span>From {probeName}</span><small>TCP ports 1-65535; no UDP; up to 45 minutes</small></div></div>
    <p className="revoke-explanation">This requests deeper service version checks on one approved target. Timeouts and filtering can leave ports unconfirmed.</p>
    {error && <div className="inline-error" role="alert">{error}</div>}
    <label className="confirmation"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /><span>I confirm this target and the Full TCP scan are authorized.</span></label>
    <button className="button primary full" disabled={!confirmed || busy} onClick={onConfirm}>{busy ? <LoaderCircle className="spin" size={15} /> : <Radar size={15} />}{busy ? "Starting" : "Start Full TCP"}</button>
  </section></div>;
}

function DeviceDrawer({ agentId, agentStatus, device, result, scanId, canOperate, onClose }: { agentId?: string; agentStatus?: AgentRecord["status"]; device: Device; result?: HostResult; scanId?: string; canOperate: boolean; onClose: () => void }) {
  const [lookups, setLookups] = useState<Record<string, VulnerabilityLookup>>({});
  const [selectedCpe, setSelectedCpe] = useState<string | null>(null);
  const [loadingCpe, setLoadingCpe] = useState<string | null>(null);
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [selectedDiagnostic, setSelectedDiagnostic] = useState<AgentDiagnosticType>("ping");
  const [fullTcpDiagnosticConfirmed, setFullTcpDiagnosticConfirmed] = useState(false);
  const [diagnosticRun, setDiagnosticRun] = useState<AgentDiagnostic | null>(null);
  const [diagnosticStarting, setDiagnosticStarting] = useState(false);
  const [diagnosticError, setDiagnosticError] = useState<string | null>(null);
  const [diagnosticNow, setDiagnosticNow] = useState(() => Date.now());
  const name = deviceDisplayName(device);
  const classifiedType = result?.device_type ?? device.device_type;
  const classifiedConfidence = result?.classification_confidence ?? device.classification_confidence;
  const portCounts = countPortStates(result?.ports ?? []);
  const cpeCount = new Set(result?.ports.filter((port) => port.state === "open").flatMap(portCpes) ?? []).size;
  const selectedLookup = selectedCpe ? lookups[selectedCpe] : undefined;
  const diagnosticActive = Boolean(
    diagnosticRun && ["queued", "claimed", "running"].includes(diagnosticRun.status),
  );
  const diagnosticBusy = diagnosticStarting || diagnosticActive;
  const selectedDiagnosticOption = DIAGNOSTIC_OPTIONS.find((item) => item.value === selectedDiagnostic) ?? DIAGNOSTIC_OPTIONS[0];
  const probeUnavailable = !agentId || agentStatus === "offline" || agentStatus === "busy";
  const elapsedSeconds = diagnosticRun && diagnosticActive
    ? Math.max(0, Math.floor((diagnosticNow - Date.parse(diagnosticRun.started_at ?? diagnosticRun.created_at)) / 1000))
    : null;
  const pingResult = pingResultFor(diagnosticRun);
  const hostStatusValue = diagnosticBusy
    ? "running"
    : diagnosticRun?.status === "failed"
      ? "failed"
      : diagnosticRun?.status === "completed" && diagnosticRun.diagnostic_type !== "ping"
        ? "completed"
      : pingResult === "reply"
        ? "online"
        : pingResult ?? "idle";
  const hostStatusLabel = diagnosticBusy
    ? "Checking"
    : diagnosticRun?.status === "failed"
      ? "Check failed"
      : diagnosticRun?.status === "completed" && diagnosticRun.diagnostic_type !== "ping"
        ? "Completed"
      : pingResult === "reply"
        ? "Echo reply"
        : pingResult === "unreachable"
          ? "Destination unreachable"
          : pingResult === "timeout"
            ? "ICMP timeout"
            : pingResult === "no_reply"
              ? "No echo reply"
              : "Not checked";
  const hostStatusDetail = pingResult === "reply"
    ? "The probe received an ICMP echo reply from this target."
    : pingResult === "unreachable"
      ? "The probe received a destination-unreachable error, not a reply from this target. Check the current IP and network path."
      : pingResult === "timeout"
        ? "No ICMP reply arrived. Ping may be blocked, or the host may no longer be reachable; this alone does not prove it is offline."
        : pingResult === "no_reply"
          ? "No echo reply from this target was confirmed. Review the raw output; discovery is a separate observation."
      : diagnosticRun?.status === "failed"
        ? diagnosticRun.message ?? "The agent could not complete the host check."
        : diagnosticRun?.status === "completed"
          ? "The check finished. Review its output below."
          : diagnosticBusy
            ? "The selected probe is running this check."
            : agentStatus === "offline"
              ? "The probe is offline. Wait for a fresh heartbeat before checking this host."
              : agentStatus === "busy"
                ? "The probe is busy with another operation. Wait for it to finish."
                : "Run a check from the selected probe.";
  const pingSummary = pingResult ? {
    reply: "Ping completed: host responded",
    unreachable: "Ping completed: destination unreachable",
    timeout: "Ping completed: timed out",
    no_reply: "Ping completed: no echo reply",
  }[pingResult] : null;
  const terminalSummary = diagnosticBusy
    ? `${diagnosticRun?.message ?? "Waiting for probe"} | ${elapsedSeconds ?? 0}s elapsed`
    : pingSummary ?? diagnosticRun?.message;
  const terminalText = diagnosticRun
    ? [
      `> ${diagnosticRun.command_line ?? `${selectedDiagnosticOption.label} ${device.ip}`}`,
      terminalSummary ? `# ${terminalSummary}` : null,
      diagnosticRun.output || (diagnosticBusy ? "Output will appear when the check finishes." : "No command output was returned."),
    ].filter(Boolean).join("\n\n")
    : null;

  useEffect(() => {
    if (!diagnosticActive) return;
    const timer = window.setInterval(() => setDiagnosticNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [diagnosticActive]);

  useEffect(() => {
    if (!agentId || !diagnosticRun || !diagnosticActive) return;
    const timer = window.setInterval(() => {
      void api.diagnostic(agentId, diagnosticRun.command_id)
        .then(setDiagnosticRun)
        .catch((cause) => setDiagnosticError(diagnosticErrorMessage(cause)));
    }, 1500);
    return () => window.clearInterval(timer);
  }, [agentId, diagnosticActive, diagnosticRun]);

  async function runDiagnostic() {
    if (!agentId) {
      setDiagnosticError("No selected agent is available for diagnostics.");
      return;
    }
    if (selectedDiagnostic === "full_tcp_nmap" && !fullTcpDiagnosticConfirmed) {
      setDiagnosticError("Confirm authorization for this Full TCP host check.");
      return;
    }
    setDiagnosticStarting(true);
    setDiagnosticError(null);
    setDiagnosticRun(null);
    setDiagnosticNow(Date.now());
    try {
      setDiagnosticRun(await api.createDiagnostic(agentId, device.ip, selectedDiagnostic, fullTcpDiagnosticConfirmed));
      setFullTcpDiagnosticConfirmed(false);
    } catch (cause) {
      setDiagnosticError(diagnosticErrorMessage(cause));
    } finally {
      setDiagnosticStarting(false);
    }
  }

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

  const hostCheckPanel = <>
    <h3>Host check</h3>
    <div className="diagnostic-runner">
      <div className="host-check-summary">
        <div><span>Target</span><strong>{device.ip}</strong></div>
        <Status value={hostStatusValue} label={hostStatusLabel} />
        <p>{hostStatusDetail}</p>
        <small>Discovery: {device.discovery_reason === "arp-response" ? "ARP response" : titleCase(device.discovery_reason)} at {new Date(device.last_seen).toLocaleString()}</small>
      </div>
      <div className="diagnostic-controls">
        <label>
          <span>Check type</span>
          <select value={selectedDiagnostic} disabled={diagnosticBusy} onChange={(event) => { setSelectedDiagnostic(event.target.value as AgentDiagnosticType); setFullTcpDiagnosticConfirmed(false); setDiagnosticRun(null); setDiagnosticError(null); }}>
            {DIAGNOSTIC_OPTIONS.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
          </select>
        </label>
        <button className="button primary" disabled={!canOperate || diagnosticBusy || probeUnavailable || (selectedDiagnostic === "full_tcp_nmap" && !fullTcpDiagnosticConfirmed)} onClick={() => void runDiagnostic()}>{diagnosticBusy ? <LoaderCircle className="spin" size={15} /> : <Terminal size={15} />}{diagnosticBusy ? "Checking" : selectedDiagnostic === "ping" ? "Check host" : "Run check"}</button>
      </div>
      {selectedDiagnostic === "full_tcp_nmap" && <label className="confirmation"><input type="checkbox" checked={fullTcpDiagnosticConfirmed} disabled={diagnosticBusy} onChange={(event) => setFullTcpDiagnosticConfirmed(event.target.checked)} /><span>I confirm this single-host Full TCP check is approved. Its terminal output is not a saved scan report.</span></label>}
      <div className="diagnostic-meta"><span>{selectedDiagnosticOption.hint}</span><small>Up to {selectedDiagnosticOption.maxSeconds < 60 ? `${selectedDiagnosticOption.maxSeconds}s` : `${selectedDiagnosticOption.maxSeconds / 60} min`}</small>{diagnosticRun && <Status value={diagnosticRun.status} />}{elapsedSeconds != null && <strong>{elapsedSeconds}s elapsed</strong>}{diagnosticRun?.duration_ms != null && <strong>{(diagnosticRun.duration_ms / 1000).toFixed(1)}s</strong>}</div>
      {diagnosticError && <div className="inline-error" role="alert"><ShieldAlert size={15} /><span>{diagnosticError}</span></div>}
      {terminalText && <pre className="terminal-output" aria-label={`${selectedDiagnosticOption.label} output`}>{terminalText}</pre>}
      {diagnosticRun?.command_line && <button className="button secondary full" onClick={() => void navigator.clipboard.writeText(terminalText ?? "")}><Clipboard size={14} />Copy output</button>}
    </div>
  </>;

  return <div className="drawer-backdrop" onClick={onClose}>
    <aside className="drawer" onClick={(event) => event.stopPropagation()}>
      <div className="modal-header"><div><span className="eyebrow">DEVICE DETAILS</span><h2>{name}</h2></div><button className="icon-button" title="Close" onClick={onClose}><X size={17} /></button></div>
      <div className="detail-summary"><Status value={result?.status ?? "not_scanned"} /><span>{result && ["partial", "timed_out", "failed", "cancelled"].includes(result.status) && !result.ports.length ? "Open state unknown" : `${portCounts.open} open`}</span>{portCounts.openFiltered > 0 && <span>{portCounts.openFiltered} open|filtered</span>}{portCounts.filtered > 0 && <span>{portCounts.filtered} filtered</span>}<span>{cpeCount} CPEs</span></div>
      <dl>
        <dt>Hostname</dt><dd>{device.hostname ?? "Not reported by discovery"}</dd>
        {result?.hostname && <><dt>Scan hostname</dt><dd>{result.hostname} ({hostnameSourceLabel(result.hostname_source)})</dd></>}
        <dt>SNMP name</dt><dd>{device.snmp_name ?? "Not reported"}</dd>
        <dt>IP address</dt><dd>{device.ip}</dd>
        <dt>MAC address</dt><dd>{device.mac ?? "Unavailable"}</dd>
        <dt>Vendor</dt><dd>{device.vendor ?? "Unknown"}</dd>
        <dt>SNMP system</dt><dd>{device.snmp_description ?? "Not reported"}</dd>
        <dt>SNMP object ID</dt><dd>{device.snmp_object_id ?? "Not reported"}</dd>
        <dt>SNMP contact</dt><dd>{device.snmp_contact ?? "Not reported"}</dd>
        <dt>SNMP location</dt><dd>{device.snmp_location ?? "Not reported"}</dd>
        <dt>SNMP uptime</dt><dd>{formatDuration(device.snmp_uptime_seconds)}</dd>
        <dt>Interfaces</dt><dd>{device.snmp_interface_count ?? device.snmp_interfaces?.length ?? "Not reported"}</dd>
        <dt>Role estimate</dt><dd>{roleEstimate(classifiedType, classifiedConfidence)}</dd>
        <dt>Latency</dt><dd>{device.latency_ms == null ? "Unavailable" : `${device.latency_ms.toFixed(2)} ms`}</dd>
        <dt>Last seen</dt><dd>{new Date(device.last_seen).toLocaleString()}</dd>
        {result?.raw_xml_sha256 && <><dt>Raw XML SHA-256</dt><dd><code className="scan-evidence-hash">{result.raw_xml_sha256}</code></dd></>}
      </dl>

      <h3>SNMP interfaces</h3>
      {device.snmp_interfaces?.length ? <div className="interface-list">{device.snmp_interfaces.map((item) => <div key={item.index}><div><strong>{interfaceName(item)}</strong><span>{[item.interface_type ? titleCase(item.interface_type) : null, item.alias].filter(Boolean).join(" - ") || "No interface alias"}</span></div><div><Status value={item.oper_status ?? "unknown"} /><small>{item.admin_status ? `Admin ${titleCase(item.admin_status)}` : "Admin unknown"}</small><small>{interfaceSpeed(item)}</small></div></div>)}</div> : <p className="muted">No SNMP interface table was reported. Enable SNMP on network devices and allow UDP 161 from the agent to collect this inventory.</p>}

      <h3>OS estimates</h3>
      {result?.os_matches.length ? <div className="os-match-list">{result.os_matches.slice(0, 5).map((match) => <div key={`${match.name}-${match.accuracy}`}><span>{match.name}</span><strong>{match.accuracy}% Nmap match</strong></div>)}</div> : <p className="muted">OS not identified by this scan.</p>}

      <h3>Observed ports and services</h3>
      {result?.ports.length ? <div className="port-list detailed">{result.ports.map((port) => <div className="service-row" key={`${port.protocol}-${port.port}`}>
        <div className="service-heading"><code>{port.port}/{port.protocol}</code><Status value={port.state} /><strong>{portServiceLabel(port)}</strong></div>
        <div className="service-details"><span>Product</span><strong>{port.product ?? "Not identified"}</strong><span>Version</span><strong>{port.version ?? "Not identified"}</strong><span>Method</span><strong>{[port.method === "table" ? "Port lookup" : port.method === "probed" ? "Probed" : port.method, port.confidence != null ? `${port.confidence}/10 Nmap score` : null].filter(Boolean).join(" - ") || "Not reported"}</strong><span>Reason</span><strong>{port.reason ?? "Not reported"}</strong><span>Source</span><strong>{portEvidenceSourceLabel(port)}</strong><span>Scan ended</span><strong>{portEvidenceTimeLabel(port)}</strong><span>Device hint</span><strong>{port.devicetype ?? port.ostype ?? "Not identified"}</strong>{port.extrainfo && <><span>Extra info</span><strong>{port.extrainfo}</strong></>}</div>
        {portCpes(port).length > 0 ? <div className="cpe-list">{portCpes(port).map((cpe) => <div key={cpe}><code>{cpe}</code>{port.state === "open" && scanId && canOperate && <button className="button secondary cve-button" disabled={loadingCpe === cpe} onClick={() => void checkVulnerabilities(cpe)}>{loadingCpe === cpe ? <LoaderCircle className="spin" size={14} /> : <ShieldAlert size={14} />}{lookups[cpe] ? "View CVEs" : "Check CVEs"}</button>}</div>)}</div> : <p className="muted">CPE not observed.</p>}
      </div>)}</div> : <p className="muted">{result ? "No port-state evidence was returned. This does not prove all ports are closed." : "No scan result is available for this device."}</p>}

      <h3>Exposure observations</h3>
      {result?.exposure_flags.length ? <div className="finding-list">{result.exposure_flags.map((flag) => <div key={flag.code}><Status value={flag.severity} /><div><strong>{flag.title}</strong><span>{flag.evidence}</span></div></div>)}</div> : <p className="muted">No rule-based exposure observations were reported.</p>}

      <div className="section-heading"><h3>Potential CVE matches</h3>{selectedLookup && <span>{selectedLookup.total} NVD matches</span>}</div>
      {lookupError && <div className="inline-error"><ShieldAlert size={15} /><span>{lookupError}</span></div>}
      {!selectedCpe && <p className="muted">{cpeCount ? "Use Check CVEs on a fingerprinted service to correlate its exact product version." : "A precise product version and CPE are required for CVE correlation."}</p>}
      {selectedCpe && loadingCpe === selectedCpe && <div className="lookup-loading"><LoaderCircle className="spin" size={16} />Checking the NVD for this service fingerprint...</div>}
      {selectedLookup && <VulnerabilityResults lookup={selectedLookup} />}
      {result?.error && <div className="inline-error"><ShieldAlert size={15} /><span>{result.error}</span></div>}
      {hostCheckPanel}
    </aside>
  </div>;
}

function VulnerabilityResults({ lookup }: { lookup: VulnerabilityLookup }) {
  return <div className="vulnerability-results">
    <div className="lookup-context"><code>{lookup.cpe}</code><span>{lookup.notice}</span></div>
    {(lookup.truncated || lookup.total > lookup.returned) && <div className="inline-error" role="status"><ShieldAlert size={15} /><span>Showing {lookup.returned} of {lookup.total} NVD matches. This bounded result is incomplete; severity counts may omit CVEs.</span></div>}
    {lookup.vulnerabilities.length ? <div className="vulnerability-list">{lookup.vulnerabilities.map((vulnerability) => <article key={vulnerability.cve_id}>
      <div className="vulnerability-heading"><a href={`https://nvd.nist.gov/vuln/detail/${vulnerability.cve_id}`} target="_blank" rel="noreferrer">{vulnerability.cve_id}<ExternalLink size={12} /></a><Status value={vulnerability.severity} />{vulnerability.cvss_score != null && <strong>CVSS {vulnerability.cvss_score.toFixed(1)}</strong>}{vulnerability.known_exploited && <span className="kev-badge">Known exploited</span>}</div>
      <p>{vulnerability.description}</p>
      {vulnerability.vector && <code className="cvss-vector">{vulnerability.vector}</code>}
      {vulnerability.required_action && <div className="required-action"><strong>Required action</strong><span>{vulnerability.required_action}{vulnerability.action_due ? ` Due ${new Date(`${vulnerability.action_due}T00:00:00`).toLocaleDateString()}.` : ""}</span></div>}
      {vulnerability.references.length > 0 && <div className="reference-links">{vulnerability.references.slice(0, 3).map((reference, index) => <a key={`${reference}-${index}`} href={reference} target="_blank" rel="noreferrer"><ExternalLink size={11} />Reference</a>)}</div>}
    </article>)}</div> : <p className="muted result-empty">NVD returned no matches for this observed CPE. This does not establish that the device is safe.</p>}
    <p className="nvd-attribution">NVD data retrieved {new Date(lookup.retrieved_at).toLocaleString()} ({nvdDataAge(lookup.retrieved_at)}){lookup.cached ? "; cache reused" : ""}. Matches are candidates, not confirmed device vulnerabilities. This product uses the NVD API but is not endorsed or certified by the NVD.</p>
  </div>;
}
