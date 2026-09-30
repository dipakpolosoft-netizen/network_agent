export const API_URL =
  process.env.NEXT_PUBLIC_FORGESEC_API_URL?.replace(/\/+$/, "") ?? "";
export const AGENT_SERVER_URL =
  process.env.NEXT_PUBLIC_FORGESEC_AGENT_SERVER_URL?.replace(/\/+$/, "") ??
  "http://127.0.0.1:8000";

export type Agent = {
  agent_id: string;
  site_id: string | null;
  approved_scopes: string[];
  approved_discovery_scopes: string[];
  label: string;
  site_name: string | null;
  hostname: string;
  agent_version: string;
  os_name: string;
  architecture: "x86_64" | "arm64";
  status: "online" | "busy" | "degraded" | "offline";
  local_ip: string | null;
  subnet: string | null;
  nmap_version: string | null;
  npcap_status: "available" | "missing" | "degraded" | "unknown";
  discovery_ready: boolean | null;
  discovery_network: string | null;
  discovery_interface: string | null;
  discovery_error: string | null;
  discovery_capability: "ready" | "selection_required" | "authorization_required" | "unsupported" | null;
  discovery_scope_options: string[];
  discovery_recommended_scope: string | null;
  discovery_requires_authorization: boolean;
  discovery_all_segments_available: boolean;
  current_command_id: string | null;
  enrolled_at: string;
  last_heartbeat_at: string | null;
  credential_rotated_at: string | null;
  revoked_at: string | null;
  revoked_reason: string | null;
};

export type Device = {
  device_id: string;
  ip: string;
  hostname: string | null;
  mac: string | null;
  vendor: string | null;
  snmp_name: string | null;
  snmp_description: string | null;
  snmp_object_id: string | null;
  snmp_contact: string | null;
  snmp_location: string | null;
  snmp_uptime_seconds: number | null;
  snmp_interface_count: number | null;
  snmp_interfaces: SnmpInterface[];
  device_type: string | null;
  classification_confidence: number | null;
  status: "up";
  discovery_reason: string;
  latency_ms: number | null;
  is_agent: boolean;
  first_seen: string;
  last_seen: string;
  discovery_scope: string | null;
};

export type Discovery = {
  discovery_id: string;
  command_id: string;
  agent_id: string;
  site_id: string | null;
  change_summary: {
    baseline_discovery_id: string | null;
    baseline_completed_at: string | null;
    new_host_count: number;
    not_observed_count: number;
    new_hosts: Array<{ device_id: string; ip: string; hostname: string | null }>;
    not_observed_hosts: Array<{ device_id: string; ip: string; hostname: string | null }>;
  };
  status: string;
  stage: string;
  network: string | null;
  interface_name: string | null;
  device_count: number;
  found_count: number;
  progress_percent: number | null;
  cancel_requested: boolean;
  authorization_confirmed: boolean;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  devices: Device[];
  error: string | null;
  events: Array<{
    event_id: string;
    status: string;
    stage: string;
    message: string;
    occurred_at: string;
    progress_percent: number | null;
    found_count: number;
  }>;
  mode: "selected" | "all";
  connected_network: string | null;
  requested_scopes: string[];
  completed_scopes: string[];
  failed_scopes: string[];
  current_scope: string | null;
  total_scopes: number;
  public_scope_authorized: boolean;
  known_targets: string[];
  follow_up_checks: Array<{
    ip: string;
    status: "already_discovered" | "responsive" | "no_response" | "error";
    method: "initial_discovery" | "targeted_tcp_icmp";
    checked_at: string;
    reason: string | null;
    error: string | null;
  }>;
};

export type PortResult = {
  protocol: "tcp" | "udp";
  port: number;
  state: string;
  evidence_source?: "nmap" | null;
  recorded_at?: string | null;
  reason: string | null;
  service: string | null;
  product: string | null;
  version: string | null;
  extrainfo: string | null;
  ostype: string | null;
  devicetype: string | null;
  method: string | null;
  confidence: number | null;
  cpe: string | null;
  cpes: string[];
};

export type Asset = {
  asset_id: string;
  site_id: string;
  display_name: string | null;
  owner: string | null;
  criticality: "low" | "medium" | "high" | "critical";
  tags: string[];
  hostname: string | null;
  mac: string | null;
  last_ip: string;
  ip_history: string[];
  vendor: string | null;
  device_type: string | null;
  classification_confidence: number | null;
  os_name: string | null;
  os_accuracy: number | null;
  open_port_count: number;
  ports: Array<{ protocol: "tcp" | "udp"; port: number; service: string | null; product: string | null; version: string | null }>;
  first_seen: string;
  last_seen: string;
  last_discovery_at: string | null;
  last_scan_at: string | null;
  last_discovery_id: string | null;
  last_scan_id: string | null;
  last_scan_status: string | null;
  port_snapshot_scan_id: string | null;
  port_snapshot_at: string | null;
  port_snapshot_ip: string | null;
  observation_count: number;
  scan_count: number;
  created_at: string;
  updated_at: string;
};

export type AssetObservation = {
  observation_id: string;
  asset_id: string;
  site_id: string;
  source_type: "discovery" | "scan";
  source_id: string;
  source_device_id: string;
  agent_id: string;
  observed_at: string;
  ip: string;
  mac: string | null;
  hostname: string | null;
  device_type: string | null;
  status: string;
  open_port_count: number | null;
  scan_profile: string | null;
  port_delta: {
    baseline_scan_id: string;
    opened_count: number;
    no_longer_confirmed_count: number;
    opened_ports: Array<{ protocol: "tcp" | "udp"; port: number; service: string | null }>;
    no_longer_confirmed_ports: Array<{ protocol: "tcp" | "udp"; port: number; service: string | null }>;
  } | null;
};

export type AssetDeviceProfile = {
  asset_id: string;
  discovery: {
    discovery_id: string;
    observed_at: string;
    ip: string;
    hostname: string | null;
    vendor: string | null;
    device_type: string | null;
    classification_confidence: number | null;
    discovery_reason: string | null;
    latency_ms: number | null;
  } | null;
  snmp: {
    discovery_id: string;
    observed_at: string;
    ip: string;
    latest_discovery: boolean;
    name: string | null;
    description: string | null;
    object_id: string | null;
    uptime_seconds: number | null;
    reported_interface_count: number | null;
    interfaces: SnmpInterface[];
    interfaces_limited: boolean;
  } | null;
};

export type AssetEvidence = {
  asset_id: string;
  items: Array<{
    review_id: string;
    source: "host_scan" | "nvd" | "nuclei" | "greenbone";
    classification: "exposure_signal" | "potential_cve" | "configuration_observation" | "scanner_finding";
    source_id: string;
    scan_id: string | null;
    observed_at: string;
    current: boolean;
    severity: "critical" | "high" | "medium" | "low" | "info" | "unknown";
    title: string;
    detail: string;
    reference: string | null;
    target: string | null;
    review_status: "unreviewed" | "investigating" | "confirmed" | "false_positive" | "accepted_risk";
    review_note: string | null;
    reviewed_at: string | null;
    reviewed_by: string | null;
  }>;
  runs: Array<{
    job_id: string;
    source: "nuclei" | "greenbone" | "ssh_inventory";
    status: "queued" | "leased" | "completed" | "failed" | "cancelled";
    created_at: string;
    completed_at: string | null;
    summary: string | null;
    current: boolean;
  }>;
  latest_inventory: {
    job_id: string;
    observed_at: string;
    current: boolean;
    hostname: string;
    os_name: string;
    os_version: string | null;
    kernel: string;
    package_count: number;
    packages_truncated: boolean;
  } | null;
  truncated: boolean;
};

export type AssetList = { items: Asset[]; total: number; limit: number; offset: number };

export type TopologyNode = {
  id: string;
  asset_id: string | null;
  label: string;
  ip: string | null;
  device_type: string | null;
  observed_only: boolean;
  last_seen: string | null;
};

export type TopologyLink = {
  id: string;
  source: string;
  target: string;
  reported_by: string;
  probe_id: string;
  local_port: string;
  remote_port: string | null;
  remote_system_name: string | null;
  match_method: "chassis_id" | "mac" | "unresolved";
  discovery_id: string;
  observed_at: string;
  stale: boolean;
};

export type TopologyGraph = {
  site_id: string;
  nodes: TopologyNode[];
  links: TopologyLink[];
  probes?: Array<{
    agent_id: string;
    label: string;
    hostname: string;
    ip: string | null;
    subnet: string | null;
    os_name: string;
    agent_version: string;
    last_heartbeat_at: string | null;
  }>;
  observed_assets: number;
  unlinked_assets: number;
  stale_hidden: number;
  total_links: number;
  truncated: boolean;
  latest_observed_at: string | null;
};

export type ScannerWorker = {
  worker_id: string;
  site_id: string;
  label: string;
  capabilities: string[];
  status: "online" | "offline" | "revoked";
  available_capabilities: string[];
  version: string | null;
  created_at: string;
  last_heartbeat_at: string | null;
  revoked_at: string | null;
};

export type ProvisionedScannerWorker = ScannerWorker & { credential: string };

export type WorkerJob = {
  job_id: string;
  site_id: string;
  capability: string;
  target_ip: string;
  profile: ScanProfile;
  target_port: number | null;
  target_scheme: "http" | "https" | null;
  source_asset_id: string | null;
  template_profile: "http_baseline" | null;
  assessment_profile: "greenbone_single_host" | null;
  inventory_profile: "linux_ssh_readonly" | null;
  progress: number | null;
  phase: string | null;
  status: "queued" | "leased" | "completed" | "failed" | "cancelled";
  created_at: string;
  updated_at: string;
  summary: string | null;
};

export type WorkerJobDetail = WorkerJob & {
  evidence: {
    engine: "nuclei";
    findings: Array<{ template_id: string; title: string; severity: "low"; matched_at: string }>;
  } | {
    engine: "greenbone";
    target_ip: string;
    task_id: string;
    report_id: string;
    truncated: boolean;
    findings: Array<{ result_id: string; name: string; severity: number; host: string; port: string; nvt_oid: string | null; cves: string[] }>;
  } | {
    engine: "ssh_inventory";
    target_ip: string;
    hostname: string;
    os_name: string;
    os_version: string | null;
    kernel: string;
    architecture: string;
    package_manager: "dpkg" | "rpm" | "none";
    packages: Array<{ name: string; version: string }>;
    packages_truncated: boolean;
  } | null;
};

export type SnmpInterface = {
  index: number;
  name: string | null;
  description: string | null;
  interface_type: string | null;
  admin_status: string | null;
  oper_status: string | null;
  speed_mbps: number | null;
  alias: string | null;
};

export type HostResult = {
  device_id: string;
  ip: string;
  status: string;
  started_at?: string | null;
  completed_at?: string | null;
  hostname: string | null;
  hostname_source?: "nmap" | "discovery" | "snmp" | null;
  device_type: string | null;
  classification_confidence: number | null;
  ports: PortResult[];
  os_matches: Array<{ name: string; accuracy: number }>;
  exposure_flags: Array<{
    code: string;
    severity: "info" | "low" | "medium" | "high";
    title: string;
    evidence: string;
  }>;
  error: string | null;
  raw_xml_sha256?: string | null;
};

export type CountItem = {
  label: string;
  count: number;
};

export type ScanSummary = {
  scanned_hosts: number;
  evidence_hosts: number;
  classified_hosts: number;
  network_devices: number;
  servers: number;
  workstations: number;
  timed_out_hosts?: number;
  failed_hosts?: number;
  open_ports: number;
  open_filtered_ports?: number;
  filtered_ports?: number;
  tcp_ports: number;
  udp_ports: number;
  service_fingerprints: number;
  cpes: number;
  exposure_findings: number;
  high_exposure_findings: number;
  management_services: number;
  snmp_enabled: number;
  device_types: CountItem[];
  vendors: CountItem[];
  services: CountItem[];
  severity_counts: {
    high: number;
    medium: number;
    low: number;
    info: number;
  };
};

export type ChangedHost = {
  device_id: string | null;
  ip: string;
  hostname: string | null;
  device_type: string | null;
};

export type ChangedPort = {
  ip: string;
  hostname: string | null;
  protocol: "tcp" | "udp";
  port: number;
  service: string | null;
};

export type ChangedFinding = {
  ip: string;
  hostname: string | null;
  code: string;
  severity: "info" | "low" | "medium" | "high";
  title: string;
};

export type ScanChangeSummary = {
  baseline_scan_id: string | null;
  baseline_created_at: string | null;
  baseline_profile: ScanProfile | null;
  new_host_count: number;
  missing_host_count: number;
  opened_port_count: number;
  closed_port_count: number;
  no_longer_confirmed_port_count?: number;
  new_finding_count: number;
  resolved_finding_count: number;
  new_hosts: ChangedHost[];
  missing_hosts: ChangedHost[];
  opened_ports: ChangedPort[];
  closed_ports: ChangedPort[];
  no_longer_confirmed_ports?: ChangedPort[];
  new_findings: ChangedFinding[];
  resolved_findings: ChangedFinding[];
};

export type RecommendedAction = {
  priority: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  title: string;
  detail: string;
  affected_count: number;
};

export type ScanActionSummary = {
  risk_score: number;
  risk_level: "low" | "medium" | "high" | "critical";
  priority_actions: RecommendedAction[];
};

export type VulnerabilityMatch = {
  cve_id: string;
  severity: "critical" | "high" | "medium" | "low" | "unknown";
  cvss_score: number | null;
  cvss_version: string | null;
  vector: string | null;
  description: string;
  published_at: string | null;
  last_modified_at: string | null;
  known_exploited: boolean;
  required_action: string | null;
  action_due: string | null;
  references: string[];
};

export type VulnerabilityLookup = {
  source: "NVD";
  cpe: string;
  normalized_cpe: string;
  total: number;
  returned: number;
  truncated: boolean;
  retrieved_at: string;
  cached: boolean;
  vulnerabilities: VulnerabilityMatch[];
  notice: string;
};

export type VulnerabilitySeverityCounts = {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
};

export type AffectedService = {
  device_id: string;
  ip: string;
  hostname: string | null;
  port: number;
  protocol: "tcp" | "udp";
  service: string | null;
  product: string | null;
  version: string | null;
};

export type CpeVulnerabilitySummary = {
  cpe: string;
  normalized_cpe: string | null;
  affected_services: AffectedService[];
  affected_service_count: number;
  total: number;
  returned: number;
  truncated: boolean;
  retrieved_at: string | null;
  cached: boolean;
  severity_counts: VulnerabilitySeverityCounts;
  highest_severity: "critical" | "high" | "medium" | "low" | "unknown" | null;
  known_exploited: number;
  top_vulnerabilities: VulnerabilityMatch[];
  error: string | null;
};

export type ScanVulnerabilitySummary = {
  source: "NVD";
  scan_id: string;
  total_cpes: number;
  checked_cpes: number;
  skipped_cpes: number;
  total_vulnerabilities: number;
  returned_vulnerabilities: number;
  known_exploited: number;
  severity_counts: VulnerabilitySeverityCounts;
  items: CpeVulnerabilitySummary[];
  notice: string;
  assessed_at: string;
  evidence_fingerprint: string;
  evidence_current: boolean;
  failed_cpes: number;
  cached_lookups: number;
  partial_cpes: number;
};

export type AgentDiagnosticType =
  | "ping"
  | "reverse_dns"
  | "arp_cache"
  | "powershell_test"
  | "inventory_nmap"
  | "network_services_nmap"
  | "standard_nmap"
  | "full_tcp_nmap";

export type AgentDiagnostic = {
  command_id: string;
  agent_id: string;
  status: string;
  diagnostic_type: AgentDiagnosticType;
  target_ip: string;
  message: string | null;
  command_line: string | null;
  output: string | null;
  exit_code: number | null;
  duration_ms: number | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
  details: Record<string, unknown>;
};

export type ScanProfile = "inventory" | "network_services" | "standard" | "full_tcp";

export type ScanProfilePlan = {
  tcp_top_ports: number | null;
  tcp_all_ports: boolean;
  tcp_ports: number[];
  udp_ports: number[];
  version_detection: "light" | "full";
  os_detection: "when_privileged" | "not_requested";
  host_timeout_seconds: number;
  assume_host_up: boolean;
  open_only_output: boolean;
};

export type ScanOrigin = {
  agent_id: string;
  label: string;
  hostname: string;
  local_ip: string | null;
  subnet: string | null;
  site_name: string | null;
  os_name: string;
  agent_version: string;
  discovery_interface: string | null;
  last_heartbeat_at: string | null;
  source: "scan_snapshot" | "current_heartbeat";
};

export type Scan = {
  scan_id: string;
  command_id: string;
  discovery_id: string;
  agent_id: string;
  site_id: string | null;
  scan_origin: ScanOrigin | null;
  profile: ScanProfile;
  profile_plan: ScanProfilePlan | null;
  status: string;
  total: number;
  queued: number;
  running: number;
  completed: number;
  failed: number;
  cancelled: number;
  cancel_requested: boolean;
  stage: string | null;
  last_progress_at: string | null;
  targets: Array<{
    device_id: string;
    ip: string;
    hostname: string | null;
    vendor?: string | null;
    snmp_name?: string | null;
    snmp_description?: string | null;
    snmp_object_id?: string | null;
    snmp_contact?: string | null;
    snmp_location?: string | null;
    snmp_uptime_seconds?: number | null;
    snmp_interface_count?: number | null;
    snmp_interfaces?: SnmpInterface[];
    device_type?: string | null;
    classification_confidence?: number | null;
    status: string;
  }>;
  results: HostResult[];
  summary: ScanSummary;
  change_summary: ScanChangeSummary;
  action_summary: ScanActionSummary;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
};

export type Enrollment = {
  enrollment_id: string;
  enrollment_token: string;
  expires_at: string;
};

export type Site = {
  site_id: string;
  name: string;
  owner: string | null;
  description: string | null;
  created_at: string;
};

export type ApprovedScope = {
  scope_id: string;
  site_id: string;
  cidr: string;
  label: string;
  description: string | null;
  exclusions: string[];
  scan_profiles: ScanProfile[];
  owner: string | null;
  approval_reference: string | null;
  approved_by: string | null;
  expires_on: string | null;
  authorization_confirmed: boolean;
  public_range_authorized: boolean;
  approval_status: "active" | "expired" | "needs_review";
  created_at: string;
  approved_at: string | null;
};

export type ScopeApproval = {
  cidr: string;
  label: string;
  description: string;
  exclusions: string[];
  scan_profiles: ScanProfile[];
  owner: string;
  approval_reference: string;
  approved_by: string;
  expires_on: string;
  authorization_confirmed: true;
  public_range_authorized: boolean;
};

export type OperatorUser = {
  user_id: string;
  email: string;
  role: "admin" | "operator" | "viewer";
  active: boolean;
  created_at: string;
};

export type OperatorSession = {
  user: OperatorUser | null;
  csrf_token: string;
  auth_required: boolean;
};

let csrfToken = "";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const mutation = init?.method && !["GET", "HEAD"].includes(init.method);
  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(mutation && csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
      ...init?.headers,
    },
    credentials: "same-origin",
    cache: "no-store",
  });
  if (!response.ok) {
    if (response.status === 401 && path !== "/api/auth/login" && typeof window !== "undefined" && window.location.pathname !== "/login") {
      window.location.assign(`/login?next=${encodeURIComponent(window.location.pathname + window.location.search + window.location.hash)}`);
    }
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail ?? `Request failed with HTTP ${response.status}`);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export const api = {
  me: async () => {
    const session = await request<OperatorSession>("/api/auth/me");
    csrfToken = session.csrf_token;
    return session;
  },
  login: async (email: string, password: string) => {
    const session = await request<OperatorSession>("/api/auth/login", {
      method: "POST", body: JSON.stringify({ email, password }),
    });
    csrfToken = session.csrf_token;
    return session;
  },
  logout: async () => {
    await request<void>("/api/auth/logout", { method: "POST" });
    csrfToken = "";
  },
  changePassword: (currentPassword: string, newPassword: string) =>
    request<void>("/api/auth/password", {
      method: "POST",
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    }),
  users: () => request<OperatorUser[]>("/api/auth/users"),
  createUser: (email: string, password: string, role: OperatorUser["role"]) =>
    request<OperatorUser>("/api/auth/users", {
      method: "POST", body: JSON.stringify({ email, password, role }),
    }),
  setUserActive: (userId: string, active: boolean) =>
    request<OperatorUser>(`/api/auth/users/${userId}`, {
      method: "PATCH", body: JSON.stringify({ active }),
    }),
  sites: () => request<Site[]>("/api/sites"),
  createSite: (name: string, owner: string, description: string) =>
    request<Site>("/api/sites", { method: "POST", body: JSON.stringify({ name, owner: owner || null, description: description || null }) }),
  siteScopes: (siteId: string) => request<ApprovedScope[]>(`/api/sites/${siteId}/scopes`),
  approveScope: (siteId: string, scope: ScopeApproval) =>
    request<ApprovedScope>(`/api/sites/${siteId}/scopes`, { method: "POST", body: JSON.stringify(scope) }),
  removeScope: (siteId: string, scopeId: string) =>
    request<void>(`/api/sites/${siteId}/scopes/${scopeId}`, { method: "DELETE" }),
  agents: () => request<Agent[]>("/api/agents"),
  assets: (siteId: string, query: string, limit: number, offset: number) => {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    if (siteId) params.set("site_id", siteId);
    if (query) params.set("query", query);
    return request<AssetList>(`/api/assets?${params.toString()}`);
  },
  asset: (assetId: string) => request<Asset>(`/api/assets/${assetId}`),
  assetObservations: (assetId: string, offset = 0) =>
    request<AssetObservation[]>(`/api/assets/${assetId}/observations?limit=50&offset=${offset}`),
  assetDeviceProfile: (assetId: string) => request<AssetDeviceProfile>(`/api/assets/${assetId}/device-profile`),
  assetEvidence: (assetId: string) => request<AssetEvidence>(`/api/assets/${assetId}/evidence`),
  reviewAssetEvidence: (assetId: string, reviewId: string, status: AssetEvidence["items"][number]["review_status"], note: string) =>
    request<AssetEvidence["items"][number]>(`/api/assets/${assetId}/evidence/${reviewId}/review`, {
      method: "PATCH", body: JSON.stringify({ status, note }),
    }),
  topology: (siteId: string, includeStale: boolean) =>
    request<TopologyGraph>(`/api/assets/topology?site_id=${encodeURIComponent(siteId)}&include_stale=${includeStale}`),
  scannerWorkers: () => request<ScannerWorker[]>("/api/workers"),
  provisionScannerWorker: (siteId: string, label: string, capability: string) =>
    request<ProvisionedScannerWorker>("/api/workers", {
      method: "POST",
      body: JSON.stringify({ site_id: siteId, label, capabilities: [capability] }),
    }),
  revokeScannerWorker: (workerId: string) =>
    request<ScannerWorker>(`/api/workers/${workerId}/revoke`, { method: "POST" }),
  siteWorkerJobs: (siteId: string) =>
    request<WorkerJob[]>(`/api/worker-jobs?site_id=${encodeURIComponent(siteId)}`),
  assetWorkerJobs: (assetId: string) =>
    request<WorkerJob[]>(`/api/worker-jobs?asset_id=${encodeURIComponent(assetId)}`),
  workerJob: (jobId: string) => request<WorkerJobDetail>(`/api/worker-jobs/${jobId}`),
  enqueueNuclei: (assetId: string, port: number, scheme: "http" | "https") =>
    request<WorkerJob>("/api/worker-jobs/nuclei", {
      method: "POST",
      body: JSON.stringify({ asset_id: assetId, port, scheme, authorization_confirmed: true }),
    }),
  enqueueGreenbone: (assetId: string) =>
    request<WorkerJob>("/api/worker-jobs/greenbone", {
      method: "POST",
      body: JSON.stringify({ asset_id: assetId, authorization_confirmed: true, maintenance_window_confirmed: true }),
    }),
  enqueueInventory: (assetId: string) =>
    request<WorkerJob>("/api/worker-jobs/inventory", {
      method: "POST",
      body: JSON.stringify({ asset_id: assetId, authorization_confirmed: true }),
    }),
  cancelWorkerJob: (jobId: string) =>
    request<WorkerJob>(`/api/worker-jobs/${jobId}/cancel`, { method: "POST" }),
  updateAsset: (assetId: string, changes: { display_name?: string | null; owner?: string | null; criticality?: Asset["criticality"]; tags?: string[] }) =>
    request<Asset>(`/api/assets/${assetId}`, { method: "PATCH", body: JSON.stringify(changes) }),
  revokeAgent: (agentId: string, reason: string) =>
    request<Agent>(`/api/agents/${agentId}/revoke`, {
      method: "POST", body: JSON.stringify({ reason }),
    }),
  discoveries: (agentId?: string) =>
    request<Discovery[]>(
      `/api/discoveries${agentId ? `?agent_id=${agentId}` : ""}`,
    ),
  scans: (agentId?: string) =>
    request<Scan[]>(`/api/scans${agentId ? `?agent_id=${agentId}` : ""}`),
  scanReport: (scanId: string) => request<Scan>(`/api/scans/${scanId}`),
  createEnrollment: (label: string, siteId: string) =>
    request<Enrollment>("/api/enrollments", {
      method: "POST",
      body: JSON.stringify({ label, site_id: siteId }),
    }),
  discover: (
    agentId: string,
    scope: string | null,
    mode: "selected" | "all",
    knownTargets: string[] = [],
  ) =>
    request(`/api/agents/${agentId}/discover`, {
      method: "POST",
      body: JSON.stringify({ authorization_confirmed: true, scope, mode, known_targets: knownTargets }),
    }),
  cancelDiscovery: (discoveryId: string) =>
    request<Discovery>(`/api/discoveries/${discoveryId}/cancel`, {
      method: "POST",
    }),
  scan: (
    discoveryId: string,
    deviceIds: string[],
    profile: ScanProfile,
    fullTcpConfirmed = false,
  ) =>
    request(`/api/discoveries/${discoveryId}/scan`, {
      method: "POST",
      body: JSON.stringify({
        device_ids: deviceIds,
        profile,
        authorization_confirmed: true,
        full_tcp_confirmed: fullTcpConfirmed,
      }),
    }),
  cancelScan: (scanId: string) =>
    request<Scan>(`/api/scans/${scanId}/cancel`, { method: "POST" }),
  scanVulnerabilities: (scanId: string) =>
    request<ScanVulnerabilitySummary | null>(`/api/scans/${scanId}/vulnerabilities`),
  refreshScanVulnerabilities: (scanId: string, limit = 25) =>
    request<ScanVulnerabilitySummary>(
      `/api/scans/${scanId}/vulnerabilities/refresh?limit=${limit}`,
      { method: "POST" },
    ),
  createDiagnostic: (
    agentId: string,
    targetIp: string,
    diagnosticType: AgentDiagnosticType,
    fullTcpConfirmed = false,
  ) =>
    request<AgentDiagnostic>(`/api/agents/${agentId}/diagnostics`, {
      method: "POST",
      body: JSON.stringify({
        target_ip: targetIp,
        diagnostic_type: diagnosticType,
        full_tcp_confirmed: fullTcpConfirmed,
      }),
    }),
  diagnostic: (agentId: string, commandId: string) =>
    request<AgentDiagnostic>(
      `/api/agents/${agentId}/diagnostics/${commandId}`,
    ),
  vulnerabilities: (scanId: string, deviceId: string, cpe: string) =>
    request<VulnerabilityLookup>(
      `/api/scans/${scanId}/devices/${encodeURIComponent(deviceId)}`
      + `/vulnerabilities?cpe=${encodeURIComponent(cpe)}`,
      { method: "POST" },
    ),
};
