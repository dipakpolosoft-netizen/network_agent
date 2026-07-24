export const API_URL =
  process.env.NEXT_PUBLIC_TELESEC_API_URL?.replace(/\/+$/, "") ?? "";
export const AGENT_SERVER_URL =
  process.env.NEXT_PUBLIC_TELESEC_AGENT_SERVER_URL?.replace(/\/+$/, "") ??
  "http://127.0.0.1:8000";

export type Agent = {
  agent_id: string;
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
};

export type Device = {
  device_id: string;
  ip: string;
  hostname: string | null;
  mac: string | null;
  vendor: string | null;
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
};

export type PortResult = {
  protocol: "tcp" | "udp";
  port: number;
  state: string;
  service: string | null;
  product: string | null;
  version: string | null;
  cpe: string | null;
};

export type HostResult = {
  device_id: string;
  ip: string;
  status: string;
  hostname: string | null;
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
  retrieved_at: string;
  cached: boolean;
  vulnerabilities: VulnerabilityMatch[];
  notice: string;
};

export type Scan = {
  scan_id: string;
  command_id: string;
  discovery_id: string;
  agent_id: string;
  profile: "standard" | "full_tcp";
  status: string;
  total: number;
  queued: number;
  running: number;
  completed: number;
  failed: number;
  cancelled: number;
  cancel_requested: boolean;
  stage: string | null;
  targets: Array<{
    device_id: string;
    ip: string;
    hostname: string | null;
    status: string;
  }>;
  results: HostResult[];
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
};

export type Enrollment = {
  enrollment_id: string;
  enrollment_token: string;
  expires_at: string;
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
    cache: "no-store",
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail ?? `Request failed with HTTP ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  agents: () => request<Agent[]>("/api/agents"),
  discoveries: (agentId?: string) =>
    request<Discovery[]>(
      `/api/discoveries${agentId ? `?agent_id=${agentId}` : ""}`,
    ),
  scans: (agentId?: string) =>
    request<Scan[]>(`/api/scans${agentId ? `?agent_id=${agentId}` : ""}`),
  createEnrollment: (label: string, siteName: string) =>
    request<Enrollment>("/api/enrollments", {
      method: "POST",
      body: JSON.stringify({ label, site_name: siteName || null }),
    }),
  discover: (
    agentId: string,
    scope: string | null,
    mode: "selected" | "all",
  ) =>
    request(`/api/agents/${agentId}/discover`, {
      method: "POST",
      body: JSON.stringify({ authorization_confirmed: true, scope, mode }),
    }),
  cancelDiscovery: (discoveryId: string) =>
    request<Discovery>(`/api/discoveries/${discoveryId}/cancel`, {
      method: "POST",
    }),
  scan: (
    discoveryId: string,
    deviceIds: string[],
    profile: "standard" | "full_tcp",
  ) =>
    request(`/api/discoveries/${discoveryId}/scan`, {
      method: "POST",
      body: JSON.stringify({
        device_ids: deviceIds,
        profile,
        authorization_confirmed: true,
      }),
    }),
  cancelScan: (scanId: string) =>
    request<Scan>(`/api/scans/${scanId}/cancel`, { method: "POST" }),
  vulnerabilities: (scanId: string, deviceId: string, cpe: string) =>
    request<VulnerabilityLookup>(
      `/api/scans/${scanId}/devices/${encodeURIComponent(deviceId)}`
      + `/vulnerabilities?cpe=${encodeURIComponent(cpe)}`,
    ),
};
