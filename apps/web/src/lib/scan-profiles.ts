import type { ApprovedScope, ScanProfile, ScanProfilePlan } from "./api";

export const NETWORK_SERVICE_TCP_PORTS = [22, 53, 80, 443, 445, 3389, 8080, 8443];
export const NETWORK_SERVICE_UDP_PORTS = [53, 67, 69, 123, 137, 161, 500, 4500, 5353, 1900];

export const SCAN_PROFILE_OPTIONS: Array<{ value: ScanProfile; label: string; hint: string }> = [
  { value: "inventory", label: "Inventory", hint: "Nmap top 200 TCP ports, light version checks, up to 8 min per host. No UDP." },
  { value: "network_services", label: "Network services", hint: "Fixed 8 TCP and 10 UDP ports, light versions, up to 12 min per host. Elevated probe required; UDP may be inconclusive." },
  { value: "standard", label: "Standard", hint: "Nmap top 1,000 TCP ports, light versions, up to 15 min per host. No UDP." },
  { value: "full_tcp", label: "Full TCP", hint: "TCP ports 1-65535, deeper versions, up to 45 min for one target. No UDP." },
];

export function scanProfileLabel(profile: string): string {
  return SCAN_PROFILE_OPTIONS.find((item) => item.value === profile)?.label ?? profile.replaceAll("_", " ");
}

export function approvedProfilesForTargets(scopes: Pick<ApprovedScope, "cidr" | "scan_profiles">[], targetScopes: string[]): ScanProfile[] {
  if (!targetScopes.length) return [];
  const uniqueScopes = [...new Set(targetScopes)];
  const approvals = uniqueScopes.map((cidr) => scopes.find((scope) => scope.cidr === cidr));
  if (approvals.some((scope) => !scope)) return [];
  return SCAN_PROFILE_OPTIONS.map((option) => option.value).filter((profile) =>
    approvals.every((scope) => scope?.scan_profiles.includes(profile)),
  );
}

export function profilePlanLines(plan: ScanProfilePlan | null | undefined): string[] {
  if (!plan) return ["Profile command details were not saved with this historical scan."];
  const tcp = plan.tcp_all_ports
    ? "TCP 1-65535"
    : plan.tcp_top_ports
      ? `Nmap top ${plan.tcp_top_ports} TCP ports`
      : `TCP ${plan.tcp_ports.join(", ") || "none"}`;
  const udp = plan.udp_ports.length ? `UDP ${plan.udp_ports.join(", ")}` : "No UDP ports";
  const version = plan.version_detection === "full" ? "Deeper service versions" : "Light service versions";
  const os = plan.os_detection === "when_privileged" ? "OS fingerprint attempted only with elevated probe privileges" : "OS fingerprint not requested";
  const output = plan.open_only_output
    ? "Only open or possibly-open port rows requested; unlisted ports are not proven closed."
    : "All reported port states retained.";
  return [
    `${tcp}; ${udp}`,
    `${version}; ${os}; up to ${Math.round(plan.host_timeout_seconds / 60)} min per host.`,
    `${plan.assume_host_up ? "Host assumed up for scanning. " : ""}${output}${plan.udp_ports.length ? " UDP open|filtered is inconclusive." : ""} Coverage and versions are not guaranteed.`,
  ];
}
