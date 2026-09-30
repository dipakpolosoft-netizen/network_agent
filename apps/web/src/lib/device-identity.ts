export function discoveryDeviceName(device: { is_agent: boolean; hostname: string | null; snmp_name: string | null; ip: string }): string {
  if (device.is_agent) return "ForgeSec collector";
  return device.hostname?.trim() || device.snmp_name?.trim() || `Host ${device.ip}`;
}

export function roleEstimate(role: string | null, score: number | null): string {
  if (!role || role === "unknown") return "Role unknown";
  const strength = score != null && score >= 0.85 ? "strong" : score != null && score >= 0.7 ? "moderate" : "limited";
  const label = role.replaceAll("-", " ").replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
  return `${label} (${strength} evidence)`;
}
