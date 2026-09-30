import type { HostResult } from "./api";

export function hostnameSourceLabel(source: HostResult["hostname_source"]): string {
  if (source === "nmap") return "Nmap";
  if (source === "discovery") return "Discovery";
  if (source === "snmp") return "SNMP";
  return "Source not recorded";
}
