import type { PortResult, Scan } from "@/lib/api";

export function portCpes(port: PortResult): string[] {
  return Array.from(new Set([port.cpe, ...(port.cpes ?? [])].filter(Boolean) as string[]));
}

export function portServiceLabel(port: PortResult): string {
  const service = port.service?.trim();
  if (!service) return "Not identified";
  return port.method === "table" ? `${service} (port lookup)` : service;
}

export function portEvidenceSourceLabel(port: PortResult): string {
  return port.evidence_source === "nmap" ? "Nmap" : "Not recorded";
}

export function portEvidenceTimeLabel(port: PortResult): string {
  if (!port.recorded_at) return "Not recorded";
  const date = new Date(port.recorded_at);
  return Number.isNaN(date.getTime()) ? "Not recorded" : date.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC");
}

export function countPortStates(ports: PortResult[]) {
  const counts = { open: 0, openFiltered: 0, filtered: 0, tcpOpen: 0, udpOpen: 0 };
  for (const port of ports) {
    if (port.state === "open") {
      counts.open += 1;
      if (port.protocol === "tcp") counts.tcpOpen += 1;
      if (port.protocol === "udp") counts.udpOpen += 1;
    } else if (port.state === "open|filtered") {
      counts.openFiltered += 1;
    } else if (port.state === "filtered") {
      counts.filtered += 1;
    }
  }
  return counts;
}

export function countScanPortStates(scan: Scan) {
  const counts = { open: 0, openFiltered: 0, filtered: 0, tcpOpen: 0, udpOpen: 0 };
  for (const result of scan.results) {
    const host = countPortStates(result.ports);
    counts.open += host.open;
    counts.openFiltered += host.openFiltered;
    counts.filtered += host.filtered;
    counts.tcpOpen += host.tcpOpen;
    counts.udpOpen += host.udpOpen;
  }
  return counts;
}
