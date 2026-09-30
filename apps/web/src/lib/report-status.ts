import type { Scan } from "./api";

export function scanResultCoverage(scan: Pick<Scan, "total" | "results">) {
  const saved = Math.min(scan.total, new Set(scan.results.map((result) => result.device_id)).size);
  return {
    saved,
    missing: Math.max(0, scan.total - saved),
    percent: scan.total ? Math.round((saved / scan.total) * 100) : 0,
  };
}

export function scanCoverageNotice(scan: Pick<Scan, "status" | "total" | "completed" | "failed" | "cancelled">): string | null {
  if (["queued", "running", "cancelling"].includes(scan.status)) {
    return `This is an in-progress snapshot: ${scan.completed} of ${scan.total} targets completed. Download again after the run finishes for final evidence.`;
  }
  if (scan.status !== "completed" || scan.failed > 0 || scan.cancelled > 0 || scan.completed < scan.total) {
    return `Coverage is incomplete: ${scan.completed} of ${scan.total} targets completed; ${scan.failed} failed and ${scan.cancelled} cancelled. Missing results and zero findings do not establish that a host is clear.`;
  }
  return null;
}
