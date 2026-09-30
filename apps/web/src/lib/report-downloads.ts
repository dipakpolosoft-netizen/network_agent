import { api, type Scan } from "./api.ts";
import { createScanPdf } from "./pdf-report.ts";

function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function serializeScanJson(scan: Scan): string {
  return JSON.stringify(scan, null, 2);
}

export async function downloadScanJson(scanId: string): Promise<void> {
  const scan = await api.scanReport(scanId);
  saveBlob(
    new Blob([serializeScanJson(scan)], { type: "application/json" }),
    `forgesec-scan-${scan.scan_id}.json`,
  );
}

export async function downloadScanPdf(scanId: string): Promise<void> {
  const scan = await api.scanReport(scanId);
  const response = await fetch("/logos/forge-sec-logo.png");
  if (!response.ok) throw new Error("ForgeSec logo could not be loaded for the PDF export");
  const logo = new Uint8Array(await response.arrayBuffer());
  const bytes = await createScanPdf(scan, logo);
  saveBlob(
    new Blob([Uint8Array.from(bytes)], { type: "application/pdf" }),
    `forgesec-scan-${scan.scan_id}.pdf`,
  );
}
