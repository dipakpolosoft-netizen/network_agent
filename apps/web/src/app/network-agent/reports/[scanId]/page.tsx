import { ScanReportPage } from "@/components/scan-report-page";

export default async function NetworkAgentScanReportPage({
  params,
}: {
  params: Promise<{ scanId: string }>;
}) {
  const { scanId } = await params;
  return <ScanReportPage scanId={scanId} />;
}
