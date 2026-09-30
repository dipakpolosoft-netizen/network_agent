"use client";

import { LoaderCircle, RefreshCw } from "lucide-react";
import { useEffect, useState } from "react";

import { type AssetDeviceProfile, api } from "@/lib/api";
import { roleEstimate } from "@/lib/device-identity";

function observedAt(value: string) {
  return new Date(value).toLocaleString();
}

function uptime(seconds: number | null) {
  if (seconds == null) return "Not reported";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  return days ? `${days}d ${hours}h at observation` : `${hours}h at observation`;
}

export function AssetDeviceDepth({ assetId }: { assetId: string }) {
  const [profile, setProfile] = useState<AssetDeviceProfile | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refresh, setRefresh] = useState(0);
  const [shown, setShown] = useState(12);

  useEffect(() => {
    let active = true;
    api.assetDeviceProfile(assetId).then((result) => {
      if (active) { setProfile(result); setError(null); setLoading(false); }
    }).catch((cause) => {
      if (active) { setError(cause instanceof Error ? cause.message : "Device profile could not be loaded"); setLoading(false); }
    });
    return () => { active = false; };
  }, [assetId, refresh]);

  const discovery = profile?.discovery;
  const snmp = profile?.snmp;
  return <details className="asset-device-depth">
    <summary><span>Device depth</span><small>{loading ? "Loading" : snmp ? `${snmp.interfaces.length} ${snmp.interfaces.length === 1 ? "interface" : "interfaces"} sampled` : "Discovery evidence"}</small></summary>
    <div className="asset-device-depth-body">
      <div className="asset-device-depth-head"><strong>Discovery evidence</strong><button className="icon-button small" type="button" title="Refresh device profile" aria-label="Refresh device profile" onClick={() => { setLoading(true); setRefresh((value) => value + 1); }}><RefreshCw size={14} /></button></div>
      {loading && !profile && <p className="asset-muted"><LoaderCircle className="spin" size={14} /> Loading device profile</p>}
      {error && <p className="inline-error" role="alert">{error}</p>}
      {discovery ? <><small className="asset-depth-source" title={discovery.discovery_id}>Observed {observedAt(discovery.observed_at)} at {discovery.ip} - Discovery {discovery.discovery_id.slice(0, 8)}</small><dl className="asset-depth-facts"><dt>Role estimate</dt><dd>{roleEstimate(discovery.device_type, discovery.classification_confidence)}</dd><dt>Detection</dt><dd>{discovery.discovery_reason ?? "Not reported"}</dd><dt>Latency</dt><dd>{discovery.latency_ms == null ? "Not measured" : `${discovery.latency_ms.toFixed(1)} ms at discovery`}</dd></dl></> : !loading && <p className="asset-muted">No discovery observation is stored for this asset.</p>}
      {snmp?.latest_discovery && discovery?.hostname && snmp.name && discovery.hostname.toLowerCase() !== snmp.name.toLowerCase() && <p className="asset-muted asset-identity-mismatch">Hostname {discovery.hostname} differs from SNMP system name {snmp.name}. Verify the device identity.</p>}
      <div className="asset-device-depth-head"><strong>SNMP system snapshot</strong>{snmp && !snmp.latest_discovery && <span className="asset-depth-historical">Older discovery</span>}</div>
      {snmp ? <><small className="asset-depth-source" title={snmp.discovery_id}>Observed {observedAt(snmp.observed_at)} at {snmp.ip} - Discovery {snmp.discovery_id.slice(0, 8)}</small><dl className="asset-depth-facts"><dt>System name</dt><dd>{snmp.name ?? "Not reported"}</dd><dt>System description</dt><dd>{snmp.description ?? "Not reported"}</dd><dt>Object ID</dt><dd>{snmp.object_id ?? "Not reported"}</dd><dt>Uptime</dt><dd>{uptime(snmp.uptime_seconds)}</dd><dt>Interfaces</dt><dd>{snmp.interfaces.length} sampled{snmp.reported_interface_count == null ? "" : ` / ${snmp.reported_interface_count} reported`}{snmp.interfaces_limited ? " (sample limited)" : ""}</dd></dl>{snmp.interfaces.length > 0 && <div className="asset-depth-interfaces">{snmp.interfaces.slice(0, shown).map((item) => <div key={item.index}><div><strong>{item.name || item.description || `Interface ${item.index}`}</strong><small>{[item.alias, item.interface_type].filter(Boolean).join(" - ") || `Index ${item.index}`}</small></div><div><span className={`asset-depth-status ${item.oper_status === "up" ? "up" : ""}`}>{item.oper_status ?? "unknown"}</span><small>Admin {item.admin_status ?? "unknown"}{item.speed_mbps == null ? "" : ` - ${item.speed_mbps} Mbps`}</small></div></div>)}</div>}{snmp.interfaces.length > shown && <button className="button secondary compact asset-more" type="button" onClick={() => setShown((value) => value + 12)}>Show more interfaces ({snmp.interfaces.length - shown})</button>}</> : !loading && <p className="asset-muted">No SNMP system data was recorded for this asset.</p>}
    </div>
  </details>;
}
