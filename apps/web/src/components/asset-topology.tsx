"use client";

import dagre from "@dagrejs/dagre";
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MiniMap,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import { Cable, HardDrive, LoaderCircle, Network, RefreshCw } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { api, type TopologyGraph, type TopologyLink, type TopologyNode } from "@/lib/api";

const NODE_WIDTH = 178;
const NODE_HEIGHT = 70;

type CanvasNode = Node<{
  label: string;
  subtitle: string;
  observedOnly: boolean;
  deviceType: string | null;
  vertical: boolean;
}, "topology">;

type LinkGroup = { id: string; source: string; target: string; links: TopologyLink[] };

function TopologyNodeView({ data }: NodeProps<CanvasNode>) {
  return <div className={`topology-node ${data.observedOnly ? "unresolved" : ""}`}>
    <Handle type="target" position={data.vertical ? Position.Top : Position.Left} className="topology-handle" />
    <span className="topology-node-icon">{data.deviceType === "switch" || data.deviceType === "router" ? <Network size={17} /> : <HardDrive size={17} />}</span>
    <span className="topology-node-copy"><strong title={data.label}>{data.label}</strong><small>{data.subtitle}</small></span>
    <Handle type="source" position={data.vertical ? Position.Bottom : Position.Right} className="topology-handle" />
  </div>;
}

const nodeTypes = { topology: TopologyNodeView };

function groupedLinks(links: TopologyLink[]): LinkGroup[] {
  const groups = new Map<string, LinkGroup>();
  for (const link of links) {
    const endpoints = [link.source, link.target].sort();
    const id = endpoints.join("|");
    const group = groups.get(id);
    if (group) group.links.push(link);
    else groups.set(id, { id, source: link.source, target: link.target, links: [link] });
  }
  return [...groups.values()];
}

function layout(nodes: TopologyNode[], groups: LinkGroup[], vertical: boolean): { nodes: CanvasNode[]; edges: Edge[] } {
  const graph = new dagre.graphlib.Graph();
  graph.setGraph({ rankdir: vertical ? "TB" : "LR", nodesep: 28, ranksep: vertical ? 58 : 104, marginx: 20, marginy: 20 });
  graph.setDefaultEdgeLabel(() => ({}));
  nodes.forEach((node) => graph.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT }));
  groups.forEach((group) => graph.setEdge(group.source, group.target));
  dagre.layout(graph);
  return {
    nodes: nodes.map((node) => {
      const position = graph.node(node.id);
      return {
        id: node.id,
        type: "topology",
        position: { x: position.x - NODE_WIDTH / 2, y: position.y - NODE_HEIGHT / 2 },
        data: {
          label: node.label,
          subtitle: node.observed_only ? "LLDP neighbor - not inventoried" : `${node.ip ?? ""} ${node.device_type ?? ""}`.trim(),
          observedOnly: node.observed_only,
          deviceType: node.device_type,
          vertical,
        },
        draggable: false,
      };
    }),
    edges: groups.map((group) => ({
      id: group.id,
      source: group.source,
      target: group.target,
      type: "smoothstep",
      animated: false,
      style: { stroke: group.links.every((link) => link.stale) ? "#b77709" : "#108760", strokeWidth: 2, strokeDasharray: group.links.every((link) => link.stale) ? "5 4" : undefined },
    })),
  };
}

function labelFor(nodes: TopologyNode[], id: string): string {
  return nodes.find((node) => node.id === id)?.label ?? "Unknown neighbor";
}

export function AssetTopology({ siteId, onOpenAsset }: { siteId: string; onOpenAsset: (assetId: string) => void }) {
  const [vertical, setVertical] = useState(false);
  const [includeStale, setIncludeStale] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const [data, setData] = useState<TopologyGraph | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);

  useEffect(() => {
    const query = window.matchMedia("(max-width: 560px)");
    const sync = () => setVertical(query.matches);
    sync();
    query.addEventListener("change", sync);
    return () => query.removeEventListener("change", sync);
  }, []);

  useEffect(() => {
    let current = true;
    api.topology(siteId, includeStale).then((result) => {
      if (!current) return;
      setData(result);
      setError(null);
    }).catch((cause) => {
      if (current) setError(cause instanceof Error ? cause.message : "Topology could not be loaded");
    }).finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [siteId, includeStale, refreshKey]);

  const groups = useMemo(() => groupedLinks(data?.links ?? []), [data]);
  const flow = useMemo(() => layout(data?.nodes ?? [], groups, vertical), [data, groups, vertical]);
  const selectedNode = data?.nodes.find((node) => node.id === selectedNodeId);
  const selectedGroup = groups.find((group) => group.id === selectedGroupId) ?? groups[0];

  return <section className="topology-workspace" aria-label="Site topology">
    <div className="topology-toolbar">
      <div className="topology-totals"><strong>{data?.total_links ?? 0} observed links</strong><span>{data?.observed_assets ?? 0} LLDP sources | {data?.unlinked_assets ?? 0} assets without mapped links</span></div>
      <div className="topology-actions"><label><input type="checkbox" checked={includeStale} onChange={(event) => { setLoading(true); setIncludeStale(event.target.checked); }} />Show stale</label><button className="icon-button" type="button" title="Refresh topology" aria-label="Refresh topology" onClick={() => { setLoading(true); setRefreshKey((value) => value + 1); }}><RefreshCw size={15} /></button></div>
    </div>
    {error && <div className="inline-error" role="alert">{error}</div>}
    {loading && !data ? <div className="topology-empty"><LoaderCircle className="spin" size={20} />Loading topology</div> : data && data.links.length ? <>
      <div className="topology-main">
        <div className="topology-canvas" role="region" aria-label={`LLDP topology with ${data.nodes.length} devices and ${groups.length} connections`}>
          <ReactFlow key={vertical ? "vertical" : "horizontal"} nodes={flow.nodes} edges={flow.edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: vertical ? 0.08 : 0.2, minZoom: vertical ? 0.68 : 0.2, maxZoom: 1.25 }} minZoom={0.2} maxZoom={2} nodesConnectable={false} nodesDraggable={false} edgesReconnectable={false} onNodeClick={(_event, node) => { setSelectedNodeId(node.id); setSelectedGroupId(null); }} onEdgeClick={(_event, edge) => { setSelectedGroupId(edge.id); setSelectedNodeId(null); }}>
            <Background variant={BackgroundVariant.Dots} gap={18} size={1} color="#d9e4e0" />
            <Controls showInteractive={false} />
            {data.nodes.length > 18 && <MiniMap pannable zoomable nodeColor={(node) => node.data.observedOnly ? "#b77709" : "#108760"} />}
          </ReactFlow>
        </div>
        <aside className="topology-inspector" aria-label="Topology evidence">
          {selectedNode ? <><span className="eyebrow">DEVICE</span><h3>{selectedNode.label}</h3><dl><dt>Identity</dt><dd>{selectedNode.observed_only ? "LLDP only" : "Inventoried asset"}</dd><dt>IP address</dt><dd>{selectedNode.ip ?? "Not observed"}</dd><dt>Type</dt><dd>{selectedNode.device_type ?? "Unknown"}</dd></dl>{selectedNode.asset_id && <button className="button secondary compact" onClick={() => onOpenAsset(selectedNode.asset_id!)}><HardDrive size={14} />Open asset</button>}</> : selectedGroup ? <><span className="eyebrow">LLDP EVIDENCE</span><h3>{labelFor(data.nodes, selectedGroup.source)} <span aria-hidden="true">to</span> {labelFor(data.nodes, selectedGroup.target)}</h3><div className="topology-evidence-list">{selectedGroup.links.map((link) => <div key={link.id}><strong>{link.local_port} <span aria-hidden="true">to</span> {link.remote_port ?? "Remote port unknown"}</strong><span>Reported by {labelFor(data.nodes, `asset:${link.reported_by}`)}</span><small>{new Date(link.observed_at).toLocaleString()} | {link.stale ? "Stale" : "Current"}</small></div>)}</div></> : <><Cable size={18} /><p>Select a device or connection.</p></>}
        </aside>
      </div>
      <div className="topology-footer"><span><i className="topology-key current" />Current LLDP</span><span><i className="topology-key stale" />Stale LLDP</span><span><i className="topology-key unknown" />Unresolved neighbor</span>{data.stale_hidden > 0 && <span>{data.stale_hidden} stale observations hidden</span>}{data.truncated && <span>Showing the latest 1,000 of {data.total_links} links</span>}</div>
    </> : <div className="topology-empty"><Network size={20} /><strong>No observed LLDP links</strong><span>{data?.stale_hidden ? `${data.stale_hidden} old observations are hidden. Enable Show stale to inspect them.` : "No LLDP neighbor evidence has been collected for this site."}</span></div>}
  </section>;
}
