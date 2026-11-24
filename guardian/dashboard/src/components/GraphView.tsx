import { Background, Controls, Handle, MarkerType, Position, ReactFlow, ReactFlowProvider, useNodesInitialized, useReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import { motion } from "motion/react";
import { useEffect, useMemo } from "react";
import { Cube, FileText, Globe, Package, Warning } from "@phosphor-icons/react";
import type { Finding, Risk, RunState } from "../types";
import { RISK, shortPurl } from "../ui";

type NData = { label: string; sub?: string; kind: "app" | "pkg" | "file" | "host" | "text"; risk?: Risk; cleared?: boolean; count?: number };

const ICON = { app: Cube, pkg: Package, file: FileText, host: Globe, text: Warning };
const ORDER: Risk[] = ["info", "low", "medium", "high", "critical"];

function GNode({ data }: NodeProps<Node<NData>>) {
  const Icon = ICON[data.kind];
  const r = data.risk ? RISK[data.risk] : null;
  const tone = data.cleared ? RISK.low.hex : r?.hex ?? (data.kind === "app" ? "#4d8dff" : "#8a909c");
  const hot = data.risk === "critical" && !data.cleared;
  return (
    <motion.div initial={{ opacity: 0, scale: 0.6 }} animate={{ opacity: 1, scale: 1 }} transition={{ type: "spring", stiffness: 300, damping: 22 }}
      className={`flex min-w-36 items-center gap-2.5 rounded-xl border bg-raised px-3 py-2 ${hot ? "glow-crit" : ""}`}
      style={{ borderColor: `${tone}66` }}>
      <Handle type="target" position={Position.Left} />
      <span className="grid size-7 place-items-center rounded-lg" style={{ background: `${tone}1f` }}><Icon size={15} weight="duotone" style={{ color: tone }} /></span>
      <div className="leading-tight">
        <div className="font-mono text-[12px] text-ink">{data.label}</div>
        <div className="text-[10.5px]" style={{ color: data.sub ? tone : undefined }}>
          {data.cleared ? "cleared by Skeptic" : data.sub}
        </div>
      </div>
      <Handle type="source" position={Position.Right} />
    </motion.div>
  );
}
const nodeTypes = { g: GNode };
const GRAPH_LIMIT = 6;

const HOST = /\b(?:\d{1,3}(?:\.\d{1,3}){3}|localhost):\d{2,5}\b/;

export function buildGraph(findings: Record<string, Finding>, app = "application") {
  const comps = new Map<string, Finding[]>();
  for (const f of Object.values(findings)) comps.set(f.component, [...(comps.get(f.component) ?? []), f]);
  const nodes: Node<NData>[] = [{ id: "app", type: "g", position: { x: 0, y: 0 }, data: { label: app, sub: "application", kind: "app" } }];
  const edges: Edge[] = [];
  const hosts = new Map<string, Risk>();
  const top = (fs: Finding[]) => fs.filter((f) => f.status !== "cleared").reduce<Risk>((m, f) => (ORDER.indexOf(f.risk) > ORDER.indexOf(m) ? f.risk : m), "info");
  const components = [...comps.keys()].filter((c) => !c.startsWith("E-"))
    .sort((a, b) => ORDER.indexOf(top(comps.get(b)!)) - ORDER.indexOf(top(comps.get(a)!)));
  const pkgs = components.slice(0, GRAPH_LIMIT);
  const pkgWithMost = pkgs.filter((c) => c.startsWith("pkg:")).sort((a, b) => (comps.get(b)!.length - comps.get(a)!.length))[0];
  pkgs.forEach((c, i) => {
    const fs = comps.get(c)!;
    const cleared = fs.every((f) => f.status === "cleared");
    const risk = top(fs);
    const kind = c.startsWith("pkg:") ? "pkg" : "file";
    const y = (i - (pkgs.length - 1) / 2) * 65;
    nodes.push({ id: c, type: "g", position: { x: 230, y }, data: { label: kind === "pkg" ? shortPurl(c) : c, kind, risk, cleared,
      sub: `${fs.length} finding${fs.length > 1 ? "s" : ""} | ${RISK[risk].label}` } });
    const hot = !cleared && ORDER.indexOf(risk) >= 3;
    edges.push({ id: `app-${c}`, source: "app", target: c, animated: hot, label: kind === "pkg" ? "depends on" : "changed",
      style: { stroke: hot ? RISK[risk].hex : "rgb(255 255 255 / 0.2)", strokeWidth: hot ? 1.8 : 1 },
      markerEnd: { type: MarkerType.ArrowClosed, color: hot ? RISK[risk].hex : "#5b616d" } });
    for (const f of fs) {
      const h = f.summary.match(HOST)?.[0];
      if (h && f.status !== "cleared") {
        hosts.set(h, ORDER.indexOf(f.risk) > ORDER.indexOf(hosts.get(h) ?? "info") ? f.risk : hosts.get(h) ?? f.risk);
        const id = `${c}-${h}`;
        if (!edges.find((e) => e.id === id)) edges.push({ id, source: c, target: `host:${h}`, animated: true,
          label: kind === "pkg" ? "resolved from" : "redirects to",
          style: { stroke: RISK.critical.hex, strokeWidth: 1.6 }, markerEnd: { type: MarkerType.ArrowClosed, color: RISK.critical.hex } });
      }
    }
  });
  [...hosts.entries()].forEach(([h, risk], i) => nodes.push({ id: `host:${h}`, type: "g", position: { x: 470, y: i * 92 - (hosts.size - 1) * 46 },
    data: { label: h, sub: "registry not on allow-list", kind: "host", risk } }));
  const texts = [...comps.keys()].filter((c) => c.startsWith("E-")).slice(0, GRAPH_LIMIT);
  texts.forEach((c, i) => {
    const fs = comps.get(c)!;
    nodes.push({ id: c, type: "g", position: { x: 470, y: (hosts.size + i) * 92 - (hosts.size - 1) * 46 + 20 },
      data: { label: "README text", sub: fs[0].type.replace("_", " "), kind: "text", risk: top(fs) } });
    if (pkgWithMost) edges.push({ id: `${pkgWithMost}-${c}`, source: pkgWithMost, target: c, label: "ships", style: { stroke: RISK.high.hex, strokeDasharray: "4 4" } });
  });
  return { nodes, edges, total: comps.size, shown: pkgs.length + texts.length };
}

function FitOnChange({ count }: { count: number }) {
  const { fitView } = useReactFlow();
  const ready = useNodesInitialized();
  useEffect(() => {
    // New nodes are measured a frame or two after they mount; fit twice so late measurements are included.
    const fit = () => fitView({ padding: 0.2, maxZoom: 1.1, duration: 450 });
    const a = setTimeout(fit, 120), b = setTimeout(fit, 600);
    return () => { clearTimeout(a); clearTimeout(b); };
  }, [count, ready, fitView]);
  return null;
}

export function GraphView({ state, app }: { state: RunState | null; app?: string }) {
  const { nodes, edges, total, shown } = useMemo(() => buildGraph(state?.findings ?? {}, app), [state?.findings, app]);
  return (
    <section className="panel flex min-w-0 flex-col overflow-hidden">
      <div className="flex items-center justify-between gap-3 px-4 py-3 text-sm">
        <span className="font-medium">Finding graph</span>
        {total > 0 && <span className="text-xs text-muted">{shown} of {total} components · see all in Findings</span>}
      </div>
      {total === 0 ? <p className="px-4 pb-4 text-sm text-muted">The graph shows components with investigation findings.</p> :
      <div className="h-[320px] min-w-0">
        <ReactFlowProvider>
        <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.2, maxZoom: 1.1 }}
          proOptions={{ hideAttribution: true }} minZoom={0.1} nodesDraggable={false} nodesConnectable={false} panOnScroll={false} zoomOnScroll={false}
          defaultEdgeOptions={{ labelStyle: { fill: "#8a909c", fontSize: 10 }, labelBgStyle: { fill: "#111318" } }}>
          <Background gap={22} size={1} color="rgb(255 255 255 / 0.05)" />
          <Controls showInteractive={false} />
          <FitOnChange count={nodes.length + edges.length} />
        </ReactFlow>
        </ReactFlowProvider>
      </div>}
    </section>
  );
}
