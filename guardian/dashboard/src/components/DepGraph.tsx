import { Background, Controls, Handle, MarkerType, Position, ReactFlow, ReactFlowProvider, useReactFlow, type Edge, type Node, type NodeChangeset, type NodeProps } from "@xyflow/react";
import { AnimatePresence, motion } from "motion/react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Cube, Lightning, MagnifyingGlass, Warning, X } from "@phosphor-icons/react";
import type { Risk } from "../types";
import { CountUp, RISK, RiskTag, spring } from "../ui";

export interface DNode { id: string; name: string; version: string; direct: boolean; runtime: boolean; dev: boolean; install: boolean; host: string;
  change: "added" | "updated" | null; severity: Risk | null; line?: number;
  vulns: { id: string; severity: Risk; label: string; malicious: boolean; fixed: string[]; summary: string; sources: string[]; reach?: string | null; reach_why?: string | null }[];
  signals: { type: string; severity: Risk; summary: string; hard: boolean }[] }
export interface DGraph { app: string; ref?: string; commit: string; nodes: DNode[]; edges: { s: string; t: string; k: string }[]; headline: Record<string, any>;
  ci: { detector: string; type: string; severity: Risk; component: string; file: string; line?: number; summary: string; label: string; url?: string; excerpt?: string }[];
  unique_links: number;
  ci_stats: { actions: { total: number; pinned: number }; images: { total: number; pinned: number } } }
type Mode = "risk" | "pr" | "direct";
// reveal: the graph has been measured and fitted, so nodes may appear; delay staggers them column by column while entering
type NData = { n?: DNode; app?: boolean; label: string; dim: boolean; onPath: boolean; reveal: boolean; delay: number };

const ORDER: Risk[] = ["info", "low", "medium", "high", "critical"];
export const REACH: Record<string, string> = { imported: "used by app code", via_import: "used via a dependency", not_imported: "not imported",
  dev_only: "dev only", unknown: "use unknown" };
const COL = 270, ROW = 58, MAX_ROWS = 12; // long columns wrap into sub-columns so the graph stays readable

function PkgNode({ data }: NodeProps<Node<NData>>) {
  const n = data.n;
  if (data.app) return (
    <motion.div initial={{ opacity: 0, scale: 0.7 }} animate={data.reveal ? { opacity: 1, scale: 1 } : { opacity: 0, scale: 0.7 }} transition={{ type: "spring", stiffness: 320, damping: 20 }}
      className="flex items-center gap-2.5 rounded-xl border border-accent/50 bg-accent/15 px-4 py-3 shadow-[0_0_40px_-10px_rgb(77_141_255/0.7)]">
      <Handle type="source" position={Position.Right} />
      <Cube size={18} weight="duotone" className="text-accent" />
      <div><div className="text-[13px] font-semibold">{data.label}</div><div className="text-[10.5px] text-muted">application root</div></div>
    </motion.div>);
  const tone = n?.severity ? RISK[n.severity].hex : "#5b616d";
  const hot = n?.severity === "critical";
  return (
    <motion.div initial={{ opacity: 0, scale: 0.85, x: -12 }} animate={data.reveal ? { opacity: data.dim ? 0.28 : 1, scale: 1, x: 0 } : { opacity: 0, scale: 0.85, x: -12 }}
      transition={{ ...spring, delay: data.delay }}
      className={`relative flex w-[230px] items-center gap-2 overflow-hidden rounded-lg border bg-raised py-1.5 pl-3 pr-2 ${hot && !data.dim ? "glow-crit" : ""} ${data.onPath ? "ring-2 ring-accent/70" : ""}`}
      style={{ borderColor: n?.severity ? `${tone}88` : "rgba(255,255,255,0.08)" }}>
      <Handle type="target" position={Position.Left} />
      <span className="absolute inset-y-0 left-0 w-1" style={{ background: tone }} />
      <div className="min-w-0 flex-1">
        <div className="truncate font-mono text-[11.5px] text-ink">{n?.name}<span className="text-faint">@{n?.version}</span></div>
        <div className="flex items-center gap-1.5 text-[10px] text-muted">
          {n?.direct ? "direct" : "transitive"} | {n?.runtime ? "runtime" : "dev"}
          {n?.vulns.length ? <span style={{ color: tone }}>| {n.vulns.length} adv</span> : null}
        </div>
      </div>
      {n?.change && <span className="rounded bg-accent/20 px-1 text-[9.5px] font-semibold text-accent">{n.change === "added" ? "NEW" : "UPD"}</span>}
      {n?.install && <Lightning size={13} weight="fill" className="text-high" aria-label="install script" />}
      {n?.signals.some((s) => s.hard) && <Warning size={13} weight="fill" className="text-crit" aria-label="hard signal" />}
      <Handle type="source" position={Position.Right} />
    </motion.div>);
}
const nodeTypes = { p: PkgNode };

export function useGraph(project?: string | null) {
  const [g, setG] = useState<DGraph | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    setG(null); setErr(null);
    fetch(`/api/depgraph${project ? `?project=${project}` : ""}`).then(async (r) => (r.ok ? setG(await r.json()) : setErr((await r.json()).detail))).catch(() => setErr("backend offline"));
  }, [project]);
  return { g, err };
}

/** BFS from the app root: depth + one shortest parent per package (prod edges preferred). */
export function bfs(g: DGraph) {
  const kids = new Map<string, { t: string; k: string }[]>();
  for (const e of g.edges) kids.set(e.s, [...(kids.get(e.s) ?? []), { t: e.t, k: e.k }]);
  for (const v of kids.values()) v.sort((a, b) => Number(a.k !== "prod") - Number(b.k !== "prod"));
  const depth = new Map<string, number>([["root", 0]]), parent = new Map<string, string>();
  const q = ["root"];
  while (q.length) {
    const u = q.shift()!;
    for (const { t } of kids.get(u) ?? []) if (!depth.has(t)) { depth.set(t, depth.get(u)! + 1); parent.set(t, u); q.push(t); }
  }
  const parents = new Map<string, string[]>();
  for (const e of g.edges) parents.set(e.t, [...(parents.get(e.t) ?? []), e.s]);
  return { kids, depth, parent, parents };
}

export function pathTo(id: string, parent: Map<string, string>) {
  const out: string[] = [];
  for (let c: string | undefined = id; c && c !== "root"; c = parent.get(c)) out.unshift(c);
  return out;
}

function Inner({ g, mode, selected, setSelected, query }: { g: DGraph; mode: Mode; selected: string | null; setSelected: (s: string | null) => void; query: string }) {
  const { fitView } = useReactFlow();
  // React Flow reports each batch of node measurements as "dimensions" changes. (In @xyflow/react 13 the
  // useNodesInitialized flag only updates when the nodes prop changes, so it cannot trigger the first reveal here.)
  const [measured, setMeasured] = useState(0);
  const onNodesChange = useCallback((changes: NodeChangeset<Node<NData>>) => {
    if (changes.getByType("dimensions").length) setMeasured((n) => n + 1);
  }, []);
  const [reveal, setReveal] = useState(false);
  const [entering, setEntering] = useState(true);
  const byId = useMemo(() => new Map(g.nodes.map((n) => [n.id, n])), [g]);
  const tree = useMemo(() => bfs(g), [g]);

  const { nodes, edges, shown } = useMemo(() => {
    let targets: string[];
    if (mode === "direct") targets = g.nodes.filter((n) => n.direct && n.runtime).map((n) => n.id);
    else if (mode === "pr") targets = g.nodes.filter((n) => n.change).map((n) => n.id);
    else targets = g.nodes.filter((n) => n.severity && n.severity !== "info" || n.change).map((n) => n.id);
    const set = new Set<string>();
    for (const t of targets) pathTo(t, tree.parent).forEach((x) => set.add(x));
    if (selected && selected !== "root") {
      pathTo(selected, tree.parent).forEach((x) => set.add(x));
      for (const k of tree.kids.get(selected) ?? []) set.add(k.t);
    }
    const q = query.trim().toLowerCase();
    if (q) g.nodes.filter((n) => n.name.toLowerCase().includes(q)).slice(0, 8).forEach((n) => pathTo(n.id, tree.parent).forEach((x) => set.add(x)));
    const onPath = new Set(selected ? pathTo(selected, tree.parent) : []);
    const cols = new Map<number, string[]>();
    for (const id of set) { const d = tree.depth.get(id) ?? 1; cols.set(d, [...(cols.get(d) ?? []), id]); }
    const rank = (id: string) => -ORDER.indexOf(byId.get(id)?.severity ?? "info") * 10 - (byId.get(id)?.change ? 100 : 0);
    const nodes: Node<NData>[] = [{ id: "root", type: "p", position: { x: 0, y: 0 }, data: { app: true, label: g.app, dim: false, onPath: false, reveal, delay: 0 } }];
    let x = COL;
    let col = 0;
    for (const d of [...cols.keys()].sort((a, b) => a - b)) {
      col += 1;
      const ids = cols.get(d)!;
      ids.sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
      const sub = Math.ceil(ids.length / MAX_ROWS), rows = Math.min(ids.length, MAX_ROWS), x0 = x;
      x += sub * 250 + 90;
      ids.forEach((id, i) => nodes.push({ id, type: "p", position: { x: x0 + Math.floor(i / MAX_ROWS) * 250, y: ((i % MAX_ROWS) - (rows - 1) / 2) * ROW },
        data: { n: byId.get(id), label: id, dim: !!selected && !onPath.has(id) && selected !== id && !(tree.kids.get(selected) ?? []).some((k) => k.t === id), onPath: onPath.has(id) || selected === id,
          reveal, delay: entering ? Math.min(1.1, col * 0.12 + (i % MAX_ROWS) * 0.025) : 0 } }));
    }
    const edges: Edge[] = [];
    for (const id of set) {
      const p = tree.parent.get(id); if (!p) continue;
      const n = byId.get(id); const hot = (onPath.has(id) || selected === id);
      const tone = n?.severity ? RISK[n.severity].hex : "#5b616d";
      edges.push({ id: `${p}->${id}`, source: p, target: id, animated: hot || n?.severity === "critical",
        style: { stroke: hot ? "#4d8dff" : n?.severity ? `${tone}aa` : "rgba(255,255,255,0.16)", strokeWidth: hot ? 2.2 : 1.2,
          strokeDasharray: tree.kids.get(p)?.find((k) => k.t === id)?.k === "dev" ? "4 4" : undefined },
        markerEnd: { type: MarkerType.ArrowClosed, color: hot ? "#4d8dff" : tone } });
    }
    return { nodes, edges, shown: set.size };
  }, [g, mode, selected, query, tree, byId, reveal, entering]);

  // First time every node has a size: fit instantly while hidden, then let the nodes fly in. Later (search results added or
  // removed) the view glides to the new fit instead.
  // The reveal happens once per mount; a ref (not the effect's cleanup) guards it, because this effect re-runs whenever
  // React Flow hands out a new fitView and a cancelled frame would leave the graph hidden.
  const revealed = useRef(false);
  useEffect(() => {
    if (!measured) return;
    if (!revealed.current) {
      revealed.current = true;
      requestAnimationFrame(() => {
        fitView({ padding: 0.12, maxZoom: 1.1, duration: 0 });
        requestAnimationFrame(() => setReveal(true));
      });
      setTimeout(() => setEntering(false), 1800);
      return;
    }
    const t = setTimeout(() => fitView({ padding: 0.12, maxZoom: 1.1, duration: 600 }), 60);
    return () => clearTimeout(t);
  }, [measured, nodes.length, fitView]);

  return (
    <>
      <ReactFlow className={reveal ? "rf-reveal" : "rf-hidden"} nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.1, maxZoom: 1.1 }} minZoom={0.15} maxZoom={1.6} proOptions={{ hideAttribution: true }}
        nodesDraggable={false} nodesConnectable={false} onNodesChange={onNodesChange} onNodeClick={(_, n) => setSelected(n.id === "root" ? null : n.id)} onPaneClick={() => setSelected(null)}>
        <Background gap={24} size={1} color="rgb(255 255 255 / 0.05)" />
        <Controls showInteractive={false} position="bottom-left" />
      </ReactFlow>
      <div className="pointer-events-none absolute bottom-3 right-3 rounded-md border border-line bg-surface/90 px-2 py-1 font-mono text-[10.5px] text-muted">
        showing {shown} of {g.nodes.length} packages | {edges.length} of {g.edges.length} links (one shortest path per package)
      </div>
    </>
  );
}

export function DepGraph({ project }: { project?: string | null } = {}) {
  const { g, err } = useGraph(project);
  const [mode, setMode] = useState<Mode>("risk");
  const [selected, setSelected] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [search, setSearch] = useState("");  // the query the graph uses: typing settles before the layout changes
  useEffect(() => { const t = setTimeout(() => setSearch(query), 250); return () => clearTimeout(t); }, [query]);
  const tree = useMemo(() => (g ? bfs(g) : null), [g]);
  const sel = g && selected ? g.nodes.find((n) => n.id === selected) : null;
  const h = g?.headline;
  const uniqueLinks = g?.unique_links ?? 0;
  const counts = useMemo(() => {
    if (!g) return null;
    const vul = g.nodes.filter((n) => n.vulns.length);
    return { total: g.nodes.length, direct: g.nodes.filter((n) => n.direct).length, runtime: g.nodes.filter((n) => n.runtime).length,
      vulnerable: vul.length, critical: g.nodes.filter((n) => n.severity === "critical").length, added: g.nodes.filter((n) => n.change).length,
      install: g.nodes.filter((n) => n.install).length };
  }, [g]);

  if (err) return <div className="panel p-6 text-sm text-muted">Dependency graph unavailable: <span className="text-crit">{err}</span></div>;
  if (!g || !counts || !tree) return (
    <div className="panel relative grid h-[640px] place-items-center overflow-hidden text-sm text-muted">
      <div className="absolute inset-x-0 top-0 h-px overflow-hidden"><div className="scanbar h-px w-1/3 bg-gradient-to-r from-transparent via-accent to-transparent" /></div>
      <div className="flex flex-col items-center gap-3"><Cube size={28} weight="duotone" className="animate-pulse text-accent" />Building the dependency graph…</div>
    </div>);

  return (
    <section className="flex flex-col gap-4">
      <div className="panel grid grid-cols-2 md:grid-cols-7 md:divide-x divide-line">
        {[["Packages", counts.total, "from manifests and lockfiles"], ["Direct", counts.direct, "declared by the app"], ["Runtime", counts.runtime, "ship to production"],
          ["Links", g.edges.length, `${uniqueLinks.toLocaleString()} unique parent → child pairs`], ["Vulnerable", counts.vulnerable, "OSV + Grype"], ["Critical", counts.critical, "incl. malicious"],
          ["Changed in PR", counts.added, `${h?.changes?.files?.length ?? 0} files touched`]].map(([l, v, s]) => (
          <div key={String(l)} className="px-4 py-3">
            <div className="text-[11px] text-muted">{l}</div>
            <div className={`font-mono text-2xl ${l === "Critical" && Number(v) ? "text-crit" : ""}`}><CountUp value={Number(v)} /></div>
            <div className="text-[10.5px] text-faint">{s}</div>
          </div>))}
      </div>

      <div className="grid gap-4 xl:grid-cols-[1fr_360px]">
        <div className="panel relative h-[680px] overflow-hidden">
          <div className="absolute left-3 top-3 z-10 flex flex-wrap items-center gap-2">
            <div className="relative flex rounded-lg border border-line bg-surface p-0.5 text-xs">
              {([["risk", "Risk paths"], ["pr", "This PR"], ["direct", "Direct runtime deps"]] as [Mode, string][]).map(([m, label]) => (
                <button key={m} onClick={() => { setMode(m); setSelected(null); }} data-on={mode === m}
                  className="relative z-10 whitespace-nowrap rounded-md px-3 py-1.5 text-muted transition-colors hover:text-ink data-[on=true]:text-ink">
                  {mode === m && <motion.span layoutId="dep-mode" className="absolute inset-0 -z-10 rounded-md bg-raised ring-1 ring-inset ring-line" />}
                  {label}
                </button>))}
            </div>
            <label className="flex items-center gap-1.5 rounded-lg border border-line bg-surface px-2 py-1.5 text-xs">
              <MagnifyingGlass size={13} className="text-muted" />
              <span className="sr-only">Find package</span>
              <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Find package"
                className="w-36 bg-transparent text-ink placeholder:text-faint focus:outline-none" />
            </label>
          </div>
          <div className="absolute right-3 top-3 z-10 flex gap-3 rounded-lg border border-line bg-surface/90 px-3 py-1.5 text-[10.5px] text-muted">
            {(["critical", "high", "medium", "low"] as Risk[]).map((r) => <span key={r} className="flex items-center gap-1"><span className="size-2 rounded-full" style={{ background: RISK[r].hex }} />{RISK[r].label}</span>)}
            <span className="flex items-center gap-1"><Lightning size={11} weight="fill" className="text-high" />install script</span>
            <span className="flex items-center gap-1"><span className="rounded bg-accent/20 px-1 text-[9px] font-semibold text-accent">NEW</span>in PR</span>
          </div>
          <div className="absolute inset-x-0 bottom-0 top-12"><ReactFlowProvider><Inner key={mode} g={g} mode={mode} selected={selected} setSelected={setSelected} query={search} /></ReactFlowProvider></div>
        </div>

        <aside className="panel scroll-thin h-[680px] overflow-y-auto p-4">
          <AnimatePresence mode="wait">
            {sel ? (
              <motion.div key={sel.id} initial={{ opacity: 0, x: 12 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -12 }} transition={spring} className="flex flex-col gap-3">
                <div className="flex items-start justify-between gap-2">
                  <div><div className="font-mono text-sm">{sel.name}</div><div className="font-mono text-xs text-muted">version {sel.version}</div></div>
                  <button onClick={() => setSelected(null)} aria-label="Close details" className="rounded p-1 text-muted hover:bg-white/5"><X size={15} /></button>
                </div>
                <div className="flex flex-wrap gap-1.5 text-[11px]">
                  {sel.severity && <RiskTag risk={sel.severity} />}
                  <span className="rounded bg-white/5 px-1.5 py-0.5">{sel.direct ? "direct" : "transitive"}</span>
                  <span className="rounded bg-white/5 px-1.5 py-0.5">{sel.runtime ? "runtime" : "dev only"}</span>
                  {sel.change && <span className="rounded bg-accent/20 px-1.5 py-0.5 text-accent">{sel.change} in this PR</span>}
                  {sel.install && <span className="rounded bg-high/15 px-1.5 py-0.5 text-high">runs install script</span>}
                </div>
                <div>
                  <div className="mb-1 text-[11px] text-muted">How it gets into the app</div>
                  <ol className="flex flex-col gap-1 border-l border-accent/40 pl-3 font-mono text-[11px]">
                    <li className="text-accent">{g.app}</li>
                    {pathTo(sel.id, tree.parent).map((id) => { const n = g.nodes.find((x) => x.id === id); return <li key={id} className={id === sel.id ? "text-ink" : "text-muted"}>{n?.name}@{n?.version}</li>; })}
                  </ol>
                </div>
                <div className="text-[11px] text-muted">Resolved from <span className={`font-mono ${sel.host && !sel.host.includes("npmjs.org") && sel.host !== "localhost:4873" ? "text-crit" : "text-ink"}`}>{sel.host || "n/a"}</span>
                  {sel.line ? <> | line <span className="font-mono text-ink">{sel.line}</span> of its manifest</> : null}</div>
                {sel.signals.length > 0 && (
                  <div className="flex flex-col gap-1.5">
                    <div className="text-[11px] text-muted">Suspicious-change signals</div>
                    {sel.signals.map((s, i) => (
                      <div key={i} className="rounded-md border border-crit/25 bg-crit/8 p-2 text-[11.5px]">
                        <div className="flex items-center justify-between"><span className="font-medium">{s.type.replace(/_/g, " ")}</span><RiskTag risk={s.severity} /></div>
                        <div className="mt-0.5 text-ink/75">{s.summary}</div>
                      </div>))}
                  </div>)}
                <div className="flex flex-col gap-1.5">
                  <div className="text-[11px] text-muted">Advisories ({sel.vulns.length})</div>
                  {!sel.vulns.length && <div className="text-[11.5px] text-faint">None known in OSV or Grype.</div>}
                  {sel.vulns.map((v) => (
                    <div key={v.id} className="rounded-md border border-line bg-raised p-2 text-[11.5px]">
                      <div className="flex items-center justify-between gap-2"><span className="font-mono">{v.id}</span><RiskTag risk={v.severity} /></div>
                      <div className="mt-0.5 text-ink/75">{v.summary || (v.malicious ? "Known malicious package" : "")}</div>
                      <div className="mt-1 flex gap-2 text-[10.5px] text-faint">
                        <span>{v.label?.replace("_", "-")}</span><span>{v.sources.join(" + ")}</span>{v.fixed.length > 0 && <span className="text-ok">fix: {v.fixed.join(", ")}</span>}
                        {v.reach && <span title={v.reach_why ?? ""} className={v.reach === "imported" || v.reach === "via_import" ? "text-high" : "text-faint"}>{REACH[v.reach] ?? v.reach}</span>}
                      </div>
                    </div>))}
                </div>
              </motion.div>
            ) : (
              <motion.div key="help" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex flex-col gap-3 text-sm text-muted">
                <div className="text-ink">Dependency graph</div>
                <p className="text-[12.5px] leading-relaxed">Built from the manifests and lockfiles at commit <span className="font-mono text-ink">{g.commit}</span>, with every package checked in OSV and Grype. No AI is involved in building it.</p>
                <p className="text-[12.5px] leading-relaxed"><b className="text-ink">Risk paths</b> shows how each vulnerable or changed package reaches the app. <b className="text-ink">This PR</b> shows only what the change added. Click any package for its path, source and advisories.</p>
                <div className="mt-2 flex flex-col gap-1.5">
                  <div className="text-[11px]">Highest risk</div>
                  {g.nodes.filter((n) => n.severity === "critical" || n.change).sort((a, b) => Number(!!b.change) - Number(!!a.change)).slice(0, 8).map((n) => (
                    <button key={n.id} onClick={() => setSelected(n.id)} className="flex items-center justify-between rounded-md border border-line bg-raised px-2 py-1.5 text-left font-mono text-[11.5px] text-ink hover:border-accent/50">
                      <span className="truncate">{n.name}@{n.version}</span>
                      <span className="flex items-center gap-1">{n.change && <span className="rounded bg-accent/20 px-1 text-[9.5px] text-accent">NEW</span>}{n.severity && <RiskTag risk={n.severity} />}</span>
                    </button>))}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </aside>
      </div>
    </section>
  );
}
