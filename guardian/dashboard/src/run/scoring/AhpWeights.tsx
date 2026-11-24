/* AI-advised AHP weights, ported from the contextual-scoring branch (components/AhpAdvisor.tsx). Changes: import paths,
   `onChanged` so the run's scores reload after an approval or reset, and project ids are URL-encoded. */
import { motion } from "motion/react";
import { useCallback, useEffect, useState } from "react";
import { ArrowDown, ArrowUp, Info, Robot, Scales, ShieldCheck } from "@phosphor-icons/react";
import type { Risk } from "../../types";
import { RiskTag, spring } from "../../ui";

interface Cell { row: string; col: string; value: number; baseline: number; changed: boolean; reason: string }
interface Matrix {
  id: string; status: string; source: string; created: string; cells: Cell[]; matrix: number[][]; weights: Record<string, number>; baseline_weights: Record<string, number>;
  drift: Record<string, number>; max_drift: number; consistency_ratio: number; claim_kind: string;
  profile: { facts: { fact: string; value: unknown; source: string }[]; confirmed: Record<string, string> };
  comparison: { rows: { id: string; title: string; level: Risk; hard_signal: boolean; baseline_score: number; baseline_rank: number; proposed_score: number; proposed_rank: number; rank_change: number }[];
    moved: number; note: string };
  decision: { decision: string; reviewer: string; note: string; at: string } | null;
}
interface Overview {
  baseline: { criteria: string[]; matrix: number[][]; weights: Record<string, number>; consistency_ratio: number };
  limits: { max_drift: number; consistency_limit: number; saaty: string };
  active: Matrix | null; proposals: Matrix[]; history: Matrix[]; confirmed: Record<string, string>;
  options: { internet_facing: string[]; data_sensitivity: string[]; deployment: string[]; replay_presets: string[] };
}

const NAME: Record<string, string> = { exploitation: "Being attacked", impact: "Impact", exposure: "Exposure", introduced: "Introduced by PR", actionable: "Fix available" };
const frac = (x: number) => (x >= 1 ? String(Math.round(x * 100) / 100) : `1/${Math.round(1 / x)}`);

async function api(path: string, init?: RequestInit) {
  const r = await fetch(path, init);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.detail ?? `HTTP ${r.status}`);
  return j;
}
const post = (path: string, body: unknown) => api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

function Bars({ w, base }: { w: Record<string, number>; base: Record<string, number> }) {
  return (
    <div className="flex flex-col gap-1.5">
      {Object.keys(base).map((k) => {
        const d = w[k] - base[k];
        return (
          <div key={k} className="grid grid-cols-[120px_1fr_auto] items-center gap-2 text-[12px]">
            <span className="text-muted">{NAME[k]}</span>
            <div className="relative h-2 rounded-full bg-white/5">
              <div className="absolute inset-y-0 left-0 rounded-full bg-accent/70" style={{ width: `${w[k] * 100}%` }} />
              <div className="absolute inset-y-[-2px] w-0.5 bg-ink/70" style={{ left: `${base[k] * 100}%` }} title="baseline" />
            </div>
            <span className="font-mono text-[11.5px]">{(w[k] * 100).toFixed(1)}% <span className={Math.abs(d) < 0.0005 ? "text-faint" : d > 0 ? "text-ok" : "text-high"}>{d >= 0 ? "+" : ""}{(d * 100).toFixed(1)}</span></span>
          </div>);
      })}
    </div>);
}

function MatrixCard({ m, baseline, reload, project }: { m: Matrix; baseline: Record<string, number>; reload: () => void; project?: string | null }) {
  const [reviewer, setReviewer] = useState("");
  const [note, setNote] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const decide = (decision: string) => post(`/api/ahp/${m.id}/decision`, { project: project ?? null, decision, reviewer, note: note || null }).then(reload).catch((e) => setErr(e.message));
  return (
    <motion.article initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={spring} className="panel flex flex-col gap-4 px-5 py-4">
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div><span className="font-mono text-[13px]">{m.id}</span> <span className="text-[12px] text-faint">· {m.source}</span></div>
        <span className="rounded-md bg-med/10 px-1.5 py-0.5 text-[11px] text-med ring-1 ring-inset ring-med/30">{m.source.startsWith("scripted replay") ? "Scripted proposal · no AI called" : "AI proposal (inferred)"} · alternative ranking, not yet used</span>
      </header>
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="flex flex-col gap-2">
          <div className="text-[11px] font-medium uppercase tracking-wide text-faint">Resulting AHP weights vs baseline (tick = baseline)</div>
          <Bars w={m.weights} base={baseline} />
          <div className="text-[12px] text-muted">Consistency ratio <span className="font-mono text-ink">{m.consistency_ratio}</span> (limit 0.10) · each weight within ±{(m.max_drift * 100).toFixed(0)} points of baseline · computed by code, not by the AI.</div>
        </div>
        <div className="flex flex-col gap-1.5">
          <div className="text-[11px] font-medium uppercase tracking-wide text-faint">Judgements (changed cells highlighted)</div>
          <ul className="scroll-thin max-h-56 space-y-1 overflow-auto text-[12.5px]">{m.cells.map((c) => (
            <li key={c.row + c.col} className={c.changed ? "text-ink" : "text-faint"}>
              <span className="font-mono text-[11.5px]">{NAME[c.row]} vs {NAME[c.col]}: {frac(c.baseline)}{c.changed && <> → <span className="text-accent">{frac(c.value)}</span></>}</span>
              <div className="text-muted">{c.reason}</div></li>))}</ul>
        </div>
      </div>
      <div>
        <div className="mb-1 text-[11px] font-medium uppercase tracking-wide text-faint">Alternative ranking next to the baseline · {m.comparison.moved} finding(s) move</div>
        <div className="scroll-thin max-h-64 overflow-auto">
          <table className="w-full min-w-[640px] text-[12.5px]">
            <thead className="text-left text-[11px] text-faint"><tr><th className="py-1">Finding</th><th>Level</th><th className="text-right">Baseline</th><th className="text-right">Proposed</th><th className="text-right">Move</th></tr></thead>
            <tbody>{m.comparison.rows.map((r) => (
              <tr key={r.id} className="border-t border-line/60"><td className="max-w-[280px] truncate py-1 pr-2">{r.title}{r.hard_signal && <span className="ml-1 text-[10.5px] text-crit">floor</span>}</td>
                <td><RiskTag risk={r.level} /></td>
                <td className="text-right font-mono text-muted">#{r.baseline_rank} · {r.baseline_score}</td><td className="text-right font-mono">#{r.proposed_rank} · {r.proposed_score}</td>
                <td className="text-right">{r.rank_change > 0 ? <span className="text-ok"><ArrowUp size={12} className="inline" />{r.rank_change}</span> : r.rank_change < 0 ? <span className="text-high"><ArrowDown size={12} className="inline" />{-r.rank_change}</span> : <span className="text-faint">–</span>}</td></tr>))}</tbody>
          </table>
        </div>
        <div className="mt-1 text-[11.5px] text-faint">{m.comparison.note}</div>
      </div>
      <div className="flex flex-col gap-2 rounded-lg border border-accent/30 bg-accent/5 px-4 py-3">
        <div className="text-[13px] font-medium">Your decision: approving makes this the matrix used for scoring (frozen by hash)</div>
        <div className="flex flex-wrap gap-2">
          <input aria-label="Proposal reviewer name" value={reviewer} onChange={(e) => setReviewer(e.target.value)} placeholder="Reviewer name (required)" className="w-full rounded-md border border-line bg-canvas px-2.5 py-1.5 text-[13px] outline-none focus:border-accent sm:w-56" />
          <input aria-label="Decision note" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Note (optional)" className="min-w-0 flex-1 rounded-md border border-line bg-canvas px-2.5 py-1.5 text-[13px] outline-none focus:border-accent" />
          <button onClick={() => decide("approve")} className="rounded-md bg-ok/20 px-3 py-1.5 text-[13px] font-medium text-ok ring-1 ring-ok/40 hover:bg-ok/30">Approve</button>
          <button onClick={() => decide("reject")} className="rounded-md bg-white/5 px-3 py-1.5 text-[13px] text-muted ring-1 ring-white/15 hover:text-ink">Reject</button>
        </div>
        {err && <div className="text-[13px] text-crit">{err}</div>}
      </div>
    </motion.article>);
}

export function AhpWeights({ project, onChanged }: { project?: string | null; onChanged?: () => void }) {
  const [ov, setOv] = useState<Overview | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [tags, setTags] = useState({ internet_facing: "unknown", data_sensitivity: "unknown", deployment: "unknown", notes: "" });
  const [reviewer, setReviewer] = useState("");
  const load = useCallback(() => api(`/api/ahp${project ? `?project=${encodeURIComponent(project)}` : ""}`).then((o: Overview) => {
    setOv(o);
    if (o.confirmed && Object.keys(o.confirmed).length) setTags((t) => ({ ...t, ...Object.fromEntries(Object.entries(o.confirmed).map(([k, v]) => [k, v ?? ""])) }));
  }).catch((e) => setErr(e.message)), [project]);
  useEffect(() => { load(); }, [load]);

  const propose = (mode: string) => {
    setBusy(true); setErr(null);
    post("/api/ahp/propose", { project: project ?? null, mode, tags }).then(load).catch((e) => setErr(e.message)).finally(() => setBusy(false));
  };
  if (!ov) return <div className="panel px-5 py-4 text-sm text-muted">{err ?? "Loading…"}</div>;
  const sel = (k: "internet_facing" | "data_sensitivity" | "deployment", opts: string[], label: string) => (
    <label className="flex flex-col gap-1 text-[12px] text-muted">{label}
      <select value={tags[k]} onChange={(e) => setTags({ ...tags, [k]: e.target.value })} className="rounded-md border border-line bg-canvas px-2 py-1.5 text-[13px] text-ink">
        {opts.map((o) => <option key={o} value={o}>{o.replace("_", " ")}</option>)}</select></label>);
  return (
    <div className="flex flex-col gap-4">
      <section className="panel flex flex-col gap-3 px-5 py-4">
        <div className="flex items-start gap-3">
          <Scales size={22} weight="duotone" className="mt-0.5 text-accent" />
          <div>
            <div className="font-medium">AI-advised AHP: context-aware weights, still deterministic and still human-approved</div>
            <div className="mt-0.5 text-[13px] text-muted"><span className="text-ink">AI proposes</span> a pairwise matrix for this repository’s context. Code checks its consistency and weight limits; <span className="text-ink">you approve</span> before it affects scoring. Pending proposals leave the current matrix in force. Hard floors and SSVC decisions stay unchanged.</div>
          </div>
        </div>
        <div className="grid gap-4 lg:grid-cols-[1fr_1.2fr]">
          <div className="flex flex-col gap-2">
            <div className="text-[11px] font-medium uppercase tracking-wide text-faint">{ov.active ? `Active: human-approved ${ov.active.id}` : "Active: baseline matrix"}</div>
            <Bars w={ov.active?.weights ?? ov.baseline.weights} base={ov.baseline.weights} />
            <div className="text-[12px] text-muted">Baseline consistency ratio {ov.baseline.consistency_ratio}.{ov.active?.decision && <> Approved by {ov.active.decision.reviewer} at {ov.active.decision.at}.</>}</div>
            {ov.active && (
              <div className="flex flex-wrap gap-2">
                <input value={reviewer} onChange={(e) => setReviewer(e.target.value)} placeholder="Reviewer name" className="w-44 rounded-md border border-line bg-canvas px-2.5 py-1 text-[13px]" />
                <button onClick={() => post("/api/ahp/reset", { project: project ?? null, reviewer, note: "back to baseline" }).then(() => { load(); onChanged?.(); }).catch((e) => setErr(e.message))} className="rounded-md bg-white/5 px-3 py-1 text-[13px] text-muted ring-1 ring-white/15 hover:text-ink">Return to baseline</button>
              </div>)}
          </div>
          <div className="flex flex-col gap-2">
            <div className="text-[11px] font-medium uppercase tracking-wide text-faint">Repository context (you confirm; unknown stays unknown)</div>
            <div className="grid gap-2 sm:grid-cols-3">{sel("internet_facing", ov.options.internet_facing, "Internet-facing?")}{sel("data_sensitivity", ov.options.data_sensitivity, "Data handled")}{sel("deployment", ov.options.deployment, "Deployment")}</div>
            <textarea aria-label="Repository context notes" value={tags.notes} maxLength={300} onChange={(e) => setTags({ ...tags, notes: e.target.value })} rows={2} placeholder="Optional note (treated as untrusted data by the advisor)" className="rounded-md border border-line bg-canvas px-2.5 py-1.5 text-[13px] outline-none focus:border-accent" />
            <div className="flex flex-wrap gap-2">
              <button disabled={busy} onClick={() => propose("agent")} className="flex items-center gap-1.5 rounded-md bg-accent/20 px-3 py-1.5 text-[13px] font-medium text-accent ring-1 ring-accent/40 hover:bg-accent/30 disabled:opacity-50"><Robot size={15} /> {busy ? "Working…" : "Propose with the AI advisor"}</button>
              <button disabled={busy} onClick={() => propose("replay")} className="rounded-md bg-white/5 px-3 py-1.5 text-[13px] text-muted ring-1 ring-white/15 hover:text-ink disabled:opacity-50">Scripted replay (no LLM is called)</button>
            </div>
            <div className="flex items-start gap-1.5 text-[11.5px] text-faint"><Info size={13} className="mt-0.5 shrink-0" /> If no LLM key is configured or the provider fails, the current scoring matrix stays in force.</div>
          </div>
        </div>
        {err && <div className="text-[13px] text-crit">{err}</div>}
      </section>

      {ov.proposals.map((m) => <MatrixCard key={m.id} m={m} baseline={ov.baseline.weights} reload={() => { load(); onChanged?.(); }} project={project} />)}
      {ov.proposals.length === 0 && <div className="panel px-5 py-3 text-[13px] text-muted">No pending proposal.</div>}

      {ov.history.length > 0 && (
        <section className="panel px-5 py-4">
          <div className="mb-2 flex items-center gap-1.5 text-[12px] font-medium uppercase tracking-wide text-faint"><ShieldCheck size={14} /> Decision history</div>
          <ul className="space-y-1 text-[12.5px] text-muted">{ov.history.map((m) => (
            <li key={m.id}><span className="font-mono text-[11.5px] text-ink">{m.id}</span> · {m.status} · {m.source}{m.decision && <> · {m.decision.reviewer}, {m.decision.at}{m.decision.note ? ` — ${m.decision.note}` : ""}</>}</li>))}</ul>
        </section>)}
    </div>);
}
