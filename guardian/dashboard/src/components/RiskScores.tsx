import { AnimatePresence, motion } from "motion/react";
import { useEffect, useMemo, useState } from "react";
import { ArrowSquareOut, CheckCircle, Info, Scales, ShieldWarning, Sparkle, Warning } from "@phosphor-icons/react";
import type { Risk } from "../types";
import { RISK, RiskTag, spring } from "../ui";

interface Contribution { factor: string; value: number; weight: number; points: number; why: string }
export interface Scored {
  id: string; kind: "vulnerability" | "supply_chain" | "ci_image"; title: string; component: string; label: string; summary: string;
  decision: "Act" | "Attend" | "Track*" | "Track"; level: Risk; score: number; floor: string | null;
  ssvc: { exploitation: string; automatable: string; technical_impact: string; mission: string; rule: string } | null;
  contributions: Contribution[]; counterfactuals: { if: string; then: string }[];
  evidence: Record<string, any>;
}
interface Scores {
  verdict: "block" | "review" | "allow"; reasons: string[]; counts: Record<string, Record<string, number>>; findings: Scored[];
  method: { ahp: { weights: Record<string, number>; consistency_ratio: number; consistent: boolean; lambda_max: number; matrix: number[][]; criteria: string[] };
    criteria_text: Record<string, string>; floors: Record<string, { level: string; decision: string; why: string }>; verdict_rule: string; epss_poc_threshold: number };
  data: { advisories: number; cves: number; epss_found: number; kev_matches: number; kev_catalog_size: number; errors: string[] };
}
interface Explanation { headline: string; sentences: { text: string; cites: string[]; status: "verified" | "inferred" }[];
  rejected: { text: string; reason: string }[]; model?: string; ai_enabled?: boolean; error?: string }

const FACTOR: Record<string, string> = { exploitation: "Being attacked", impact: "Impact", exposure: "Exposure", introduced: "Introduced by PR", actionable: "Fix available" };
const DEC_TONE: Record<string, string> = { Act: "text-crit bg-crit/12 ring-crit/40", Attend: "text-high bg-high/12 ring-high/40",
  "Track*": "text-med bg-med/12 ring-med/40", Track: "text-ok bg-ok/12 ring-ok/40" };
const VERDICT = {
  block: { text: "Block this merge", cls: "border-crit/40 bg-crit/10 text-crit", Icon: ShieldWarning },
  review: { text: "Needs a human decision", cls: "border-high/40 bg-high/10 text-high", Icon: Warning },
  allow: { text: "No new high or critical risk", cls: "border-ok/40 bg-ok/10 text-ok", Icon: CheckCircle },
};

function Decision({ d }: { d: string }) {
  return <span className={`rounded-md px-1.5 py-0.5 font-mono text-[11px] ring-1 ring-inset ${DEC_TONE[d] ?? ""}`}>{d}</span>;
}

export function RiskScores({ project, fullScan = false }: { project?: string | null; fullScan?: boolean }) {
  const [s, setS] = useState<Scores | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [sel, setSel] = useState<string | null>(null);
  const [filter, setFilter] = useState<"introduced" | "all" | "pre_existing">("all");
  const [showMethod, setShowMethod] = useState(false);
  useEffect(() => {
    setS(null); setErr(null); setSel(null);
    fetch(`/api/scores${project ? `?project=${project}` : ""}`)
      .then(async (r) => (r.ok ? r.json() : Promise.reject((await r.json()).detail)))
      .then((d: Scores) => { setS(d); setSel(d.findings[0]?.id ?? null); })
      .catch((e) => setErr(String(e)));
  }, [project]);
  const list = useMemo(() => (s?.findings ?? []).filter((f) => filter === "all" || f.label === filter), [s, filter]);
  if (err) return <div className="panel px-5 py-4 text-sm text-crit">{err}</div>;
  if (!s) return <div className="panel px-5 py-4 text-sm text-muted">Scoring findings…</div>;
  const v = VERDICT[s.verdict];
  const cur = s.findings.find((f) => f.id === sel) ?? null;
  const ahp = s.method.ahp;
  return (
    <div className="flex flex-col gap-4">
      <section className="grid gap-4 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
        {fullScan ? (
          <div className="panel flex items-start gap-3 px-5 py-4">
            <Info size={22} className="mt-0.5 text-accent" />
            <div><div className="font-medium">Full scan (no pull request to compare)</div>
              <div className="mt-1 text-sm text-muted">Every finding is shown as already present. Upload a Git URL with a base and head to get a merge verdict.</div></div>
          </div>
        ) : (
          <div className={`flex items-start gap-3 rounded-xl border px-5 py-4 ${v.cls}`}>
            <v.Icon size={26} weight="duotone" className="mt-0.5 shrink-0" />
            <div className="min-w-0"><div className="text-lg font-semibold">{v.text}</div>
              <ul className="mt-1 space-y-0.5 text-sm text-ink/85">{s.reasons.slice(0, 4).map((r) => <li key={r} className="truncate">• {r}</li>)}</ul></div>
          </div>)}
        <div className="panel grid grid-cols-4 divide-x divide-line">
          {(["critical", "high", "medium", "low"] as Risk[]).map((lv) => (
            <div key={lv} className="flex flex-col gap-1 px-4 py-3">
              <RiskTag risk={lv} />
              <span className="font-mono text-xl">{s.counts[lv]?.introduced ?? 0}<span className="text-sm text-faint"> new</span></span>
              <span className="text-[11px] text-muted">{s.counts[lv]?.pre_existing ?? 0} already present</span>
            </div>))}
        </div>
      </section>

      <button onClick={() => setShowMethod((x) => !x)} className="panel flex flex-wrap items-center gap-x-4 gap-y-1 px-5 py-2.5 text-left text-[12.5px] text-muted hover:text-ink">
        <span className="flex items-center gap-1.5 text-ink"><Scales size={15} /> How scores are computed</span>
        <span>Floors for attacks · SSVC decision · AHP weights (consistency ratio <span className="font-mono text-ink">{ahp.consistency_ratio}</span> {ahp.consistent ? "✓ < 0.10" : "✗"})</span>
        <span>EPSS for {s.data.epss_found}/{s.data.cves} CVEs · KEV matches {s.data.kev_matches} (catalog {s.data.kev_catalog_size})</span>
        {s.data.errors.map((e) => <span key={e} className="text-high">{e}</span>)}
      </button>
      <AnimatePresence>{showMethod && <Method s={s} />}</AnimatePresence>

      <section className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.25fr)]">
        <div className="panel flex max-h-[720px] min-h-0 flex-col">
          <div className="flex gap-1 border-b border-line px-3 pt-2 text-[12.5px]">
            {([["all", "All"], ["introduced", "Introduced by PR"], ["pre_existing", "Already present"]] as const).map(([k, l]) => (
              <button key={k} onClick={() => setFilter(k)} className={`rounded-t-md px-2.5 pb-2 pt-1 ${filter === k ? "text-ink" : "text-muted hover:text-ink"}`}>
                {l} <span className="text-faint">{(s.findings ?? []).filter((f) => k === "all" || f.label === k).length}</span>
                {filter === k && <motion.span layoutId="score-filter" className="mt-1.5 block h-0.5 rounded-full bg-accent" />}
              </button>))}
          </div>
          <div className="border-b border-line px-4 py-1.5 text-[11px] text-faint">Sorted by decision (floors and SSVC) first, then by priority score within the same decision.</div>
          <ul className="min-h-0 flex-1 overflow-y-auto">
            {list.map((f) => (
              <li key={f.id}>
                <button onClick={() => setSel(f.id)} className={`flex w-full items-center gap-3 border-b border-line px-4 py-2.5 text-left hover:bg-raised ${sel === f.id ? "bg-raised" : ""}`}>
                  <RiskTag risk={f.level} className="shrink-0" />
                  <Decision d={f.decision} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-mono text-[12px]">{f.title}</div>
                    <div className="truncate text-[11px] text-muted">{f.label === "introduced" ? "introduced by this PR" : "already present"} · {f.kind.replace("_", " ")}</div>
                  </div>
                  <div className="w-16 shrink-0 text-right">
                    <div className="font-mono text-[13px]">{f.score.toFixed(1)}</div>
                    <div className="mt-1 h-1 rounded-full bg-line"><div className="h-1 rounded-full" style={{ width: `${f.score}%`, background: RISK[f.level].hex }} /></div>
                  </div>
                </button>
              </li>))}
            {!list.length && <li className="px-4 py-6 text-sm text-muted">Nothing here.</li>}
          </ul>
        </div>
        <AnimatePresence mode="wait">{cur && <ScoreCard key={cur.id} f={cur} project={project} />}</AnimatePresence>
      </section>
    </div>
  );
}

function Method({ s }: { s: Scores }) {
  const a = s.method.ahp;
  return (
    <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} exit={{ opacity: 0, height: 0 }} className="overflow-hidden">
      <div className="panel grid gap-6 px-5 py-4 text-[12.5px] lg:grid-cols-3">
        <div>
          <div className="mb-2 font-medium text-ink">1 · Hard floors (no agent or factor can lower these)</div>
          <ul className="space-y-1 text-muted">{Object.entries(s.method.floors).map(([k, f]) => (
            <li key={k}><span className="font-mono text-ink">{f.level}</span> · {f.why}</li>))}</ul>
        </div>
        <div>
          <div className="mb-2 font-medium text-ink">2 · SSVC decision (adapted from CISA)</div>
          <p className="text-muted">Being attacked? (KEV = in the wild, EPSS ≥ {s.method.epss_poc_threshold} = likely) → can it be automated? → total or partial impact (CVSS) → how important is the code (runtime direct / indirect / dev-only) → <span className="text-ink">Act · Attend · Track* · Track</span>.</p>
          <p className="mt-2 text-muted">Verdict: {s.method.verdict_rule}.</p>
        </div>
        <div>
          <div className="mb-2 font-medium text-ink">3 · Priority score 0–100 = Σ weight × factor</div>
          <table className="w-full font-mono text-[11.5px]">
            <tbody>{a.criteria.map((c, i) => (
              <tr key={c} className="border-b border-line/60"><td className="py-0.5 pr-2 font-sans text-muted">{FACTOR[c]}</td>
                {a.matrix[i].map((x, j) => <td key={j} className="px-1 text-right text-faint">{x >= 1 ? x : `1/${Math.round(1 / x)}`}</td>)}
                <td className="pl-2 text-right text-ink">{(a.weights[c] * 100).toFixed(1)}%</td></tr>))}</tbody>
          </table>
          <p className="mt-2 text-muted">AHP pairwise matrix (Saaty 1–9). λmax {a.lambda_max}, consistency ratio {a.consistency_ratio} (must be &lt; 0.10).</p>
        </div>
      </div>
    </motion.div>);
}

function ScoreCard({ f, project }: { f: Scored; project?: string | null }) {
  const [ex, setEx] = useState<Explanation | null>(null);
  const [busy, setBusy] = useState(false);
  const ask = (force = false) => {
    setBusy(true);
    fetch("/api/explain", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id: f.id, project, force }) })
      .then((r) => r.json()).then(setEx).catch(() => setEx({ headline: "", sentences: [], rejected: [], error: "backend offline" })).finally(() => setBusy(false));
  };
  const ev = f.evidence;
  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }} transition={spring}
      className="panel flex max-h-[720px] min-h-0 flex-col gap-4 overflow-y-auto px-5 py-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="break-all font-mono text-[13px]">{f.title}</div>
          <div className="mt-1 text-[12px] text-muted">{f.label === "introduced" ? "Introduced by this PR" : "Already present before this PR"}</div>
        </div>
        <div className="flex shrink-0 items-center gap-2"><RiskTag risk={f.level} /><Decision d={f.decision} />
          <span className="font-mono text-2xl">{f.score.toFixed(1)}</span></div>
      </div>

      <div>
        <div className="mb-1.5 text-[11px] uppercase tracking-wide text-faint">Why this level</div>
        {f.floor ? (
          <div className="rounded-lg border border-crit/30 bg-crit/8 px-3 py-2 text-[12.5px]"><span className="font-medium text-crit">Hard floor:</span> {f.floor}. Nothing can lower this.</div>
        ) : f.ssvc ? (
          <div className="flex flex-wrap items-center gap-1.5 text-[12px]">
            {[["Being attacked", f.ssvc.exploitation], ["Automatable", f.ssvc.automatable], ["Impact", f.ssvc.technical_impact], ["Importance", f.ssvc.mission]].map(([k, val], i) => (
              <span key={k} className="flex items-center gap-1.5">{i > 0 && <span className="text-faint">→</span>}
                <span className="rounded-md bg-raised px-2 py-1"><span className="text-muted">{k}: </span><span className="font-mono">{val}</span></span></span>))}
            <span className="text-faint">⇒</span><Decision d={f.decision} />
            <div className="mt-1 w-full text-muted">Rule: {f.ssvc.rule}.</div>
          </div>
        ) : <div className="text-[12.5px] text-muted">Configuration finding, ranked by the factors below.</div>}
      </div>

      <div>
        <div className="mb-1.5 text-[11px] uppercase tracking-wide text-faint">What makes up the score (points add up to {f.score.toFixed(1)})</div>
        <div className="space-y-1.5">{f.contributions.map((c) => (
          <div key={c.factor} className="grid grid-cols-[120px_1fr_44px] items-center gap-2 text-[12px]">
            <span className="text-muted">{FACTOR[c.factor]}</span>
            <div className="relative h-5 rounded bg-line/60">
              <motion.div initial={{ width: 0 }} animate={{ width: `${c.weight * 100}%` }} className="absolute inset-y-0 left-0 rounded bg-white/5" />
              <motion.div initial={{ width: 0 }} animate={{ width: `${c.points}%` }} transition={spring} className="absolute inset-y-0 left-0 rounded" style={{ background: RISK[f.level].hex + "cc" }} />
              <span className="absolute inset-0 flex items-center truncate px-2 text-[11px] text-ink/90">{c.why}</span>
            </div>
            <span className="text-right font-mono">+{c.points.toFixed(1)}</span>
          </div>))}</div>
        <div className="mt-1 text-[11px] text-faint">Faint bar = the factor's maximum (its AHP weight); coloured bar = what this finding earned.</div>
      </div>

      {f.counterfactuals.length > 0 && (
        <div>
          <div className="mb-1.5 text-[11px] uppercase tracking-wide text-faint">What would change it</div>
          <ul className="space-y-1 text-[12.5px]">{f.counterfactuals.map((c) => (
            <li key={c.if} className="flex gap-2"><span className="text-accent">If</span><span className="text-muted">{c.if}</span><span className="text-faint">→</span><span>{c.then}</span></li>))}</ul>
        </div>)}

      <div>
        <div className="mb-1.5 text-[11px] uppercase tracking-wide text-faint">Evidence</div>
        <div className="flex flex-wrap gap-1.5 font-mono text-[11.5px]">
          {ev.url && <a href={ev.url} target="_blank" rel="noreferrer" className="flex items-center gap-1 rounded-md bg-raised px-2 py-1 text-accent hover:underline">{ev.advisory}<ArrowSquareOut size={12} /></a>}
          {ev.cve && <span className="rounded-md bg-raised px-2 py-1">{ev.cve}</span>}
          {ev.epss && <span className="rounded-md bg-raised px-2 py-1">EPSS {Number(ev.epss.epss).toFixed(3)} · pct {Number(ev.epss.percentile).toFixed(2)} · {ev.epss.date}</span>}
          {ev.kev && <span className="rounded-md bg-crit/15 px-2 py-1 text-crit">CISA KEV since {ev.kev.date_added}</span>}
          {ev.cvss_vector && <span className="max-w-full break-all rounded-md bg-raised px-2 py-1">{ev.cvss_vector}</span>}
          {(ev.lockfile_line || ev.file) && <span className="rounded-md bg-raised px-2 py-1">{ev.file ?? "package-lock.json"}{ev.lockfile_line ? `:${ev.lockfile_line}` : ""}</span>}
          {ev.resolved && <span className="max-w-full break-all rounded-md bg-raised px-2 py-1">{ev.resolved}</span>}
          {ev.file && <span className="rounded-md bg-raised px-2 py-1">{ev.file}{ev.line ? `:${ev.line}` : ""}</span>}
        </div>
        {f.summary && <p className="mt-2 text-[12px] text-muted">Advisory text: “{f.summary}”</p>}
      </div>

      <div className="rounded-lg border border-accent/25 bg-accent/5 px-4 py-3">
        <div className="flex items-center justify-between gap-2">
          <span className="flex items-center gap-1.5 text-[12.5px] font-medium"><Sparkle size={15} className="text-accent" /> Score explanation</span>
          {!busy && (!ex || ex.error || ex.ai_enabled) && (
            <button onClick={() => ask(!!ex?.ai_enabled)} className="rounded-md bg-accent/15 px-2.5 py-1 text-[12px] text-accent hover:bg-accent/25">{ex?.ai_enabled ? "Request AI summary" : "Explain"}</button>
          )}
        </div>
        {busy && <div className="mt-2 animate-pulse text-[12.5px] text-muted">Preparing the explanation…</div>}
        {ex && !busy && (ex.error ? <div className="mt-2 text-[12.5px] text-high">{ex.error}</div> : (
          <div className="mt-2 space-y-2 text-[13px]">
            <div className="font-medium">{ex.headline}</div>
            {ex.sentences.map((x, i) => (
              <p key={i} className="leading-relaxed">
                <span className={`mr-1.5 rounded px-1 py-0.5 align-middle text-[10px] font-semibold ${x.status === "verified" ? "bg-ok/15 text-ok" : "bg-med/15 text-med"}`}>{x.status}</span>
                {x.text}{" "}<span className="text-[10.5px] text-faint">[{x.cites.join(", ")}]</span>
              </p>))}
            <div className="text-[11px] text-faint">Generated from the score card{ex.rejected.length ? ` · ${ex.rejected.length} sentence(s) removed` : ""}. {ex.model !== "deterministic" && "AI sentences are marked inferred."}</div>
          </div>))}
      </div>
    </motion.div>);
}
