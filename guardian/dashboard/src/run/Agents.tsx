import { AnimatePresence, motion } from "motion/react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ArrowRight, CheckCircle, CircleNotch, Coins, Detective, Fingerprint, Gavel, Play, Question, Scales, ShieldStar, User, Wrench, XCircle } from "@phosphor-icons/react";
import { RiskTag, spring } from "../ui";
import type { Risk } from "../types";
import { api, Badge, jsonPost, q, SectionHead, type Finding, type Sections, type StepId } from "./shared";

/* The 4 agents (Lead, Investigator, Verifier, Fixer) plus the rule Gatekeeper and the human, drawn as one pipeline.
   Every status and number comes from /api/investigation(/events), /api/run and /api/ai/usage. Nothing is simulated. */

type AgentId = "lead" | "investigator" | "verifier" | "fixer" | "gatekeeper" | "human";
type State = "idle" | "queued" | "running" | "done" | "partial" | "failed" | "waiting";
type Ev = { agent: AgentId; state: string; [k: string]: any };
type Usage = { calls: number; cached_calls: number; tokens: number; seconds: number };
type UsageSummary = { run: Usage; month: Usage; budget: { run: number; month: number }; month_left: number };

const META: Record<AgentId, { name: string; role: string; kind: "ai" | "rules" | "human"; hex: string; Icon: typeof Detective }> = {
  lead: { name: "Lead", role: "Plans the run: groups findings into cases, one Investigator per case", kind: "rules", hex: "#4d8dff", Icon: ShieldStar },
  investigator: { name: "Investigator", role: "Examines one case with its evidence, in parallel", kind: "ai", hex: "#a78bfa", Icon: Detective },
  verifier: { name: "Verifier", role: "Challenges every claim, looks for missed risks", kind: "ai", hex: "#f472b6", Icon: Scales },
  fixer: { name: "Fixer", role: "Explains the computed fix and its trade-offs", kind: "ai", hex: "#3ccf91", Icon: Wrench },
  gatekeeper: { name: "Gatekeeper", role: "Checks every AI sentence against stored evidence", kind: "rules", hex: "#8a909c", Icon: Gavel },
  human: { name: "You", role: "Approve or reject the exact patch", kind: "human", hex: "#e7e9ee", Icon: User },
};
const ORDER: AgentId[] = ["lead", "investigator", "verifier", "fixer", "gatekeeper", "human"];
const norm = (x?: string): State => x === "done" || x === "finished" ? "done" : x === "running" ? "running" : x === "waiting" ? "waiting"
  : x === "partial" || x === "budget_reached" ? "partial" : x === "failed" || x === "unavailable" ? "failed" : x === "skipped" ? "idle" : x ? "done" : "idle";

function stateLabel(s: State) {
  return { idle: "not run", queued: "queued", running: "working", done: "done", partial: "partial", failed: "failed", waiting: "needs you" }[s];
}

function Meter({ u }: { u: UsageSummary | null }) {
  if (!u) return null;
  const pct = Math.min(100, Math.round((u.month.tokens / Math.max(u.budget.month, 1)) * 100));
  return (
    <div className="flex items-center gap-2 text-[11px] text-faint" title="Tokens Guardian spent in the last 30 days (ledger) against its own cap">
      <Coins />
      <div className="h-1.5 w-24 overflow-hidden rounded-full bg-raised"><motion.div className={`h-full ${pct > 80 ? "bg-crit" : pct > 50 ? "bg-high" : "bg-accent"}`} initial={{ width: 0 }} animate={{ width: `${pct}%` }} transition={spring} /></div>
      <span className="tabular-nums">{u.month.tokens.toLocaleString()} / {u.budget.month.toLocaleString()} tokens this month</span>
    </div>);
}

function Connector({ flow, done }: { flow: boolean; done: boolean }) {
  return (
    <div aria-hidden className="hidden w-8 shrink-0 items-center xl:flex">
      <svg viewBox="0 0 32 10" className="w-full overflow-visible">
        <line x1="0" y1="5" x2="27" y2="5" strokeWidth="1.5" className={flow ? "dash-flow stroke-accent" : done ? "stroke-white/35" : "stroke-white/10"} strokeDasharray={flow ? "4 3" : undefined} />
        <path d="M26 1.5 L31 5 L26 8.5" fill="none" strokeWidth="1.5" className={flow ? "stroke-accent" : done ? "stroke-white/35" : "stroke-white/10"} />
      </svg>
    </div>);
}

const CASE_DOT: Record<string, string> = { done: "bg-ok", running: "bg-accent", partial: "bg-high", waiting: "bg-high", failed: "bg-crit", idle: "bg-white/25", queued: "bg-white/25" };
const CASE_WORD: Record<string, string> = { done: "done", running: "working", partial: "partial", waiting: "waiting", failed: "failed", idle: "not investigated", queued: "queued" };
const CASE_RANK: Record<string, number> = { running: 0, failed: 1, partial: 2, waiting: 2, queued: 3, idle: 3, done: 4 };
const shortName = (x: string) => (x.includes("/") ? `…/${x.split("/").pop()}` : x);

/* Many cases (a large PR) must not turn the card into a wall of names: a status bar with counts, the cases that
   need attention first, and a "+N more" that opens the full list below. */
function CaseSummary({ cases }: { cases: { id: string; component: string; state: State }[] }) {
  if (!cases.length) return null;
  const counts = cases.reduce((m: Record<string, number>, c) => ({ ...m, [c.state]: (m[c.state] ?? 0) + 1 }), {});
  const top = [...cases].sort((a, b) => (CASE_RANK[a.state] ?? 5) - (CASE_RANK[b.state] ?? 5)).slice(0, 4);
  return (
    <div className="mt-2.5">
      <div className="flex h-1.5 overflow-hidden rounded-full bg-white/5">{Object.entries(counts).map(([k, n]) => (
        <motion.span key={k} className={CASE_DOT[k] ?? "bg-white/25"} initial={{ width: 0 }} animate={{ width: `${(n / cases.length) * 100}%` }} transition={spring} />))}</div>
      <div className="mt-1.5 flex flex-wrap gap-x-2.5 gap-y-0.5 text-[10.5px] text-faint tabular-nums">{Object.entries(counts).map(([k, n]) => (
        <span key={k} className="flex items-center gap-1"><span className={`size-1.5 rounded-full ${CASE_DOT[k] ?? "bg-white/25"}`} />{n} {CASE_WORD[k] ?? k}</span>))}</div>
      <ul className="mt-2 space-y-1">{top.map((c) => (
        <li key={c.id} className="flex items-center gap-1.5 text-[10.5px]" title={c.component}>
          <span className="relative size-1.5 shrink-0">{c.state === "running" && <span className="ping-soft absolute inset-0 rounded-full bg-accent" />}
            <span className={`absolute inset-0 rounded-full ${CASE_DOT[c.state] ?? "bg-white/25"}`} /></span>
          <span className="truncate font-mono text-muted">{shortName(c.component)}</span></li>))}</ul>
      {cases.length > top.length && <p className="mt-1.5 text-[10.5px] text-accent">+{cases.length - top.length} more · details below</p>}
    </div>);
}

function AgentNode({ id, state, metric, metricLabel, children, selected, onClick, i }: {
  id: AgentId; state: State; metric?: number | string; metricLabel?: string; children?: React.ReactNode; selected: boolean; onClick: () => void; i: number;
}) {
  const m = META[id], active = state === "running";
  return (
    <motion.button onClick={onClick} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ ...spring, delay: i * 0.07 }}
      whileHover={{ y: -2 }} aria-pressed={selected}
      className={`relative flex min-h-[184px] w-full flex-col overflow-hidden rounded-xl bg-surface p-3.5 text-left ring-1 transition-shadow ${selected ? "ring-2" : "ring-line hover:ring-white/15"}`}
      style={{ ...(selected || active ? { boxShadow: `0 0 0 1px ${m.hex}55, 0 14px 40px -18px ${m.hex}80` } : {}), ...(selected ? { ["--tw-ring-color" as string]: m.hex } : {}) }}>
      {active && <span className="pointer-events-none absolute inset-x-0 top-0 h-0.5 overflow-hidden"><span className="scanbar block h-full w-1/3" style={{ background: m.hex }} /></span>}
      <div className="flex items-center gap-2.5">
        <span className="relative grid size-9 shrink-0 place-items-center rounded-lg" style={{ background: `${m.hex}1f`, color: m.hex }}>
          {active && <span className="ping-soft absolute inset-0 rounded-lg" style={{ background: `${m.hex}55` }} />}
          <m.Icon size={19} weight="duotone" />
        </span>
        <div className="min-w-0">
          <div className="text-[13.5px] font-semibold leading-tight">{m.name}</div>
          <Badge kind={m.kind} />
        </div>
      </div>
      <p className="mt-2 text-[11.5px] leading-snug text-muted">{m.role}</p>
      {children}
      <div className="mt-auto flex items-end justify-between pt-3">
        <span className={`flex items-center gap-1 text-[11px] ${state === "done" ? "text-ok" : state === "running" ? "text-accent" : state === "failed" ? "text-crit" : state === "partial" || state === "waiting" ? "text-high" : "text-faint"}`}>
          {state === "running" ? <CircleNotch className="animate-spin" /> : state === "done" ? <CheckCircle weight="fill" /> : state === "failed" ? <XCircle weight="fill" /> : null}{stateLabel(state)}
        </span>
        {metric !== undefined && <span className="text-right"><span className="block font-mono text-[20px] leading-none tabular-nums">{metric}</span><span className="text-[10px] text-faint">{metricLabel}</span></span>}
      </div>
    </motion.button>);
}

function EvChips({ ids, index }: { ids: string[]; index: Record<string, any> }) {
  return (<span className="ml-1 inline-flex flex-wrap gap-1 align-middle">{(ids ?? []).map((id) => (
    <span key={id} title={`${index[id]?.source ?? "?"}${index[id]?.path ? ` · ${index[id].path}` : ""}\nSHA-256 ${index[id]?.sha256 ?? "?"}`}
      className="inline-flex items-center gap-0.5 rounded bg-canvas px-1 font-mono text-[10px] text-faint ring-1 ring-line"><Fingerprint />{id.slice(2, 8)}</span>))}</span>);
}

const ASSESS: Record<string, string> = { malicious: "bg-crit/14 text-crit", vulnerable: "bg-high/14 text-high", risky_config: "bg-high/14 text-high", benign: "bg-ok/14 text-ok", unclear: "bg-info/12 text-info" };

function Detail({ id, s, inv, findings, onPick }: { id: AgentId; s: Sections; inv: any; findings: Finding[]; onPick: (x: StepId) => void }) {
  const index = inv?.evidence_index ?? {};
  const rem = s.remediation, review = rem.review;
  const byId = new Map(findings.map((f) => [f.id, f]));
  const empty = <p className="text-[12.5px] text-muted">This agent hasn't run for this change yet. Press <b className="text-ink">Run the 4 agents</b>.</p>;
  const m = META[id];
  const [all, setAll] = useState(false);
  const LIMIT = 6;
  const cases: any[] = inv?.cases ?? [];
  const sevRank = (c: any) => { const lv = c.finding_ids.map((x: string) => byId.get(x)?.level); return ["critical", "high", "medium", "low", "info"].findIndex((r) => lv.includes(r)) + 1 || 9; };
  const AR: Record<string, number> = { malicious: 0, vulnerable: 1, risky_config: 2, unclear: 3, benign: 4 };
  const shown = (list: any[]) => (all ? list : list.slice(0, LIMIT));
  const more = (n: number) => n > LIMIT && (
    <button onClick={() => setAll((x) => !x)} className="mt-3 rounded-md px-2.5 py-1 text-[12px] text-accent ring-1 ring-accent/40 transition hover:bg-accent/10">
      {all ? "Show fewer" : `Show all ${n} cases`}</button>);
  const tally = (pairs: [string, number][]) => (
    <div className="mt-3 flex flex-wrap gap-1.5 text-[11.5px]">{pairs.filter(([, n]) => n > 0).map(([k, n]) => (
      <span key={k} className="rounded-md bg-raised px-2 py-0.5 text-muted ring-1 ring-line"><b className="font-mono text-ink">{n}</b> {k}</span>))}</div>);
  const body = (() => {
    if (id === "lead") return !inv?.cases ? empty : (
      <div>
        <p className="text-[12.5px] text-muted">The Lead is rule-based (no AI, no tokens). It took the {inv.cases.reduce((n: number, c: any) => n + c.finding_ids.length, 0)} findings this PR introduced and grouped them by component into {inv.cases.length} case(s), assigning one Investigator to each, in parallel. Older findings are reported but not investigated.</p>
        {tally((["critical", "high", "medium", "low", "info"] as Risk[]).map((r) => [`${r}`, cases.filter((c) => ["critical", "high", "medium", "low", "info"][sevRank(c) - 1] === r).length]))}
        <ul className="mt-3 grid gap-2 md:grid-cols-2">{shown([...cases].sort((a, b) => sevRank(a) - sevRank(b))).map((c: any) => {
          const lv = (c.finding_ids.map((x: string) => byId.get(x)?.level).filter(Boolean) as Risk[]);
          const top = (["critical", "high", "medium", "low", "info"] as Risk[]).find((r) => lv.includes(r)) ?? "info";
          return (<li key={c.case_id} className="rounded-lg bg-raised p-3 text-[12px]">
            <div className="flex items-center gap-2"><RiskTag risk={top} /><span className="font-mono text-[12.5px]">{c.component}</span><span className="ml-auto font-mono text-[10.5px] text-faint">{c.case_id}</span></div>
            <ul className="mt-2 space-y-0.5 font-mono text-[11px] text-muted">{c.finding_ids.slice(0, 3).map((x: string) => <li key={x} className="truncate">· {x}</li>)}</ul>
            {c.finding_ids.length > 3 && <p className="mt-0.5 text-[11px] text-faint">+{c.finding_ids.length - 3} more finding(s)</p>}
          </li>);
        })}</ul>
        {more(cases.length)}
      </div>);
    if (id === "investigator") return !inv?.cases ? empty : (
      <div>
      {tally([["malicious", cases.filter((c) => c.assessment === "malicious").length], ["vulnerable", cases.filter((c) => c.assessment === "vulnerable").length],
        ["risky config", cases.filter((c) => c.assessment === "risky_config").length], ["unclear", cases.filter((c) => c.assessment === "unclear").length],
        ["benign", cases.filter((c) => c.assessment === "benign").length], ["not investigated (budget / limit)", cases.filter((c) => c.status !== "done").length]])}
      <ul className="mt-3 grid gap-3 lg:grid-cols-2">{shown([...cases].sort((a, b) => (AR[a.assessment] ?? 5) - (AR[b.assessment] ?? 5) || sevRank(a) - sevRank(b))).map((c: any, i: number) => (
        <motion.li key={c.case_id} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ ...spring, delay: i * 0.06 }} className="rounded-xl bg-raised p-3.5">
          <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
            <span className="font-mono">{c.component}</span>
            {c.assessment && <span className={`rounded px-1.5 py-0.5 text-[10.5px] font-medium ${ASSESS[c.assessment] ?? ASSESS.unclear}`}>{c.assessment.replace("_", " ")}</span>}
            {c.confidence && <span className="text-[11px] text-faint">model confidence {c.confidence}</span>}
            {c.cached && <span className="text-[10.5px] text-faint" title="Same evidence as before: answered from cache, 0 tokens">cached</span>}
            {c.status !== "done" && <span className="ml-auto text-[11px] text-high">{c.status.replace("_", " ")}</span>}
          </div>
          {c.summary && <p className="mt-2 text-[12.5px] leading-relaxed">{c.summary}</p>}
          <ul className="mt-2 space-y-1.5 text-[12px] text-muted">{c.claims.map((cl: any, k: number) => <li key={k} className="leading-relaxed">• {cl.text}<EvChips ids={cl.evidence_ids} index={index} /></li>)}</ul>
          {c.innocent_explanation && <p className="mt-2 text-[11.5px] text-faint"><b className="font-medium text-muted">Innocent explanation weighed:</b> {c.innocent_explanation}</p>}
          {c.open_questions?.length > 0 && <ul className="mt-2 space-y-0.5 text-[11.5px]">{c.open_questions.map((oq: string, k: number) => <li key={k} className="flex gap-1.5 text-info"><Question className="mt-0.5 shrink-0" />{oq}</li>)}</ul>}
          {c.error && c.status !== "done" && <p className="mt-1 text-[11px] text-faint">{c.error}</p>}
        </motion.li>))}</ul>
      {more(cases.length)}
      </div>);
    if (id === "verifier") return !inv?.verifier || inv.verifier.status === "skipped" ? empty : (
      <div className="grid gap-3 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
        <ul className="space-y-2">{inv.verifier.challenges.map((x: any, k: number) => (
          <motion.li key={k} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ ...spring, delay: k * 0.04 }} className="rounded-lg bg-raised p-3 text-[12px]">
            <div className="mb-1 flex items-center gap-2"><span className={`rounded px-1.5 text-[10.5px] font-medium ${x.kind === "dispute" ? "bg-crit/14 text-crit" : x.kind === "corroborate" ? "bg-ok/14 text-ok" : "bg-info/12 text-info"}`}>{x.kind}</span>
              <span className="font-mono text-[11px] text-faint">{inv.cases.find((c: any) => c.case_id === x.case_id)?.component}</span></div>
            <span className="text-muted">{x.concern}</span><EvChips ids={x.evidence_ids} index={index} />
          </motion.li>))}
          {inv.verifier.challenges.length === 0 && <li className="text-[12px] text-muted">No challenges raised.</li>}</ul>
        <div className="rounded-lg bg-high/6 p-3 ring-1 ring-high/20">
          <h4 className="text-[12px] font-semibold text-high">Risks nobody covered</h4>
          <ul className="mt-2 space-y-2 text-[12px] text-muted">{inv.verifier.missed_risks.map((x: any, k: number) => <li key={k}>{x.risk}<EvChips ids={x.evidence_ids} index={index} /></li>)}
            {inv.verifier.missed_risks.length === 0 && <li>None reported.</li>}</ul>
        </div>
      </div>);
    if (id === "fixer") {
      if (rem.status === "not_started") return empty;
      const all_c: any[] = rem.candidates ?? [];
      const act = all_c.filter((c) => c.type !== "escalate");
      const nameOf: Record<string, string> = Object.fromEntries(all_c.map((c) => [c.id, c.package ?? c.file ?? c.id]));
      const byType = all_c.reduce((m: Record<string, number>, c) => ({ ...m, [c.type]: (m[c.type] ?? 0) + 1 }), {});
      const cov = review?.coverage;
      const ok = review?.status === "done" || review?.status === "partial";
      return (
        <div className="grid gap-4 lg:grid-cols-2">
          <div>
            <h4 className="flex items-center gap-2 text-[12px] font-semibold">Computed fix <Badge kind="rules" /></h4>
            {tally(Object.entries(byType).map(([t, n]) => [t.replace(/_/g, " "), n as number]))}
            <ul className="mt-2 space-y-1.5">{shown(act).map((c: any) => (
              <li key={c.id} className="rounded-lg bg-raised px-3 py-2 text-[12px]">
                <span className="rounded bg-accent/12 px-1.5 py-0.5 font-mono text-[10.5px] text-accent">{c.type.replace(/_/g, " ")}</span>
                <span className="ml-2 font-mono">{c.package ?? c.file}{c.to ? ` ${c.from} → ${c.to}` : ""}</span></li>))}</ul>
            {act.length > LIMIT && <button onClick={() => setAll((x) => !x)} className="mt-2 text-[11.5px] text-accent hover:underline">{all ? "Show fewer" : `Show all ${act.length} fixes`}</button>}
            {all_c.length > act.length && <p className="mt-2 text-[11.5px] text-faint">{all_c.length - act.length} item(s) have no safe automatic fix: escalated to a person (listed in Fix & approve).</p>}
          </div>
          <div>
            <h4 className="flex items-center gap-2 text-[12px] font-semibold">Fixer's explanation and Verifier's concerns <Badge kind="ai" /></h4>
            {cov && (
              <div className="mt-2 flex flex-wrap gap-1.5 text-[11.5px]">
                <span className="rounded-md bg-ok/10 px-2 py-0.5 text-ok"><b className="font-mono">{cov.reviewed}</b> of {cov.actionable} fixes AI-reviewed</span>
                {cov.not_reviewed?.length > 0 && <span className="rounded-md bg-high/10 px-2 py-0.5 text-high"><b className="font-mono">{cov.not_reviewed.length}</b> not reviewed: rule rationale shown</span>}
                {cov.needs_person > 0 && <span className="rounded-md bg-raised px-2 py-0.5 text-muted ring-1 ring-line"><b className="font-mono">{cov.needs_person}</b> need a person</span>}
                {cov.retries > 0 && <span className="rounded-md bg-raised px-2 py-0.5 text-muted ring-1 ring-line" title="a refused batch was split into smaller ones and retried">{cov.retries} re-planned batch(es)</span>}
              </div>)}
            {ok ? (<ul className="mt-2 space-y-1.5 text-[12px]">
              {shown(review.explanations).map((x: any, k: number) => <li key={"e" + k} className="rounded-lg bg-raised px-3 py-2 text-muted"><span className="font-mono text-ink">{nameOf[x.candidate_id] ?? x.candidate_id}:</span> {x.text}</li>)}
              {review.challenges.slice(0, all ? undefined : 4).map((x: any, k: number) => <li key={"c" + k} className="rounded-lg bg-high/6 px-3 py-2 text-muted ring-1 ring-high/20">⚑ <span className="font-mono">{nameOf[x.candidate_id] ?? x.candidate_id}:</span> {x.concern}</li>)}
              {cov?.not_reviewed?.length > 0 && <li className="text-[11px] text-faint">Not reviewed: {cov.not_reviewed.slice(0, 3).map((x: any) => `${nameOf[x.candidate_id] ?? x.candidate_id} (${x.reason})`).join("; ")}{cov.not_reviewed.length > 3 ? ` +${cov.not_reviewed.length - 3} more` : ""}</li>}
            </ul>) : review?.status === "unavailable"
              ? <p className="mt-2 text-[12px] text-high">The model could not be reached for any batch: {review.error}. The computed fix and its rule rationale are unaffected; run the review again from Fix & approve.</p>
              : <p className="mt-2 text-[12px] text-muted">Not reviewed yet.</p>}
            <button onClick={() => onPick("fix")} className="mt-3 inline-flex items-center gap-1 text-[12px] text-accent hover:underline">Review the patch and decide <ArrowRight /></button>
          </div>
        </div>);
    }
    if (id === "gatekeeper") {
      if (!inv?.cases) return empty;
      const rej = [...inv.cases.flatMap((c: any) => c.rejected.map((r: any) => ({ ...r, who: `Investigator · ${c.component}` }))),
        ...(inv.verifier?.rejected ?? []).map((r: any) => ({ ...r, who: "Verifier" })), ...(review?.rejected ?? []).map((r: any) => ({ ...r, who: "Fixer" }))];
      const kept = inv.cases.reduce((n: number, c: any) => n + c.claims.length, 0) + (inv.verifier?.challenges?.length ?? 0) + (inv.verifier?.missed_risks?.length ?? 0);
      return (
        <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
          <div className="rounded-lg bg-raised p-3 text-[12px] text-muted">
            <p className="font-medium text-ink">Rules every AI sentence must pass</p>
            <ol className="mt-2 list-decimal space-y-1 pl-4">
              <li>It cites evidence IDs that exist in this run (each stored with a SHA-256).</li>
              <li>Every version, advisory ID or number it mentions appears in that evidence.</li>
              <li>It cannot change the merge decision: <b className="font-mono text-ink">{String(inv.rules_verdict?.verdict ?? "").toUpperCase()}</b> stays as the rules decided.</li>
            </ol>
            <p className="mt-3 tabular-nums"><span className="text-ok">{kept} kept</span> · <span className={rej.length ? "text-crit" : ""}>{rej.length} rejected</span></p>
          </div>
          <ul className="space-y-2 text-[12px]">{rej.map((r, k) => <li key={k} className="rounded-lg bg-crit/6 p-3 ring-1 ring-crit/20"><span className="text-[11px] text-faint">{r.who}</span><p className="text-muted"><s>{r.text}</s></p><p className="text-[11px] text-crit">{r.reason}</p></li>)}
            {rej.length === 0 && <li className="text-muted">Nothing was rejected in this run.</li>}</ul>
        </div>);
    }
    return (
      <div className="text-[12.5px] text-muted">
        {rem.approval ? <p className="flex items-center gap-2"><Badge kind="human" /> {rem.approval.decision === "approve" ? "Approved" : "Rejected"} by <b className="text-ink">{rem.approval.approver}</b>: “{rem.approval.reason}”</p>
          : <p>Nothing changes until a named person approves the exact patch (its SHA-256 is bound to the approval). Guardian never merges or deploys by itself.</p>}
        <button onClick={() => onPick("fix")} className="mt-3 inline-flex items-center gap-1 text-accent hover:underline">Go to Fix & approve <ArrowRight /></button>
      </div>);
  })();
  return (
    <AnimatePresence mode="wait">
      <motion.section key={id} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }} transition={spring} className="panel p-5"
        style={{ borderTop: `2px solid ${m.hex}` }}>
        <h2 className="mb-3 flex items-center gap-2 text-[14px] font-semibold"><m.Icon weight="duotone" style={{ color: m.hex }} /> {m.name}: what it produced</h2>
        {body}
      </motion.section>
    </AnimatePresence>);
}

export function Agents({ s, project, refresh, onPick }: { s: Sections; project: string | null; refresh: () => void; onPick: (x: StepId) => void }) {
  const findings: Finding[] = useMemo(() => s.findings?.items ?? [], [s]);
  const inv = s.investigation?.status === "pending" ? null : s.investigation;
  const rem = s.remediation;
  const [events, setEvents] = useState<Ev[] | null>(null);
  const [running, setRunning] = useState(false);
  const [usage, setUsage] = useState<UsageSummary | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [sel, setSel] = useState<AgentId>(inv?.cases ? "investigator" : "lead");
  const timer = useRef<number | null>(null);
  const caseCount = useMemo(() => new Set(findings.filter((f) => f.label === "introduced").map((f) => f.component ?? f.title)).size, [findings]);
  const loadUsage = useCallback(() => api("/api/ai/usage").then(setUsage).catch(() => undefined), []);

  const poll = useCallback(() => {
    if (timer.current) window.clearInterval(timer.current);
    timer.current = window.setInterval(async () => {
      try {
        const r = await api(`/api/investigation/events${q(project)}`);
        setEvents(r.events);
        if (r.status !== "running") { window.clearInterval(timer.current!); setRunning(false); loadUsage(); refresh(); if (String(r.status).startsWith("error")) setErr(r.status); }
      } catch (e) { setErr((e as Error).message); }
    }, 900);
  }, [project, refresh, loadUsage]);

  useEffect(() => { loadUsage(); api(`/api/investigation/events${q(project)}`).then((r) => { if (r.status === "running") { setRunning(true); setEvents(r.events); poll(); } }).catch(() => undefined); }, [project, poll, loadUsage]);
  useEffect(() => () => { if (timer.current) window.clearInterval(timer.current); }, []);

  const start = async () => {
    setErr(null);
    try { await api("/api/investigate", jsonPost({ project, fix_review: true })); setRunning(true); setEvents([]); setSel("lead"); poll(); }
    catch (e) { setErr((e as Error).message); }
  };

  // Agent states: live events while running, otherwise the saved results.
  const live = running && events;
  const last = (a: AgentId) => [...(events ?? [])].reverse().find((e) => e.agent === a);
  const caseStates: { id: string; component: string; state: State }[] = live
    ? Object.values((events ?? []).filter((e) => e.agent === "investigator").reduce((m: Record<string, any>, e) => ({ ...m, [e.case]: { id: e.case, component: e.component, state: norm(e.state) } }), {}))
    : (inv?.cases ?? []).map((c: any) => ({ id: c.case_id, component: c.component, state: norm(c.status === "not_investigated" ? "skipped" : c.status) }));
  const savedFixer: State = rem.review?.status === "done" ? "done" : rem.review?.status === "unavailable" ? "failed" : rem.status !== "not_started" ? "partial" : "idle";
  const st: Record<AgentId, State> = live ? {
    lead: last("lead") ? "done" : "running",
    investigator: !last("lead") ? "queued" : caseStates.some((c) => c.state === "running") || caseStates.length === 0 ? "running" : caseStates.every((c) => c.state === "done") ? "done" : "partial",
    verifier: last("verifier") ? norm(last("verifier")!.state) : "queued",
    fixer: last("fixer") ? norm(last("fixer")!.state) : "queued",
    gatekeeper: last("gatekeeper") && last("fixer") && last("fixer")!.state !== "running" ? "done" : last("gatekeeper") ? "running" : "queued",  // it also checks the Fixer
    human: last("human") ? "waiting" : "queued",
  } : {
    lead: inv?.cases ? "done" : "idle",
    investigator: !inv?.cases ? "idle" : caseStates.every((c) => c.state === "done") ? "done" : "partial",
    verifier: inv?.verifier ? norm(inv.verifier.status) : "idle",
    fixer: savedFixer,
    gatekeeper: inv?.cases ? "done" : "idle",
    human: rem.approval ? "done" : rem.status === "proposed" ? "waiting" : "idle",
  };
  const g = last("gatekeeper");
  const rejected = live ? g?.rejected : inv?.cases ? inv.cases.reduce((n: number, c: any) => n + c.rejected.length, 0) + (inv.verifier?.rejected?.length ?? 0) + (rem.review?.rejected?.length ?? 0) : undefined;
  const claims = inv?.cases?.reduce((n: number, c: any) => n + c.claims.length, 0);
  const metric: Record<AgentId, [number | string | undefined, string]> = {
    lead: [live ? last("lead")?.cases : inv?.cases?.length, "cases"],
    investigator: [live ? (events ?? []).filter((e) => e.agent === "investigator" && e.state !== "running").reduce((n, e) => n + (e.claims ?? 0), 0) : claims, "claims kept"],
    verifier: [live ? last("verifier")?.challenges : inv?.verifier?.challenges?.length, "challenges"],
    fixer: [live ? last("fixer")?.candidates : rem.candidates?.length, "fixes"],
    gatekeeper: [rejected, "rejected"],
    human: [rem.approval ? (rem.approval.decision === "approve" ? "✓" : "✗") : undefined, rem.approval?.decision ?? ""],
  };
  const u = inv?.usage?.run as Usage | undefined;

  return (
    <div className="flex flex-col gap-4">
      <SectionHead n={3} title="Investigate with 4 agents" sub="Rules already found and scored the risks. Now the Lead plans, one Investigator per case examines the evidence in parallel, the Verifier challenges every claim, and the Fixer explains the computed fix. The Gatekeeper checks every AI sentence; you make the decision."
        right={<><Meter u={usage} />
          <button onClick={start} disabled={running || caseCount === 0} className="inline-flex items-center gap-2 rounded-lg bg-accent px-3.5 py-2 text-[13px] font-medium text-white transition hover:brightness-110 active:scale-[0.98] disabled:opacity-50">
            {running ? <CircleNotch className="animate-spin" /> : <Play weight="fill" />}{running ? "Agents working…" : inv?.cases ? "Run again" : "Run the 4 agents"}</button></>} />

      <section className="panel p-4">
        <div className="flex flex-col gap-3 xl:flex-row xl:items-stretch">
          {ORDER.map((id, i) => (
            <div key={id} className="flex flex-1 items-stretch xl:min-w-0">
              <AgentNode id={id} state={st[id]} metric={metric[id][0]} metricLabel={metric[id][1]} selected={sel === id} onClick={() => setSel(id)} i={i}>
                {id === "investigator" && <CaseSummary cases={caseStates} />}
              </AgentNode>
              {i < ORDER.length - 1 && <Connector flow={st[ORDER[i + 1]] === "running"} done={st[id] === "done" && st[ORDER[i + 1]] !== "idle"} />}
            </div>))}
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-line pt-3 text-[11px] text-faint tabular-nums">
          {running ? <span className="text-accent">Live: {(events ?? []).length} events from the agents</span>
            : u ? <span>Last run: {u.calls === 0 ? "answered from cache (same evidence) · " : ""}{u.calls} model call(s) + {u.cached_calls} cached · {u.tokens.toLocaleString()} tokens · {inv.seconds}s · {inv.model} ({inv.effort})</span>
              : <span>{caseCount} case(s) to investigate → about {caseCount + 2} model calls, capped at {usage?.budget.run.toLocaleString() ?? "…"} tokens. Same evidence again costs 0 (cached).</span>}
          {inv?.packet_sha256 && <span title={`evidence packet SHA-256 ${inv.packet_sha256}`}><Fingerprint className="inline" /> evidence packet {String(inv.packet_sha256).slice(0, 12)}</span>}
          {inv?.status === "partial" && <span className="text-high">Partial run: some steps did not finish (shown, not filled in)</span>}
        </div>
        {err && <p role="alert" className="mt-2 text-[12px] text-crit">{err}</p>}
      </section>

      <Detail id={sel} s={s} inv={inv} findings={findings} onPick={onPick} />
    </div>);
}
