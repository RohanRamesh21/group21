import { motion } from "motion/react";
import { useCallback, useEffect, useRef, useState } from "react";
import { ArrowSquareOut, CheckCircle, Flask, Hammer, Info, Prohibit, ShieldCheck, Warning, WarningOctagon } from "@phosphor-icons/react";
import type { Risk } from "../types";
import { RiskTag, spring } from "../ui";

interface Check { name: string; status: "pass" | "warn" | "fail"; detail: string }
interface Plan {
  id: string; finding_ids: string[]; candidate_id: string; type: string; target: string | null; rationale: string; evidence_ids: string[];
  claim_kind: string; produced_by: "rule_based" | "fixer_agent"; status: string; plan_sha256: string; flags: { type: string; evidence_id: string; patterns: string[] }[];
  forecast: { fix_score?: number; rollback?: string; checks_not_run?: string[]; compat?: { risk: number; semver?: string | null; via_direct_parents?: string[] };
    expected_risk_reduction?: { component_share: number; findings_cleared: number; note: string }; criteria?: Record<string, number> };
  upgrade_safety: { applicable: boolean; risk: string; reasons: string[]; coverage?: string; checks_not_run: string[]; semver_jump?: string;
    engines_check?: { status: string; detail: string }; new_issues?: string[] | null; install_script_added?: string[] | null } | null;
  confidence: { value: number; band: string; missing: string[] } | null;
  patch: { supported: boolean; diff: string; notes: string[]; lockfile: string };
  alternatives: { candidate_id: string; type: string; target: string | null; fix_score: number; compat_risk: number; findings_cleared: number }[];
  finding_summary: { title?: string; level?: Risk; score?: number; label?: string; decision?: string; floor?: string | null };
  review: { checks: Check[]; llm_outcome: string; llm_concerns: string[]; exchange: { from: string; kind: string; text: string; evidence_ids: string[] }[]; outcome: string };
  decisions: { decision: string; reviewer: string; note?: string | null; at: string; plan_sha256: string }[];
  validation: Validation | null; job: { status: string; error?: string; outcome?: string } | null;
}
interface Validation {
  tier: string; branch: string | null; work_dir: string | null; steps: { name: string; status: string; detail: string }[]; build_tests: string; outcome: string; wording: string;
  comparison_frame: string; checks_not_run: string[];
  delta: { verified: boolean; failed_conditions: string[]; conditions: Record<string, boolean>; levels_before: Record<string, number>; levels_after: Record<string, number>;
    risk_index: { before: number; after: number; note: string }; targets: { id: string; status: string; before: string; after: string | null }[];
    new_findings: { id: string; level: string; score: number }[]; remaining_risk: { id: string; level: string; score: number; decision: string; owner: string | null }[] } | null;
  sbom_diff: { added: string[]; removed: string[]; updated: string[]; basis: string } | null;
}
interface RunData {
  run_id: string; status: string; error: string | null; meta: { mode?: string; mode_used?: string; requested_mode?: string; note?: string | null; created?: string };
  plans: Plan[]; messages: { t: string; event: string; sender?: string; recipient?: string; kind?: string; claim?: string; plan?: string; reason?: string; [k: string]: unknown }[];
  priority: { id: string; title: string; level: Risk; score: number }[]; tier2: { configured: boolean };
}

const FIX_TEXT: Record<string, string> = { upgrade_to_fixed: "Upgrade to a fixed version", override_transitive: "Override the transitive version", remove_package: "Remove the package",
  revert_change: "Revert the change", pin_action_sha: "Pin the action to a commit SHA", pin_image_digest: "Pin the image by digest", escalate: "Escalate for security review" };
const STATUS: Record<string, { text: string; cls: string }> = {
  proposed: { text: "Waiting for a human decision", cls: "text-accent bg-accent/12 ring-accent/40" },
  approved: { text: "Approved, not applied", cls: "text-ok bg-ok/12 ring-ok/40" },
  rejected: { text: "Rejected", cls: "text-muted bg-white/5 ring-white/15" },
  escalated: { text: "Escalated to security review", cls: "text-high bg-high/12 ring-high/40" },
  applied: { text: "Applied in sandbox", cls: "text-ok bg-ok/12 ring-ok/40" },
  verified: { text: "Verified", cls: "text-ok bg-ok/15 ring-ok/50" },
  not_verified: { text: "Not verified", cls: "text-crit bg-crit/12 ring-crit/40" },
  failed: { text: "Failed", cls: "text-crit bg-crit/12 ring-crit/40" },
};
const PRODUCER: Record<string, string> = { rule_based: "Rule-based (no LLM)", fixer_agent: "Fixer agent" };
const SAFE_TONE: Record<string, string> = { low: "text-ok", medium: "text-med", high: "text-crit", unknown: "text-muted", "n/a": "text-muted" };
const CHECK_ICON = { pass: <CheckCircle size={14} className="text-ok" weight="fill" />, warn: <Warning size={14} className="text-high" weight="fill" />, fail: <WarningOctagon size={14} className="text-crit" weight="fill" /> };

async function api(path: string, init?: RequestInit) {
  const r = await fetch(path, init);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.detail ?? `HTTP ${r.status}`);
  return j;
}
const post = (path: string, body: unknown) => api(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

function Chip({ cls, children }: { cls: string; children: React.ReactNode }) {
  return <span className={`inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset ${cls}`}>{children}</span>;
}

function Diff({ text }: { text: string }) {
  if (!text) return null;
  return (
    <pre className="scroll-thin max-h-56 overflow-auto rounded-lg border border-line bg-canvas/60 p-3 font-mono text-[11.5px] leading-5">
      {text.split("\n").map((l, i) => (
        <div key={i} className={l.startsWith("+") && !l.startsWith("+++") ? "text-ok" : l.startsWith("-") && !l.startsWith("---") ? "text-crit" : l.startsWith("@@") ? "text-accent" : "text-muted"}>{l || " "}</div>))}
    </pre>);
}

function EvidenceChip({ run, id }: { run: string; id: string }) {
  const [open, setOpen] = useState(false);
  const [body, setBody] = useState<string | null>(null);
  const toggle = () => {
    setOpen((o) => !o);
    if (!body) api(`/api/remediation/${run}/evidence/${id}`).then((e) => setBody(e.content)).catch((e) => setBody(String(e)));
  };
  return (
    <span className="inline-block">
      <button onClick={toggle} className="rounded bg-white/5 px-1.5 py-0.5 font-mono text-[11px] text-muted hover:text-ink">{id}</button>
      {open && <pre className="scroll-thin mt-1 max-h-48 max-w-[560px] overflow-auto rounded-md border border-line bg-canvas/70 p-2 text-[11px] text-muted">{body ?? "loading…"}</pre>}
    </span>);
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return <div className="flex flex-col gap-1.5"><div className="text-[11px] font-medium uppercase tracking-wide text-faint">{title}</div>{children}</div>;
}

function PlanCard({ p, run, tier2, reload }: { p: Plan; run: string; tier2: boolean; reload: () => void }) {
  const [reviewer, setReviewer] = useState("");
  const [note, setNote] = useState("");
  const [tier, setTier] = useState<"tier1" | "tier2">("tier1");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const st = STATUS[p.status] ?? STATUS.proposed;
  const hard = !!p.finding_summary.floor;
  const decide = (decision: string) => {
    setBusy(true); setErr(null);
    post(`/api/remediation/${run}/plans/${p.id}/decision`, { decision, reviewer, note: note || null }).then(reload).catch((e) => setErr(e.message)).finally(() => setBusy(false));
  };
  const apply = () => {
    setBusy(true); setErr(null);
    post(`/api/remediation/${run}/plans/${p.id}/apply`, { tier }).then(reload).catch((e) => setErr(e.message)).finally(() => setBusy(false));
  };
  const running = p.job?.status === "running";
  const needsNote = p.review.outcome === "block";
  return (
    <motion.article initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={spring} className="panel flex flex-col gap-4 px-5 py-4">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[12px] text-faint">{p.id}</span>
            {p.finding_summary.level && <RiskTag risk={p.finding_summary.level} />}
            <span className="font-mono text-[12px] text-muted">score {p.finding_summary.score}</span>
            {p.finding_summary.label && <span className="text-[12px] text-faint">{p.finding_summary.label.replace("_", "-")}</span>}
            {hard && <Chip cls="text-crit bg-crit/12 ring-crit/40"><Prohibit size={12} /> hard signal: never fixed by an upgrade</Chip>}
          </div>
          <h3 className="mt-1 truncate text-[15px] font-medium">{p.finding_summary.title ?? p.finding_ids[0]}</h3>
          {p.finding_ids.length > 1 && <div className="text-[12px] text-muted">Also clears {p.finding_ids.length - 1} related finding(s)</div>}
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <Chip cls={st.cls}>{st.text}</Chip>
          <Chip cls="text-muted bg-white/5 ring-white/15">{PRODUCER[p.produced_by]}</Chip>
          <Chip cls="text-med bg-med/10 ring-med/30"><Info size={12} /> Forecast, not verified</Chip>
        </div>
      </header>

      <div className="rounded-lg border border-line bg-raised/50 px-4 py-3">
        <div className="text-[12px] text-faint">Recommended fix</div>
        <div className="mt-0.5 text-[15px] font-medium">{FIX_TEXT[p.type] ?? p.type}{p.target ? <span className="font-mono text-accent"> → {p.target}</span> : null}</div>
        <p className="mt-1.5 text-[13px] text-muted">{p.rationale}</p>
        <div className="mt-2 flex flex-wrap gap-1.5">{p.evidence_ids.map((e) => <EvidenceChip key={e} run={run} id={e} />)}</div>
      </div>

      {p.flags.length > 0 && (
        <div className="rounded-lg border border-crit/40 bg-crit/8 px-4 py-2 text-[13px] text-crit">
          <WarningOctagon size={15} className="mr-1.5 inline" weight="fill" /> Instruction-like text aimed at AI reviewers was found ({p.flags.map((f) => f.patterns.join(", ")).join("; ")}). It was ignored; a human must look.
        </div>)}

      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="Why this one (ranked candidates)">
          <table className="w-full text-[12.5px]">
            <tbody>
              <tr className="border-b border-line/60 text-accent"><td className="py-1 pr-2">{FIX_TEXT[p.type]} {p.target ?? ""}</td>
                <td className="text-right font-mono">{p.forecast.fix_score}</td><td className="pl-2 text-right font-mono text-faint">compat {p.forecast.compat?.risk}</td></tr>
              {p.alternatives.map((a) => (
                <tr key={a.candidate_id} className="border-b border-line/60 text-muted"><td className="py-1 pr-2">{FIX_TEXT[a.type]} {a.target ?? ""}</td>
                  <td className="text-right font-mono">{a.fix_score}</td><td className="pl-2 text-right font-mono text-faint">compat {a.compat_risk}</td></tr>))}
            </tbody>
          </table>
          <div className="text-[11.5px] text-faint">Fix score = AHP over risk reduction, compatibility, footprint, rollback and evidence. A forecast from current data.</div>
        </Section>
        <Section title="Upgrade safety">
          {p.upgrade_safety?.applicable ? (
            <>
              <div className="text-[13px]">Predicted breaking-change risk: <span className={`font-semibold ${SAFE_TONE[p.upgrade_safety.risk]}`}>{p.upgrade_safety.risk}</span>
                <span className="text-faint"> · {p.upgrade_safety.semver_jump ?? "?"} jump · coverage {p.upgrade_safety.coverage}</span></div>
              <ul className="space-y-0.5 text-[12.5px] text-muted">{p.upgrade_safety.reasons.map((r) => <li key={r}>• {r}</li>)}</ul>
            </>) : <div className="text-[12.5px] text-muted">Not applicable: this fix does not change a version.</div>}
          {p.confidence && <div className="text-[12.5px] text-muted">Confidence in the finding: <span className="text-ink">{p.confidence.band}</span> ({p.confidence.value})
            {p.confidence.missing.length > 0 && <span className="text-faint"> · missing: {p.confidence.missing.slice(0, 3).join("; ")}</span>}</div>}
        </Section>
      </div>

      <Section title={`Skeptic review · ${p.review.outcome}`}>
        <ul className="space-y-1 text-[12.5px]">{p.review.checks.map((c) => (
          <li key={c.name} className="flex items-start gap-1.5">{CHECK_ICON[c.status]}<span><span className="font-mono text-[11.5px] text-muted">{c.name}</span> <span className="text-muted">{c.detail}</span></span></li>))}</ul>
        {p.review.exchange.length > 0 && (
          <div className="mt-1 space-y-1 border-l border-line pl-3 text-[12.5px]">{p.review.exchange.map((m, i) => (
            <div key={i}><span className="font-medium text-ink">{m.from === "skeptic" ? "Skeptic" : "Fixer"}</span> <span className="text-faint">({m.kind})</span> <span className="text-muted">{m.text}</span></div>))}</div>)}
        <div className="text-[11.5px] text-faint">Deterministic checks always run. A fresh-context LLM Skeptic (High/Critical and hard-signal plans) can only add concerns, never soften a failed check{p.review.llm_outcome === "not_run" ? " · not run for this plan" : ""}.</div>
      </Section>

      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="Patch preview (nothing is written yet)">
          {!p.patch.supported && <Chip cls="text-high bg-high/12 ring-high/40">Recommend-only: cannot be applied automatically</Chip>}
          <Diff text={p.patch.diff} />
          <ul className="space-y-0.5 text-[12px] text-muted">{p.patch.notes.map((n) => <li key={n}>• {n}</li>)}</ul>
        </Section>
        <Section title="Rollback and what was not checked">
          <div className="text-[12.5px] text-muted">Rollback: <span className="text-ink">{p.forecast.rollback}</span></div>
          <div className="text-[12.5px] text-muted">Not checked: {[...(p.forecast.checks_not_run ?? []), ...(p.upgrade_safety?.checks_not_run ?? [])].join(" · ") || "nothing recorded"}</div>
          <div className="font-mono text-[11px] text-faint">plan sha256 {p.plan_sha256.slice(0, 16)}… (an approval is bound to this exact plan)</div>
        </Section>
      </div>

      {p.decisions.length > 0 && (
        <div className="rounded-lg border border-line px-4 py-2 text-[12.5px] text-muted">
          {p.decisions.map((d, i) => <div key={i}><span className="text-ink">{d.decision}</span> by {d.reviewer} at {d.at}{d.note ? ` — ${d.note}` : ""} <span className="font-mono text-faint">hash {d.plan_sha256.slice(0, 12)}</span></div>)}
        </div>)}

      {p.status === "proposed" && (
        <div className="flex flex-col gap-2 rounded-lg border border-accent/30 bg-accent/5 px-4 py-3">
          <div className="text-[13px] font-medium">Your decision {needsNote && <span className="text-crit">· a safety check failed: approving needs a written reason</span>}</div>
          <div className="flex flex-wrap gap-2">
            <input value={reviewer} onChange={(e) => setReviewer(e.target.value)} placeholder="Reviewer name (required)" className="w-56 rounded-md border border-line bg-canvas px-2.5 py-1.5 text-[13px] outline-none focus:border-accent" />
            <input value={note} onChange={(e) => setNote(e.target.value)} placeholder={needsNote ? "Reason (required)" : "Note (optional)"} className="min-w-[220px] flex-1 rounded-md border border-line bg-canvas px-2.5 py-1.5 text-[13px] outline-none focus:border-accent" />
          </div>
          <div className="flex flex-wrap gap-2">
            <button disabled={busy} onClick={() => decide("approve")} className="rounded-md bg-ok/20 px-3 py-1.5 text-[13px] font-medium text-ok ring-1 ring-ok/40 hover:bg-ok/30 disabled:opacity-50">Approve</button>
            <button disabled={busy} onClick={() => decide("reject")} className="rounded-md bg-white/5 px-3 py-1.5 text-[13px] text-muted ring-1 ring-white/15 hover:text-ink disabled:opacity-50">Reject</button>
            <button disabled={busy} onClick={() => decide("escalate")} className="rounded-md bg-high/15 px-3 py-1.5 text-[13px] text-high ring-1 ring-high/40 hover:bg-high/25 disabled:opacity-50">Escalate to security review</button>
          </div>
          <div className="text-[11.5px] text-faint">Nothing is merged, pushed or published. Approving only allows a local sandbox test.</div>
        </div>)}

      {(p.status === "approved" || p.status === "applied" || p.status === "not_verified" || p.status === "verified" || p.status === "failed") && p.patch.supported && p.decisions.at(-1)?.decision === "approve" && (
        <div className="flex flex-wrap items-center gap-3 rounded-lg border border-line px-4 py-3">
          <Hammer size={18} className="text-muted" />
          <select value={tier} onChange={(e) => setTier(e.target.value as "tier1" | "tier2")} className="rounded-md border border-line bg-canvas px-2 py-1.5 text-[13px]">
            <option value="tier1">Tier 1: apply, regenerate lockfile (scripts off), rescan, compare</option>
            <option value="tier2" disabled={!tier2}>Tier 2: + build and tests in Docker, no network{tier2 ? "" : " (no digest-pinned image configured)"}</option>
          </select>
          <button disabled={busy || running} onClick={apply} className="rounded-md bg-accent/20 px-3 py-1.5 text-[13px] font-medium text-accent ring-1 ring-accent/40 hover:bg-accent/30 disabled:opacity-40">
            {running ? "Running in sandbox…" : p.status === "approved" ? "Apply in local sandbox copy" : "Re-run in sandbox"}
          </button>
        </div>)}
      {p.job?.status === "error" && <div className="text-[13px] text-crit">Sandbox error: {p.job.error}</div>}
      {err && <div className="text-[13px] text-crit">{err}</div>}
      {p.validation && <ValidationPanel v={p.validation} />}
    </motion.article>);
}

function ValidationPanel({ v }: { v: Validation }) {
  const d = v.delta;
  const tone = v.outcome === "verified" ? "border-ok/40 bg-ok/8" : v.outcome === "remediated_tests_not_run" ? "border-med/40 bg-med/8" : "border-crit/40 bg-crit/8";
  return (
    <div className={`flex flex-col gap-3 rounded-lg border px-4 py-3 ${tone}`}>
      <div className="flex items-center gap-2 text-[14px] font-medium">
        {v.outcome === "verified" ? <ShieldCheck size={18} className="text-ok" weight="fill" /> : <Flask size={18} />} {v.wording}
      </div>
      <div className="text-[12px] text-muted">Tier {v.tier.slice(-1)} · build and tests: <span className="text-ink">{v.build_tests}</span> · local branch <span className="font-mono">{v.branch}</span> (never pushed)</div>
      <ul className="space-y-0.5 text-[12.5px]">{v.steps.map((s, i) => <li key={i} className="text-muted"><span className={s.status === "ok" ? "text-ok" : s.status === "failed" ? "text-crit" : "text-faint"}>{s.status}</span> · {s.name}{s.detail ? ` — ${s.detail.slice(0, 160)}` : ""}</li>)}</ul>
      {d && (
        <div className="grid gap-4 lg:grid-cols-3">
          <Section title="Before → after">
            <table className="w-full font-mono text-[12px]">
              <tbody>{(["critical", "high", "medium", "low"] as const).map((lv) => (
                <tr key={lv} className="border-b border-line/60"><td className="py-0.5 font-sans text-muted">{lv}</td><td className="text-right">{d.levels_before[lv] ?? 0}</td><td className="px-2 text-faint">→</td><td className="text-right">{d.levels_after[lv] ?? 0}</td></tr>))}</tbody>
            </table>
            <div className="text-[12px] text-muted">Risk index {d.risk_index.before} → {d.risk_index.after}</div>
            <div className="text-[11px] text-faint">{v.comparison_frame}</div>
          </Section>
          <Section title="Verification conditions">
            <ul className="space-y-0.5 text-[12.5px]">{Object.entries(d.conditions).map(([k, ok]) => <li key={k} className={ok ? "text-ok" : "text-crit"}>{ok ? "✓" : "✗"} <span className="font-mono text-[11.5px]">{k}</span></li>)}</ul>
            <div className="text-[12px] text-muted">Targets: {d.targets.map((t) => `${t.status}`).join(", ") || "none"}</div>
            <div className="text-[12px] text-muted">New findings: {d.new_findings.length ? d.new_findings.map((n) => `${n.id} (${n.level})`).join(", ") : "none"}</div>
          </Section>
          <Section title="Package diff (SBOM comparison)">
            {v.sbom_diff && <div className="text-[12.5px] text-muted">+{v.sbom_diff.added.length} added · −{v.sbom_diff.removed.length} removed · {v.sbom_diff.updated.length} changed
              {v.sbom_diff.added.length > 0 && <div className="text-high">New packages are new risk: {v.sbom_diff.added.slice(0, 5).join(", ")}</div>}
              <div className="mt-1 text-[11px] text-faint">{v.sbom_diff.basis}</div></div>}
          </Section>
        </div>)}
      {d && d.remaining_risk.length > 0 && (
        <Section title="Remaining risk (owner unassigned)">
          <ul className="text-[12.5px] text-muted">{d.remaining_risk.slice(0, 5).map((r) => <li key={r.id}><span className="font-mono text-[11.5px]">{r.id}</span> · {r.level} · {r.decision}</li>)}</ul>
        </Section>)}
    </div>);
}

export function Remediation({ project }: { project?: string | null }) {
  const [runs, setRuns] = useState<{ run_id: string; mode: string; created: string }[]>([]);
  const [run, setRun] = useState<string | null>(null);
  const [data, setData] = useState<RunData | null>(null);
  const [mode, setMode] = useState("rule_based");
  const [top, setTop] = useState(3);
  const [err, setErr] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const timer = useRef<number | null>(null);

  const load = useCallback((id: string) => api(`/api/remediation/${id}`).then(setData).catch((e) => setErr(e.message)), []);
  useEffect(() => { api("/api/remediation/runs").then((r) => { setRuns(r); if (r[0]) setRun((cur) => cur ?? r[0].run_id); }).catch(() => undefined); }, []);
  useEffect(() => { if (run) { setData(null); load(run); } }, [run, load]);
  useEffect(() => {
    if (!run) return;
    const busy = data?.status === "running" || data?.plans.some((p) => p.job?.status === "running");
    if (busy) { timer.current = window.setTimeout(() => load(run), 1200); }
    return () => { if (timer.current) window.clearTimeout(timer.current); };
  }, [data, run, load]);

  const start = () => {
    setStarting(true); setErr(null);
    post("/api/remediation/runs", { project: project ?? null, top_n: top, mode })
      .then((r) => { setRun(r.run_id); setRuns((x) => [{ run_id: r.run_id, mode, created: "" }, ...x]); })
      .catch((e) => setErr(e.message)).finally(() => setStarting(false));
  };

  return (
    <div className="flex flex-col gap-4">
      <section className="panel flex flex-col gap-3 px-5 py-4">
        <div className="flex items-start gap-3">
          <Hammer size={22} className="mt-0.5 text-accent" weight="duotone" />
          <div>
            <div className="font-medium">Remediation: from a prioritised finding to a verified fix</div>
            <div className="mt-0.5 text-[13px] text-muted">Prioritised risk → recommended fix → <span className="text-ink">human approval</span> → build and test in a sandbox → rescan → verified. Recommendations are forecasts; only the rescan proves them, and only a passing build and test run can say “verified”.</div>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select value={mode} onChange={(e) => setMode(e.target.value)} className="rounded-md border border-line bg-canvas px-2 py-1.5 text-[13px]">
            <option value="rule_based">Rule-based (no LLM): top fix score per finding</option>
            <option value="agent">Fixer agent + Skeptic (live LLM, falls back to rule-based)</option>
            <option value="replay">Scripted agent replay (no LLM is called)</option>
          </select>
          <select value={top} onChange={(e) => setTop(Number(e.target.value))} className="rounded-md border border-line bg-canvas px-2 py-1.5 text-[13px]">
            {[1, 2, 3, 5, 8].map((n) => <option key={n} value={n}>Top {n} findings</option>)}
          </select>
          <button onClick={start} disabled={starting} className="rounded-md bg-accent/20 px-3 py-1.5 text-[13px] font-medium text-accent ring-1 ring-accent/40 hover:bg-accent/30 disabled:opacity-50">{starting ? "Starting…" : "Recommend fixes"}</button>
          {runs.length > 0 && (
            <select value={run ?? ""} onChange={(e) => setRun(e.target.value)} className="rounded-md border border-line bg-canvas px-2 py-1.5 text-[13px] text-muted">
              {runs.map((r) => <option key={r.run_id} value={r.run_id}>{r.run_id} · {r.mode}</option>)}
            </select>)}
          {run && <>
            <a href={`/api/remediation/${run}/report?fmt=html`} target="_blank" rel="noreferrer" className="flex items-center gap-1 text-[13px] text-accent hover:underline">Report (HTML) <ArrowSquareOut size={13} /></a>
            <a href={`/api/remediation/${run}/report?fmt=md`} target="_blank" rel="noreferrer" className="flex items-center gap-1 text-[13px] text-accent hover:underline">Markdown <ArrowSquareOut size={13} /></a></>}
        </div>
        {err && <div className="text-[13px] text-crit">{err}</div>}
        {data?.meta.note && <div className="rounded-md border border-high/30 bg-high/8 px-3 py-1.5 text-[12.5px] text-high">{data.meta.note}</div>}
        {data && <div className="text-[12px] text-faint">Run {data.run_id} · produced by <span className="text-muted">{data.meta.mode_used ?? data.meta.mode}</span>{data.meta.mode_used === "replay" ? " (scripted replay: no LLM was called)" : ""} · {data.status}</div>}
      </section>

      {data?.status === "running" && <div className="panel px-5 py-4 text-sm text-muted">Building fix plans…</div>}
      {data?.status === "error" && <div className="panel px-5 py-4 text-sm text-crit">{data.error}</div>}
      {data && data.status !== "running" && data.plans.length === 0 && data.status !== "error" && (
        <div className="panel px-5 py-4 text-sm text-muted">No plans: no scored finding with fix candidates is left (or the report has no candidates).</div>)}
      <div className="flex flex-col gap-4">{data?.plans.map((p) => <PlanCard key={p.id} p={p} run={data.run_id} tier2={data.tier2.configured} reload={() => load(data.run_id)} />)}</div>

      {data && data.messages.length > 0 && (
        <section className="panel px-5 py-4">
          <div className="mb-2 text-[12px] font-medium uppercase tracking-wide text-faint">Debate and audit log</div>
          <ul className="scroll-thin max-h-72 space-y-1 overflow-auto text-[12.5px] text-muted">{data.messages.map((m, i) => (
            <li key={i}><span className="font-mono text-[11px] text-faint">{m.t.slice(11, 19)}</span> <span className="text-ink">{m.event}</span>
              {m.sender && <> · {m.sender} → {m.recipient} ({m.kind})</>}{m.plan && <> · {m.plan}</>} {(m.claim ?? m.reason) && <span>— {String(m.claim ?? m.reason).slice(0, 220)}</span>}</li>))}</ul>
        </section>)}
    </div>);
}
