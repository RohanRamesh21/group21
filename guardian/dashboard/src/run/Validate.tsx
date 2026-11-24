import { useCallback, useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import {
  ArrowRight, CheckCircle, CircleNotch, Cube, Gavel, Hammer, LockKey, MagnifyingGlass, Package, Play, Plug, Pulse,
  ShieldCheck, Stack, Terminal, TestTube, Timer, WarningCircle, XCircle,
} from "@phosphor-icons/react";
import { spring } from "../ui";
import { api, jsonPost, q, SectionHead, type Sections } from "./shared";
import { Verdict } from "./Shell";

/* ------------------------------------------------------------------ model of a validation run --------------------
   The server reports progress as plain messages ("[baseline] build: npm run build", "validation: source rescan …").
   The view only *reads* them: a stage that has run is shown as "done" (neutral); pass/fail appears when the gate has
   decided, from validation.json. Nothing here invents a result. */

type Phase = { label: string; hint: string; Icon: typeof Cube };
const PHASES: Phase[] = [
  { label: "Approval check", hint: "exact patch hash", Icon: LockKey },
  { label: "Baseline sandbox", hint: "branch before this PR", Icon: Cube },
  { label: "Fixed sandbox", hint: "PR + approved patch", Icon: Cube },
  { label: "SBOM diff", hint: "what was really installed", Icon: Stack },
  { label: "Rescan", hint: "same engine & advisories", Icon: MagnifyingGlass },
  { label: "Gate", hint: "rules decide", Icon: Gavel },
];

const STAGES = [
  { id: "install", label: "Install", hint: "npm ci · scripts off", Icon: Package },
  { id: "hooks", label: "Approved hooks", hint: "1 allow-listed script", Icon: Plug },
  { id: "build", label: "Build", hint: "npm run build", Icon: Hammer },
  { id: "target_test", label: "Security test", hint: "jsonata sandbox", Icon: ShieldCheck },
  { id: "unit", label: "Unit tests", hint: "SQLite suite", Icon: TestTube },
  { id: "integration", label: "Integration", hint: "start · login · monitor", Icon: Pulse },
];

type Prog = { baseline?: string; candidate?: string; rescan?: string; sbom?: string };
type LaneAt = { idx: number; finished: boolean; cmd?: string; label?: string };

function laneAt(msg?: string): LaneAt {
  if (!msg) return { idx: -1, finished: false };
  if (msg === "finished") return { idx: STAGES.length, finished: true };
  const m = msg.match(/^(\w+): (.*)$/);
  const idx = STAGES.findIndex((x) => x.id === m?.[1]);
  return { idx, finished: false, cmd: m?.[2], label: STAGES[idx]?.label.toLowerCase() };
}

function model(p: Prog) {
  const b = laneAt(p.baseline), c = laneAt(p.candidate);
  const frac = (l: LaneAt) => (l.finished ? 1 : l.idx < 0 ? 0 : (l.idx + 0.5) / STAGES.length);
  const started = !!(p.baseline || p.candidate || p.rescan);
  const pct = Math.min(97, (started ? 4 : 1) + 33 * frac(b) + 33 * frac(c) + 14 * (p.rescan === "done" ? 1 : p.rescan ? 0.5 : 0) + 14 * (p.sbom ? 0.5 : 0));
  const phases = [
    started ? "done" : "running",
    b.finished ? "done" : started ? "running" : "pending",
    c.finished ? "done" : started ? "running" : "pending",
    p.sbom ? "running" : "pending",
    p.rescan === "done" ? "done" : p.rescan ? "running" : "pending",
    "pending",
  ];
  const headline = p.sbom ? "Building SBOMs of what was really installed (Syft)"
    : b.finished && c.finished ? "Sandboxes done · finishing the rescan"
    : started ? `Running in parallel · baseline: ${b.finished ? "done" : b.label ?? "starting"} · fixed: ${c.finished ? "done" : c.label ?? "starting"}`
    : "Checking your approval and preparing two copies of the app";
  return { b, c, pct, phases, headline };
}

const laneStates = (l: LaneAt): Record<string, string> =>
  Object.fromEntries(STAGES.map((x, i) => [x.id, l.finished || i < l.idx ? "done" : i === l.idx ? "running" : "pending"]));

const fmt = (sec: number) => `${Math.floor(sec / 60)}:${String(sec % 60).padStart(2, "0")}`;

function useNow(): number {
  const [n, setN] = useState(Date.now());
  useEffect(() => { const t = window.setInterval(() => setN(Date.now()), 1000); return () => window.clearInterval(t); }, []);
  return n;
}

/* ------------------------------------------------------------------ pieces ------------------------------------- */

function StageIcon({ state }: { state: string }) {
  const box = "relative grid size-5 shrink-0 place-items-center";
  if (state === "running") return (
    <span className={box}><span className="ping-soft absolute inset-0 rounded-full bg-accent/40" />
      <CircleNotch className="animate-spin text-accent" size={16} weight="bold" /></span>);
  const pop = (el: React.ReactNode) => <motion.span initial={{ scale: 0 }} animate={{ scale: 1 }} transition={spring} className={box}>{el}</motion.span>;
  if (state === "done") return pop(<CheckCircle className="text-muted" weight="fill" size={16} />);
  if (state === "passed") return pop(<CheckCircle className="text-ok" weight="fill" size={16} />);
  if (state === "failed") return pop(<XCircle className="text-crit" weight="fill" size={16} />);
  if (state === "not_run" || state === "skipped" || state === "error") return pop(<WarningCircle className="text-high" weight="fill" size={16} />);
  return <span className={box}><span className="size-1.5 rounded-full bg-white/20" /></span>;
}

function Lane({ title, sub, states, seconds, notes, active, starting, cmd }: {
  title: string; sub: string; states: Record<string, string>; seconds?: Record<string, number | null | undefined>;
  notes?: Record<string, string>; active?: boolean; starting?: boolean; cmd?: string;
}) {
  return (
    <div className={`relative overflow-hidden rounded-xl p-4 ring-1 transition-colors duration-500 ${active ? "bg-accent/5 ring-accent/50" : "bg-canvas/40 ring-line"}`}>
      {active && <motion.div aria-hidden className="pointer-events-none absolute inset-x-0 top-0 h-px w-1/2 bg-gradient-to-r from-transparent via-accent to-transparent"
        animate={{ x: ["-100%", "200%"] }} transition={{ duration: 2.2, repeat: Infinity, ease: "linear" }} />}
      <div className="flex items-center gap-2">
        <Cube className={active ? "text-accent" : "text-faint"} weight="duotone" size={20} />
        <div className="min-w-0">
          <div className="text-[12.5px] font-medium">{title}</div>
          <div className="text-[11px] text-faint">{sub}</div>
        </div>
        {active && <span className="ml-auto rounded-full bg-accent/15 px-2 py-0.5 text-[10.5px] font-medium text-accent">{starting ? "starting container" : "running"}</span>}
      </div>
      <ol className="mt-3 space-y-1.5">
        {STAGES.map((s) => {
          const state = states[s.id] ?? "pending";
          const secs = seconds?.[s.id];
          return (
            <li key={s.id} className={`flex items-center gap-2.5 text-[12.5px] transition-opacity duration-500 ${state === "pending" ? "opacity-45" : ""}`}>
              <StageIcon state={state} />
              <s.Icon size={15} className="shrink-0 text-faint" />
              <span className={state === "running" ? "text-ink" : "text-muted"}>{s.label}</span>
              <span className="hidden truncate text-[11px] text-faint sm:inline">{s.hint}</span>
              <span className="ml-auto shrink-0 tabular-nums text-[11px] text-faint">
                {notes?.[s.id] ? <span className="text-accent">{notes[s.id]}</span> : secs ? `${secs}s` : state === "running" ? "running…" : state === "done" ? "done" : state === "skipped" || state === "not_run" ? state.replace("_", " ") : ""}</span>
            </li>);
        })}
      </ol>
      <AnimatePresence>{active && cmd && (
        <motion.p initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} key={cmd}
          className="mt-3 truncate rounded-md bg-black/30 px-2 py-1 font-mono text-[11px] text-muted">$ {cmd}</motion.p>)}</AnimatePresence>
    </div>);
}

function PhaseRail({ states }: { states: string[] }) {
  return (
    <ol className="grid grid-cols-3 gap-y-4 md:grid-cols-6">
      {PHASES.map((p, i) => {
        const state = states[i] ?? "pending";
        return (
          <li key={p.label} className="relative flex flex-col items-center px-1 text-center">
            {i > 0 && (
              <span className="absolute right-1/2 top-4 hidden h-0.5 w-full -translate-y-1/2 bg-white/10 md:block">
                <motion.span className="block h-full bg-accent" initial={false} animate={{ width: state === "pending" ? "0%" : "100%" }} transition={{ duration: 0.7, ease: "easeOut" }} />
              </span>)}
            <span className={`relative z-10 grid size-8 place-items-center rounded-full ring-1 transition-colors duration-500 ${
              state === "done" ? "bg-accent/15 text-accent ring-accent/40" : state === "running" ? "bg-accent text-white ring-accent" : "bg-raised text-faint ring-line"}`}>
              {state === "running" && <span className="ping-soft absolute inset-0 rounded-full bg-accent/50" />}
              {state === "done" ? <CheckCircle weight="fill" size={16} /> : <p.Icon size={16} weight={state === "running" ? "bold" : "regular"} />}
            </span>
            <span className={`mt-1.5 text-[11.5px] ${state === "pending" ? "text-faint" : "text-ink"}`}>{p.label}</span>
            <span className="text-[10.5px] text-faint">{p.hint}</span>
          </li>);
      })}
    </ol>);
}

const SANDBOX = ["All Linux capabilities dropped", "Non-root user", "No internet · local registry only", "No secrets · no Docker socket", "2 CPU · 4 GB"];

function SandboxBadges() {
  return (
    <ul className="flex flex-wrap gap-1.5 text-[11px] text-muted">
      {SANDBOX.map((b) => <li key={b} className="flex items-center gap-1 rounded-full bg-raised px-2 py-0.5 ring-1 ring-line"><LockKey size={11} className="text-faint" />{b}</li>)}
    </ul>);
}

function LiveProgress({ prog, startedAt, log }: { prog: Prog; startedAt: number | null; log: { t: number; m: string }[] }) {
  const now = useNow();
  const M = model(prog);
  const pct = M.pct;
  const el = startedAt ? Math.max(0, Math.floor((now - startedAt) / 1000)) : 0;
  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={spring} className="mt-3 space-y-5">
      <div className="flex flex-wrap items-end gap-3">
        <div>
          <div className="flex items-center gap-2 text-[15px] font-semibold">
            <span className="relative size-2.5"><span className="ping-soft absolute inset-0 rounded-full bg-accent" /><span className="absolute inset-0 rounded-full bg-accent" /></span>
            Proving the fix</div>
          <AnimatePresence mode="wait">
            <motion.p key={M.headline} initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -4 }} className="mt-0.5 text-[12.5px] text-muted">{M.headline}</motion.p>
          </AnimatePresence>
        </div>
        <div className="ml-auto flex items-center gap-3 font-mono text-[12px] tabular-nums text-muted">
          <span className="flex items-center gap-1"><Timer size={14} />{fmt(el)}</span>
          <span className="text-faint">usually ~1.5–2 min</span>
          <span className="text-[14px] text-ink">{Math.round(pct)}%</span>
        </div>
      </div>
      <div className="relative h-1.5 overflow-hidden rounded-full bg-raised" role="progressbar" aria-valuenow={Math.round(pct)} aria-valuemin={0} aria-valuemax={100}>
        <motion.div className="h-full rounded-full bg-accent" initial={false} animate={{ width: `${pct}%` }} transition={{ type: "spring", stiffness: 60, damping: 20 }} />
        <motion.div aria-hidden className="absolute inset-y-0 w-1/4 bg-gradient-to-r from-transparent via-white/25 to-transparent"
          animate={{ x: ["-100%", "400%"] }} transition={{ duration: 1.8, repeat: Infinity, ease: "linear" }} />
      </div>
      <PhaseRail states={M.phases} />
      <div className="grid gap-3 md:grid-cols-2">
        <Lane title="Baseline" sub="target branch before this PR" states={laneStates(M.b)} active={!M.b.finished && M.phases[0] === "done"} starting={M.b.idx < 0 && !M.b.finished} cmd={M.b.cmd} />
        <Lane title="Fixed version" sub="pull request + approved patch" states={laneStates(M.c)} active={!M.c.finished && M.phases[0] === "done"} starting={M.c.idx < 0 && !M.c.finished} cmd={M.c.cmd} />
      </div>
      <SandboxBadges />
      <div className="rounded-lg bg-black/30 p-3 font-mono text-[11px] ring-1 ring-line">
        <div className="mb-1.5 flex items-center gap-1.5 text-faint"><Terminal size={13} /> live log <span className="ml-auto font-sans">pass / fail appears when both sandboxes and the rescan finish</span></div>
        <AnimatePresence initial={false}>
          {log.slice(-6).map((e) => (
            <motion.div key={e.t + e.m} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} className="flex gap-3 text-muted">
              <span className="shrink-0 tabular-nums text-faint">+{fmt(Math.max(0, Math.floor((e.t - (startedAt ?? e.t)) / 1000)))}</span>
              <span className="truncate">{e.m}</span>
            </motion.div>))}
        </AnimatePresence>
        {log.length === 0 && <div className="text-faint">waiting for the first step…</div>}
      </div>
    </motion.div>);
}

/* ------------------------------------------------------------------ validation panel --------------------------- */

const finalStates = (side: any): Record<string, string> => Object.fromEntries((side?.stages ?? []).map((x: any) => [x.id, x.status]));
const finalSecs = (side: any): Record<string, number> => Object.fromEntries((side?.stages ?? []).map((x: any) => [x.id, x.seconds]));
const finalNotes = (side: any): Record<string, string> => Object.fromEntries((side?.stages ?? [])
  .filter((x: any) => x.id === "hooks" && (x.hooks ?? []).some((h: any) => h.cache === "hit")).map((x: any) => [x.id, "reused verified build"]));

function Validation({ project, s, refresh, onRunning }: { project: string | null; s: Sections; refresh: () => void; onRunning?: (r: boolean) => void }) {
  const [state, setState] = useState<{ status?: string; message?: string; progress?: Prog } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [log, setLog] = useState<{ t: number; m: string }[]>([]);
  const [startedAt, setStartedAt] = useState<number | null>(null);
  const timer = useRef<number | null>(null);
  const refreshRef = useRef(refresh);
  refreshRef.current = refresh;
  const v = s.validation;

  const onStatus = useCallback((r: any) => {
    setState(r);
    if (r?.message) setLog((prev) => (prev.length && prev[prev.length - 1].m === r.message ? prev : [...prev, { t: Date.now(), m: r.message }]));
  }, []);

  const poll = useCallback(() => {
    if (timer.current) window.clearInterval(timer.current);
    timer.current = window.setInterval(async () => {
      try {
        const r = await api(`/api/validation${q(project)}`);
        onStatus(r);
        if (r.status && r.status !== "running") { window.clearInterval(timer.current!); refreshRef.current(); }
      } catch { /* 404 until the first result exists */ }
    }, 2000);
  }, [project, onStatus]);

  useEffect(() => { // opened or reloaded while a validation is running: pick it up instead of showing the start button
    let alive = true;
    api(`/api/validation${q(project)}`).then((r) => {
      if (!alive) return;
      if (r.status === "running") { onStatus(r); setStartedAt(Date.now()); poll(); }
      else if (r.status === "interrupted") setState(r);
    }).catch(() => {});
    return () => { alive = false; if (timer.current) window.clearInterval(timer.current); };
  }, [project, poll, onStatus]);

  const start = async () => {
    setErr(null); setLog([]); setStartedAt(Date.now());
    try { await api("/api/validate", jsonPost({ project })); setState({ status: "running" }); poll(); }
    catch (e) { setErr((e as Error).message); }
  };

  const running = state?.status === "running";
  useEffect(() => { onRunning?.(running); }, [running, onRunning]);
  const g = v.gate;
  const approved = s.remediation.status === "approved";
  const executed = !!v.baseline;

  return (
    <section className="panel p-5" aria-labelledby="val-h">
      <div className="flex flex-wrap items-center gap-3">
        <h2 id="val-h" className="text-[13px] font-semibold">Validation</h2>
        {g && !running && (
          <>
            <span className="text-[12px] text-faint">Last run {v.finished ? new Date(v.finished * 1000).toLocaleString() : ""}</span>
            <button onClick={start} className="ml-auto rounded-md px-2.5 py-1 text-[12px] text-accent ring-1 ring-accent/40 transition hover:bg-accent/10 active:scale-[0.98]">Run validation again</button>
          </>)}
      </div>

      {running && <LiveProgress prog={(state as any)?.progress ?? {}} startedAt={startedAt} log={log} />}

      {!running && !g && (
        <div className="mt-3 space-y-5">
          <p className="max-w-[70ch] text-[12.5px] text-muted">Two copies of the app go into locked Docker sandboxes <b className="text-ink">at the same time</b>: the target branch before this PR (the known-good baseline)
            and the pull request with your approved patch. Both are installed, built and tested while the fixed version is rescanned. Fixed rules decide “verified”.</p>
          <PhaseRail states={[]} />
          <div className="flex flex-wrap items-center gap-3">
            <button onClick={start} disabled={!approved}
              title={!approved ? "A person must approve the fix first" : ""}
              className="flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-[13px] font-medium text-white shadow-[0_0_24px_-6px] shadow-accent/60 transition hover:brightness-110 active:scale-[0.98] disabled:opacity-40 disabled:shadow-none">
              <Play weight="fill" size={14} />Validate approved fix</button>
            <span className="text-[12px] text-faint">{approved ? "takes about 1.5–2 minutes" : "approve the fix in step 4 first"}</span>
          </div>
          <SandboxBadges />
          {(state?.status === "interrupted" || state?.status === "cancelled") && <p role="alert" className="text-[12px] text-high">{state.message ?? "Validation was stopped. Run it again."}</p>}
          {String(state?.status ?? "").startsWith("error") && <p role="alert" className="text-[12px] text-crit">{state?.status}</p>}
        </div>)}

      {!running && g && (
        <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={spring} className="mt-3 space-y-5">
          <div className="flex flex-wrap gap-2 text-[12px]">
            <span className="rounded bg-raised px-2 py-1">target: <b className={g.target === "corrected" ? "text-ok" : "text-crit"}>{g.target}</b></span>
            <span className="rounded bg-raised px-2 py-1">validation: <b className={g.validation === "passed" ? "text-ok" : g.validation === "incomplete" ? "text-high" : "text-crit"}>{g.validation}</b></span>
            <span className={`rounded px-2 py-1 ${g.verified ? "bg-ok/10 ring-1 ring-ok/30" : "bg-raised"}`}>verified: <b className={g.verified ? "text-ok" : "text-crit"}>{g.verified ? "yes" : "no"}</b></span>
          </div>
          {g.reasons?.length > 0 && <ul className="list-disc pl-5 text-[12px] text-muted">{g.reasons.map((r: string) => <li key={r}>{r}</li>)}</ul>}
          <PhaseRail states={executed ? PHASES.map(() => "done") : []} />
          {v.timings && (
            <p className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px] text-muted"><Timer size={14} className="text-faint" />
              <span>Took <b className="font-mono text-ink">{fmt(Math.round(v.timings.total))}</b></span>
              <span className="text-faint">in parallel → baseline {v.timings.baseline}s · fixed {v.timings.candidate}s · rescan {v.timings.rescan}s</span>
              <span className="text-faint">then SBOMs {v.timings.sbom}s</span></p>)}
          {executed && (
            <div className="grid gap-3 md:grid-cols-2">
              <Lane title="Baseline" sub="target branch before this PR" states={finalStates(v.baseline)} seconds={finalSecs(v.baseline)} notes={finalNotes(v.baseline)} />
              <Lane title="Fixed version" sub="pull request + approved patch" states={finalStates(v.candidate)} seconds={finalSecs(v.candidate)} notes={finalNotes(v.candidate)} />
            </div>)}
          {String(state?.status ?? "").startsWith("error") && <p role="alert" className="text-[12px] text-crit">{state?.status}</p>}
        </motion.div>)}

      {err && <p role="alert" className="mt-2 text-[12px] text-crit">{err}</p>}
    </section>);
}

/* The PR as submitted vs the PR with the approved fix, rescanned by the same engine. "Verified" still comes only
   from the gate; this card says what the rescan found. Pre-existing findings are counted, never hidden. */
const GROUPS: [string, string][] = [["vulnerabilities", "Known vulnerabilities (CVE / GHSA)"], ["malware_suspicious", "Malware & suspicious packages"],
  ["config_ci", "Config & CI changes"], ["other", "Dependency version changes (low, info)"]];

function VerdictChange({ vc, gate }: { vc: any; gate: any }) {
  if (!vc) return null;
  if (vc.error) return <p className="panel p-4 text-[12px] text-high">{vc.error}</p>;
  const { before: b, after: a } = vc;
  const verified = !!gate?.verified;
  const side = (title: string, sub: string, x: any, after: boolean, delay: number) => (
    <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ ...spring, delay }}
      className={`rounded-xl p-4 ring-1 ${after ? (verified && x.introduced.total === 0 ? "bg-ok/5 ring-ok/30" : "ring-line") : "bg-crit/5 ring-crit/30"}`}>
      <div className="text-[11.5px] font-medium uppercase tracking-wide text-faint">{title}</div>
      <div className="text-[11px] text-faint">{sub}</div>
      <div className="mt-2"><Verdict verdict={x.verdict} complete size="xl" /></div>
      <ul className="mt-3 space-y-1 text-[12.5px]">{GROUPS.map(([k, label]) => (
        <li key={k} className="flex justify-between gap-3"><span className="text-muted">{label}</span>
          <b className={`font-mono tabular-nums ${!x.introduced[k] ? "text-ok" : k === "other" ? "text-muted" : "text-crit"}`}>{x.introduced[k]}</b></li>))}
        <li className="flex justify-between gap-3 border-t border-line pt-1"><span>High / critical <span className="text-faint">(level or advisory severity)</span></span>
          <b className={`font-mono tabular-nums ${x.high_or_critical ? "text-crit" : "text-ok"}`}>{x.high_or_critical}</b></li>
      </ul>
    </motion.div>);
  return (
    <section className="panel p-5" aria-labelledby="vc-h">
      <h2 id="vc-h" className="text-[13px] font-semibold">Before → after the fix <span className="font-normal text-faint">· same engine, same advisory snapshot</span></h2>
      <div className="mt-3 grid items-center gap-3 md:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)]">
        {side("Before", "the pull request as submitted", b, false, 0)}
        <motion.span initial={{ opacity: 0, scale: 0.6 }} animate={{ opacity: 1, scale: 1 }} transition={{ ...spring, delay: 0.25 }}>
          <ArrowRight className="mx-auto size-6 rotate-90 text-faint md:rotate-0" /></motion.span>
        {side("After the approved fix", "pull request + approved patch, rescanned", a, true, 0.4)}
      </div>
      <p className="mt-3 text-[12px] text-muted">
        {verified ? <><b className="text-ok">Verified:</b> built, tested and rescanned in isolation.</> : <><b className="text-high">Not verified yet:</b> {gate?.validation ?? "validation has not passed"}; the “after” column is the rescan only.</>}
        {" "}Counts are risks <i>this pull request</i> introduces. {a.pre_existing} older finding(s) were already in the project before this PR; they are unchanged and listed under Detect › Already there.</p>
    </section>);
}

/* Before/after delta from contextual scoring (informational; the gate decides "verified"). */
function Delta({ d }: { d: any }) {
  if (!d) return null;
  if (d.error) return <p className="panel p-4 text-[12px] text-high">{d.error}</p>;
  const LV = ["critical", "high", "medium", "low", "info"];
  return (
    <details className="panel group p-4 text-[12.5px]">
      <summary className="flex cursor-pointer list-none items-center gap-2 text-[13px] font-semibold">
        <ArrowRight size={13} className="text-faint transition group-open:rotate-90" />
        Advanced · contextual risk index <span className="font-normal text-faint">(informational, not part of the decision)</span></summary>
      <p className="mt-2 max-w-[90ch] text-[12px] text-muted">Counts <i>every</i> finding in the project, matched by advisory. An advisory that also affects a copy the
        project already had stays “unchanged” here even when the copy this PR added is gone. The gate above judges what the pull request introduces.</p>
      <div className="mt-3 grid gap-4 md:grid-cols-[220px_minmax(0,1fr)]">
        <div>
          <div className="flex items-baseline gap-2 font-mono tabular-nums"><span className="text-[22px] text-muted">{d.risk_index.before}</span><span className="text-faint">→</span>
            <span className={`text-[26px] ${d.risk_index.after < d.risk_index.before ? "text-ok" : d.risk_index.after > d.risk_index.before ? "text-crit" : ""}`}>{d.risk_index.after}</span></div>
          <p className="mt-1 text-[11px] text-faint">{d.risk_index.definition}. {d.risk_index.note}</p>
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <table className="text-[12px] tabular-nums"><thead className="text-[11px] text-faint"><tr><th className="text-left">level</th><th className="text-right">before</th><th className="text-right">after</th></tr></thead>
            <tbody>{LV.map((lv) => <tr key={lv}><td className="text-muted">{lv}</td><td className="text-right">{d.levels_before[lv] ?? 0}</td><td className="text-right">{d.levels_after[lv] ?? 0}</td></tr>)}</tbody></table>
          <ul className="space-y-1 text-[12px]">{d.targets.map((t: any) => (
            <li key={t.id} className="flex gap-2"><span className={t.status === "remediated" ? "text-ok" : t.status === "regressed" ? "text-crit" : "text-high"}>{t.status}</span><span className="truncate font-mono text-[11px] text-muted">{t.id}</span></li>))}</ul>
        </div>
      </div>
      <p className="mt-2 text-[11.5px] text-muted">Conditions: {Object.entries(d.conditions).map(([k, v]) => `${k.replace(/_/g, " ")} ${v ? "✓" : "✗"}`).join(" · ")}
        {d.new_findings?.length ? ` · ${d.new_findings.length} new finding(s)` : ""}</p>
    </details>);
}

export function Validate({ s, project, refresh }: { s: Sections; project: string | null; refresh: () => void }) {
  const [running, setRunning] = useState(false); // a re-run must not show the previous result as if it were current
  return (
    <div className="flex flex-col gap-4">
      <SectionHead n={5} title="Validate the approved fix" sub="Baseline and candidate are installed, built and tested in disposable containers (all capabilities dropped, non-root, no secrets, no internet except the local registry), then rescanned. “Verified” only when every required stage passed." />
      {!running && <VerdictChange vc={s.before_after?.verdict_change} gate={s.validation?.gate} />}
      <Validation project={project} s={s} refresh={refresh} onRunning={setRunning} />
      <Delta d={s.before_after?.delta} />
    </div>);
}
