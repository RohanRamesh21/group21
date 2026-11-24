import { AnimatePresence, motion } from "motion/react";
import { useEffect, useRef, useState } from "react";
import { ArrowsClockwise, ClockCounterClockwise, FileZip, FolderOpen, GithubLogo, Play, Robot, Terminal, Warning } from "@phosphor-icons/react";
import type { Route } from "../route";
import { pageMotion, VerdictChip } from "../ui";
import { useMeta, useRun } from "../useRun";
import { AgentLanes } from "./AgentLanes";
import { CaseBoard } from "./CaseBoard";
import { Debate } from "./Debate";
import { EvidenceDrawer } from "./EvidenceDrawer";
import { GraphView } from "./GraphView";
import { HumanModal } from "./HumanModal";
import { Overview } from "./Overview";
import { useContext } from "./ProjectResults";
import { RecentScans, useScans } from "./RecentScans";
import { ScanProgress } from "./ScanProgress";
import { useJob } from "./ScanPage";
import { SourceInput } from "./SourceInput";

/** Choose what to investigate: a finished scan, or a new source that is scanned first. */
function TargetPicker({ go, onNewScan }: { go: (r: Route) => void; onNewScan: (id: string) => void }) {
  const { entries } = useScans();
  const done = entries.filter((e) => e.status === "done");
  return (
    <motion.section {...pageMotion} className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.15fr)]">
      <div className="panel flex flex-col gap-3 p-5">
        <div><h2 className="text-[15px] font-medium">Investigate a finished scan</h2>
          <p className="text-[12.5px] text-muted">The agents re-read that repository's commits, lockfile and registry data themselves.</p></div>
        <div className="scroll-thin max-h-[380px] overflow-y-auto pr-1">
          {done.length ? <RecentScans dense entries={done} limit={50} onOpen={(id) => go({ page: "investigate", id })} />
            : <div className="py-6 text-center text-[13px] text-muted">No finished scans yet. Scan something on the right.</div>}
        </div>
      </div>
      <div className="panel flex flex-col gap-4 p-5">
        <div><h2 className="text-[15px] font-medium">Or bring something new</h2>
          <p className="text-[12.5px] text-muted">Guardian scans it first (the agents need the evidence), then starts the investigation.</p></div>
        <SourceInput id="investigate" submitLabel="Scan, then investigate" onStarted={onNewScan} />
      </div>
    </motion.section>
  );
}

/** The agent investigation of one scanned project (or the clearly labelled recorded example). */
export function Investigate({ id, go }: { id: string | null; go: (r: Route) => void }) {
  const meta = useMeta();
  const { runId, state, feed, error, start, answer, reset } = useRun();
  const { ctx, err: ctxErr } = useContext(id);
  const [evidence, setEvidence] = useState<string | null>(null);
  const [pending, setPending] = useState<string | null>(null);   // a new source being scanned before the agents start
  const autoRun = useRef<string | null>(null);
  const { job: pendingJob } = useJob(pending);

  // a fresh target never shows the previous target's run
  useEffect(() => { reset(); }, [id, reset]);
  // the new source finished scanning: open it and start the agents
  useEffect(() => {
    if (pendingJob?.status === "done") {
      autoRun.current = pendingJob.id;
      const t = setTimeout(() => { setPending(null); go({ page: "investigate", id: pendingJob.id }); }, 900);
      return () => clearTimeout(t);
    }
  }, [pendingJob?.status, pendingJob?.id, go]);
  useEffect(() => {
    if (id && ctx && autoRun.current === id && meta?.live_available) { autoRun.current = null; start("live", id); }
  }, [id, ctx, meta?.live_available, start]);

  const running = state?.status === "running" || state?.status === "starting";
  const recorded = !!state?.target?.recorded;
  const modelError = feed.find((f) => f.type === "audit" && f.event === "investigation_error");
  const { job: targetJob } = useJob(id);
  const Icon = id === "main" ? Terminal : targetJob?.kind === "git" ? GithubLogo : targetJob?.kind === "zip" ? FileZip : FolderOpen;

  return (
    <div className="flex flex-col gap-4 pb-12">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2.5 text-2xl font-semibold tracking-tight"><Robot size={26} weight="duotone" className="text-accent" />Agent investigation</h1>
          <p className="mt-1 max-w-3xl text-[13px] text-muted">Lead, Dependency Hunter, Change Forensics and Skeptic dig into a change, cite evidence for every claim and argue it out.
            Deterministic checks run first and hard signals can never be argued down. A human owns the final decision.</p>
        </div>
      </div>

      <AnimatePresence mode="wait">
        {!id && !pending && <TargetPicker key="pick" go={go} onNewScan={setPending} />}
        {!id && pending && (
          <motion.div key="scanning" {...pageMotion} className="flex flex-col gap-2">
            {pendingJob ? <ScanProgress job={pendingJob} compact /> : <div className="panel h-40 animate-pulse" />}
            <div className="flex items-center gap-3 text-[12.5px] text-muted">
              {pendingJob?.status === "error" ? <span className="text-crit">The scan failed, so there is nothing to investigate.</span> : <span>The investigation starts as soon as the scan finishes.</span>}
              <button onClick={() => setPending(null)} className="text-accent hover:underline">choose something else</button>
            </div>
          </motion.div>
        )}
        {id && (
          <motion.section key={`target-${id}`} {...pageMotion} className="panel flex flex-wrap items-center gap-x-5 gap-y-3 px-5 py-4">
            <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-accent/12 text-accent ring-1 ring-inset ring-accent/25">
              <Icon size={20} weight="duotone" />
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2"><span className="text-[11.5px] uppercase tracking-wider text-faint">Investigating</span>
                <span className="font-mono text-[15px] text-ink">{ctx?.app ?? (ctxErr ? "unknown scan" : "…")}</span><VerdictChip verdict={ctx?.verdict} /></div>
              <div className="font-mono text-[11.5px] text-muted">
                {ctxErr ? <span className="text-crit">{ctxErr}</span> : ctx ? (ctx.compare ? `${ctx.base} (${ctx.base_commit.slice(0, 8)}) → ${ctx.head} (${ctx.head_commit.slice(0, 8)})` : `${ctx.head_commit.slice(0, 8)} · full scan: no change to compare, the agents review what is present`) : "loading…"}
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {meta?.live_available && meta.model && <span className="hidden rounded-md border border-line px-2 py-1 font-mono text-[11px] text-muted xl:inline">{meta.model.replace("anthropic/", "")}</span>}
              {state && <span className="font-mono text-[11.5px] text-muted">{state.elapsed.toFixed(0)}s</span>}
              <motion.button whileTap={{ scale: 0.97 }} onClick={() => start("live", id)} disabled={running || !ctx || !meta?.live_available}
                title={meta && !meta.live_available ? "No LLM key in .env: live agents are not available on this server" : undefined}
                className="inline-flex items-center gap-2 rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white shadow-[inset_0_1px_0_rgb(255_255_255/0.25)] transition enabled:hover:brightness-110 disabled:opacity-40">
                {running && !recorded ? <ArrowsClockwise size={15} className="animate-spin" /> : <Play size={14} weight="fill" />}
                {running && !recorded ? "Investigating…" : state && !recorded ? "Run again" : "Run investigation"}
              </motion.button>
              <button onClick={() => go({ page: "investigate", id: null })} disabled={running} className="rounded-lg border border-line px-3 py-2 text-[13px] text-muted transition-colors enabled:hover:text-ink disabled:opacity-40">Change</button>
            </div>
          </motion.section>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {meta && !meta.live_available && id && (
          <motion.div key="nolive" initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden rounded-lg border border-high/30 bg-high/8 px-4 py-2.5 text-[12.5px] text-high">
            Live agents need an LLM key in <span className="font-mono">.env</span> (see docs/SETUP.md). The scan results for this project are complete without them.
          </motion.div>)}
        {(error || state?.status === "error") && (
          <motion.div key="err" initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="rounded-lg border border-crit/30 bg-crit/8 px-4 py-2.5 text-[12.5px] text-crit">
            {error ?? state?.error}
          </motion.div>)}
        {modelError && !recorded && (
          <motion.div key="model" initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            className="flex items-start gap-2 rounded-lg border border-high/30 bg-high/8 px-4 py-2.5 text-[12.5px] text-ink/85">
            <Warning size={16} className="mt-0.5 shrink-0 text-high" weight="bold" />
            <span><b className="text-high">The model could not be used</b> ({String((modelError as { detail?: string }).detail ?? (modelError as { error?: string }).error)}).
              The required deterministic checks still ran; the findings below come from them and the verdict falls back to the hard-signal rule.</span>
          </motion.div>)}
        {recorded && (
          <motion.div key="rec" initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
            className="flex items-center gap-2 rounded-lg border border-line bg-surface/70 px-4 py-2.5 text-[12.5px] text-muted">
            <ClockCounterClockwise size={15} className="text-accent" />
            <span><b className="text-ink">Recorded example.</b> A replay of an earlier agent run on a fixed sample scenario{ctx ? <>, not an investigation of <span className="font-mono text-ink">{ctx.app}</span></> : null}. No model is called.</span>
          </motion.div>)}
      </AnimatePresence>

      {(id || state) && (
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.45, delay: 0.1 }} className="flex flex-col gap-4">
          <Overview ctx={ctx} state={state} recorded={recorded} />
          <div className="grid gap-4 xl:h-[640px] xl:grid-cols-[1.35fr_1fr]">
            <AgentLanes feed={feed} onEvidence={setEvidence} />
            <div className="grid min-h-0 gap-4" style={{ gridTemplateRows: "1fr 1fr" }}>
              <GraphView state={state} app={recorded ? "recorded example" : ctx?.app} />
              <Debate feed={feed} state={state} />
            </div>
          </div>
          <CaseBoard state={state} onEvidence={setEvidence} />
        </motion.div>
      )}

      {meta?.replay_available && (
        <div className="flex flex-wrap items-center gap-2 text-[12px] text-faint">
          <span>No LLM key, or want to see a full debate first?</span>
          <button onClick={() => start("replay", null)} disabled={running} className="inline-flex items-center gap-1.5 text-accent enabled:hover:underline disabled:opacity-40">
            <ClockCounterClockwise size={13} /> Play the recorded example run</button>
        </div>
      )}

      <HumanModal state={state} onAnswer={answer} />
      <EvidenceDrawer runId={runId} id={evidence} onClose={() => setEvidence(null)} />
    </div>
  );
}
