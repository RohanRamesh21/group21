import { AnimatePresence, MotionConfig, motion } from "motion/react";
import { useEffect, useMemo, useState } from "react";
import { Play } from "@phosphor-icons/react";
import { AgentLanes } from "./components/AgentLanes";
import { CaseBoard } from "./components/CaseBoard";
import { Debate } from "./components/Debate";
import { EvidenceDrawer } from "./components/EvidenceDrawer";
import { GraphView } from "./components/GraphView";
import { HumanModal } from "./components/HumanModal";
import { Overview } from "./components/Overview";
import { ProjectScan } from "./components/ProjectScan";
import { Agents } from "./run/Agents";
import { Detect } from "./run/Detect";
import { Discover } from "./run/Discover";
import { FixApprove } from "./run/FixApprove";
import { Report } from "./run/Report";
import { Header, Journey, type PrRun } from "./run/Shell";
import { LiveToasts } from "./run/LiveToasts";
import { Summary } from "./run/Summary";
import { Validate } from "./run/Validate";
import { api, journey, type StepId } from "./run/shared";
import { useRunModel } from "./run/useRunModel";
import { OutdatedRun } from "./run/OutdatedRun";
import { useMeta, useRun } from "./useRun";

type View = StepId | "scan" | "replay";

function Replay() {
  const meta = useMeta();
  const { runId, state, feed, start, answer } = useRun();
  const [evidence, setEvidence] = useState<string | null>(null);
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-3 rounded-xl bg-high/8 px-4 py-3 text-[12.5px] text-high ring-1 ring-high/30">
        RECORDED: this replays an earlier run of the older multi-agent loop, for illustration only. The live, budgeted agents are in step 3 “Investigate”.
        <button onClick={() => start("replay", "canned")} className="ml-auto inline-flex items-center gap-1.5 rounded-lg bg-high/90 px-3 py-1.5 font-medium text-canvas"><Play weight="fill" /> Play recording</button>
      </div>
      <Overview meta={meta} state={state} />
      <div className="grid gap-4 xl:h-[640px] xl:grid-cols-[1.35fr_1fr]">
        <AgentLanes feed={feed} onEvidence={setEvidence} />
        <div className="grid min-h-0 gap-4" style={{ gridTemplateRows: "1fr 1fr" }}><GraphView state={state} /><Debate feed={feed} state={state} /></div>
      </div>
      <CaseBoard state={state} onEvidence={setEvidence} />
      <HumanModal state={state} onAnswer={answer} />
      <EvidenceDrawer runId={runId} id={evidence} onClose={() => setEvidence(null)} />
    </div>);
}

export default function App() {
  const [project, setProject] = useState<string | null>(() => new URLSearchParams(window.location.search).get("run"));
  const [prRuns, setPrRuns] = useState<PrRun[]>([]);
  const loadPrRuns = () => api("/api/pr-runs").then(setPrRuns).catch(() => undefined);
  useEffect(() => { loadPrRuns(); }, []);
  useEffect(() => {  // keep ?run= in the address bar, so a PR comment link or Buddy can open the same run
    const u = new URL(window.location.href);
    if (project) u.searchParams.set("run", project); else u.searchParams.delete("run");
    window.history.replaceState(null, "", u.toString());
  }, [project]);
  const VIEWS: View[] = ["summary", "discover", "detect", "investigate", "fix", "validate", "report", "scan", "replay"];
  const fromHash = () => (VIEWS.find((v) => v === window.location.hash.slice(1)) ?? "summary") as View;
  const [view, setView] = useState<View>(fromHash);
  useEffect(() => { if (window.location.hash.slice(1) !== view) window.history.replaceState(null, "", `#${view}`); }, [view]);
  useEffect(() => { const on = () => setView(fromHash()); window.addEventListener("hashchange", on); return () => window.removeEventListener("hashchange", on); }, []);
  const [jobs, setJobs] = useState<{ id: string; label: string }[]>([]);
  const { model, err, refresh } = useRunModel(project);
  const s = model?.sections;
  const steps = useMemo(() => journey(s), [s]);
  useEffect(() => { api("/api/projects").then((j) => setJobs((j.jobs ?? j).filter((x: { status: string }) => x.status === "done"))).catch(() => undefined); }, [view]);
  useEffect(() => { window.scrollTo({ top: 0, behavior: "smooth" }); }, [view]);
  const isStep = view !== "scan" && view !== "replay";

  return (
    <MotionConfig reducedMotion="user">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded focus:bg-accent focus:px-3 focus:py-1.5">Skip to content</a>
      <div className="relative z-10 mx-auto flex min-h-[100dvh] max-w-[1560px] flex-col">
        <Header s={s} project={project} setProject={(p) => { setProject(p); setView("summary"); }} jobs={jobs} prRuns={prRuns} view={view} setView={setView} />
        <LiveToasts project={project} onRunsChanged={loadPrRuns} onCurrentChanged={refresh}
          onOpen={(p, v) => { setProject(p); setView(v ?? "summary"); }} />
        {s && <Journey steps={steps} active={isStep ? view : ""} onPick={setView} />}
        <main id="main" className="flex-1 px-6 pb-10 pt-5">
          {isStep && err && (err.startsWith("outdated")
            ? <OutdatedRun project={project} message={err} onDone={() => { loadPrRuns(); refresh(); }} />
            : <div role="alert" className="panel p-8 text-[13px] text-muted">{err === "no run yet" ? "No run yet. Use “Scan a project”, or run `guardian check` in the terminal." : `Could not load the run: ${err}`}</div>)}
          {isStep && !s && !err && <div className="panel h-48 animate-pulse" aria-busy="true" />}
          <AnimatePresence mode="wait">
            <motion.div key={view + (project ?? "")} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }} transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}>
              {view === "scan" && <ProjectScan />}
              {view === "replay" && <Replay />}
              {s && view === "summary" && <Summary s={s} steps={steps} onPick={setView} />}
              {s && view === "discover" && <Discover s={s} project={project} />}
              {s && view === "detect" && <Detect s={s} project={project} refresh={refresh} />}
              {s && view === "investigate" && <Agents s={s} project={project} refresh={refresh} onPick={setView} />}
              {s && view === "fix" && <FixApprove s={s} project={project} refresh={refresh} />}
              {s && view === "validate" && <Validate s={s} project={project} refresh={refresh} />}
              {s && view === "report" && <Report s={s} project={project} />}
            </motion.div>
          </AnimatePresence>
        </main>
      </div>
    </MotionConfig>);
}
