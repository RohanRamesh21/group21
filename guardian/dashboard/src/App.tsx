import { MotionConfig, motion } from "motion/react";
import { useState } from "react";
import { AgentLanes } from "./components/AgentLanes";
import { CaseBoard } from "./components/CaseBoard";
import { DepGraph } from "./components/DepGraph";
import { Debate } from "./components/Debate";
import { EvidenceDrawer } from "./components/EvidenceDrawer";
import { GraphView } from "./components/GraphView";
import { HumanModal } from "./components/HumanModal";
import { Overview } from "./components/Overview";
import { TopBar } from "./components/TopBar";
import { useMeta, useRun } from "./useRun";

export default function App() {
  const meta = useMeta();
  const { runId, state, feed, error, start, answer } = useRun();
  const [mode, setMode] = useState<"replay" | "live">("replay");
  const [evidence, setEvidence] = useState<string | null>(null);
  const [tab, setTab] = useState<"investigation" | "graph">("investigation");

  return (
    <MotionConfig reducedMotion="user">
      <div className="relative z-10 mx-auto flex min-h-[100dvh] max-w-[1600px] flex-col">
        <TopBar meta={meta} state={state} mode={mode} setMode={setMode} onStart={() => start(mode, mode === "live" ? "real" : "canned")} />
        {(error || meta?.error) && (
          <div className="mx-6 mb-2 rounded-lg border border-crit/30 bg-crit/8 px-4 py-2 text-sm text-crit">{error ?? meta?.error}</div>
        )}
        <nav className="mx-6 mb-3 flex gap-1 border-b border-line text-sm" aria-label="Views">
          {([["investigation", "Investigation"], ["graph", "Dependency graph"]] as const).map(([k, label]) => (
            <button key={k} onClick={() => setTab(k)} className={`relative px-3 pb-2.5 pt-1 transition-colors ${tab === k ? "text-ink" : "text-muted hover:text-ink"}`}>
              {label}
              {tab === k && <motion.span layoutId="tab-line" className="absolute inset-x-2 -bottom-px h-0.5 rounded-full bg-accent" />}
            </button>))}
        </nav>
        {tab === "graph" && <main className="flex flex-1 flex-col gap-4 px-6 pb-6"><DepGraph /></main>}
        <main className={`flex flex-1 flex-col gap-4 px-6 pb-6 ${tab === "graph" ? "hidden" : ""}`}>
          <Overview meta={meta} state={state} />
          <div className="grid gap-4 xl:h-[640px] xl:grid-cols-[1.35fr_1fr]">
            <AgentLanes feed={feed} onEvidence={setEvidence} />
            <div className="grid min-h-0 gap-4" style={{ gridTemplateRows: "1fr 1fr" }}>
              <GraphView state={state} />
              <Debate feed={feed} state={state} />
            </div>
          </div>
          <CaseBoard state={state} onEvidence={setEvidence} />
        </main>
      </div>
      <HumanModal state={state} onAnswer={answer} />
      <EvidenceDrawer runId={runId} id={evidence} onClose={() => setEvidence(null)} />
    </MotionConfig>
  );
}
