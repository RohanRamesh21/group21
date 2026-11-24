import { MotionConfig, motion } from "motion/react";
import { useState } from "react";
import { AgentLanes } from "./components/AgentLanes";
import { AhpAdvisor } from "./components/AhpAdvisor";
import { CaseBoard } from "./components/CaseBoard";
import { Day1Report } from "./components/Day1Report";
import { DepGraph } from "./components/DepGraph";
import { Debate } from "./components/Debate";
import { EvidenceDrawer } from "./components/EvidenceDrawer";
import { GraphView } from "./components/GraphView";
import { HumanModal } from "./components/HumanModal";
import { Overview } from "./components/Overview";
import { ProjectScan } from "./components/ProjectScan";
import { Remediation } from "./components/Remediation";
import { RiskScores } from "./components/RiskScores";
import { TopBar } from "./components/TopBar";
import { useMeta, useRun } from "./useRun";

export default function App() {
  const meta = useMeta();
  const { runId, state, feed, error, start, answer } = useRun();
  const [mode, setMode] = useState<"replay" | "live">("replay");
  const [evidence, setEvidence] = useState<string | null>(null);
  // Scoring-only view by default (no uptime-kuma sandbox needed). Open the dashboard with ?full to get every tab back.
  const scoringOnly = !new URLSearchParams(window.location.search).has("full");
  const [tab, setTab] = useState<"investigation" | "day1" | "graph" | "scores" | "remediation" | "ahp" | "scan">(scoringOnly ? "scores" : "investigation");
  const tabs = ([["investigation", "Investigation"], ["day1", "Day 1 report"], ["graph", "Dependency graph"], ["scores", "Risk scores"], ["remediation", "Remediation"], ["ahp", "AHP advisor"], ["scan", "Scan a project"]] as const)
    .filter(([k]) => !scoringOnly || k === "scores" || k === "ahp");

  return (
    <MotionConfig reducedMotion="user">
      <div className="relative z-10 mx-auto flex min-h-[100dvh] max-w-[1600px] flex-col">
        {scoringOnly
          ? <header className="px-6 pb-2 pt-5"><h1 className="text-lg font-semibold text-ink">Software Supply Chain Guardian</h1><p className="text-sm text-muted">Risk scoring &amp; AHP advisor</p></header>
          : <TopBar meta={meta} state={state} mode={mode} setMode={setMode} onStart={() => start(mode, mode === "live" ? "real" : "canned")} />}
        {!scoringOnly && (error || meta?.error) && (
          <div className="mx-6 mb-2 rounded-lg border border-crit/30 bg-crit/8 px-4 py-2 text-sm text-crit">{error ?? meta?.error}</div>
        )}
        <nav className="mx-6 mb-3 flex gap-1 border-b border-line text-sm" aria-label="Views">
          {tabs.map(([k, label]) => (
            <button key={k} onClick={() => setTab(k)} className={`relative px-3 pb-2.5 pt-1 transition-colors ${tab === k ? "text-ink" : "text-muted hover:text-ink"}`}>
              {label}
              {tab === k && <motion.span layoutId="tab-line" className="absolute inset-x-2 -bottom-px h-0.5 rounded-full bg-accent" />}
            </button>))}
        </nav>
        {tab === "day1" && <main className="flex flex-1 flex-col gap-4 px-6 pb-6"><Day1Report /></main>}
        {tab === "graph" && <main className="flex flex-1 flex-col gap-4 px-6 pb-6"><DepGraph /></main>}
        {tab === "scores" && <main className="flex flex-1 flex-col gap-4 px-6 pb-6"><RiskScores /></main>}
        {tab === "remediation" && <main className="flex flex-1 flex-col gap-4 px-6 pb-6"><Remediation /></main>}
        {tab === "ahp" && <main className="flex flex-1 flex-col gap-4 px-6 pb-6"><AhpAdvisor /></main>}
        {tab === "scan" && <main className="flex flex-1 flex-col gap-4 px-6 pb-6"><ProjectScan /></main>}
        <main className={`flex flex-1 flex-col gap-4 px-6 pb-6 ${tab !== "investigation" ? "hidden" : ""}`}>
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
