import { AnimatePresence, motion } from "motion/react";
import { useEffect, useState } from "react";
import { ArrowRight, ChartBar, FileZip, FolderOpen, GithubLogo, Graph, Robot, SquaresFour, Terminal, Wrench } from "@phosphor-icons/react";
import { apiProject, getJSON, q, type Context, type Job } from "../api";
import type { Route, View } from "../route";
import { VerdictChip, ease } from "../ui";
import { DepGraph } from "./DepGraph";
import { Remediation } from "./Remediation";
import { ResultsOverview } from "./ResultsOverview";
import { RiskScores } from "./RiskScores";

const TABS: { key: View; label: string; Icon: typeof Graph }[] = [
  { key: "overview", label: "Overview", Icon: SquaresFour },
  { key: "graph", label: "Dependency graph", Icon: Graph },
  { key: "scores", label: "Risk scores", Icon: ChartBar },
  { key: "fix", label: "Fix & validate", Icon: Wrench },
];

export function useContext(id: string | null) {
  const [ctx, setCtx] = useState<Context | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    setCtx(null); setErr(null);
    if (!id) return;
    getJSON<Context>(`/api/context${q(id)}`).then(setCtx).catch((e) => setErr(String(e.message ?? e)));
  }, [id]);
  return { ctx, err };
}

/** Everything Guardian found for one scan, in four views. */
export function ProjectResults({ id, job, view, go }: { id: string; job: Job | null; view: View; go: (r: Route) => void }) {
  const { ctx, err } = useContext(id);
  const project = apiProject(id);
  const SrcIcon = id === "main" ? Terminal : job?.kind === "git" ? GithubLogo : job?.kind === "zip" ? FileZip : FolderOpen;
  const source = id === "main" ? "guardian check (command line)" : job?.kind === "git" ? job.url : job?.kind === "path" ? job.path : job?.label;
  const setView = (v: View) => go({ page: "scan", id, view: v });

  return (
    <div className="flex flex-col gap-4">
      <motion.header initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, ease }}
        className="panel flex flex-wrap items-center gap-x-6 gap-y-3 px-5 py-4">
        <div className="flex min-w-0 flex-1 items-center gap-3.5">
          <span className="grid size-11 shrink-0 place-items-center rounded-xl bg-accent/12 text-accent ring-1 ring-inset ring-accent/25"><SrcIcon size={22} weight="duotone" /></span>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2.5">
              <h1 className="truncate text-xl font-semibold tracking-tight">{ctx?.app ?? job?.label ?? "…"}</h1>
              <VerdictChip verdict={ctx?.verdict} />
            </div>
            <div className="mt-0.5 flex flex-wrap items-center gap-x-2 font-mono text-[11.5px] text-muted">
              <span className="truncate">{source}</span>
              {ctx && <span className="text-faint">·</span>}
              {ctx && (ctx.compare ? <span>{ctx.base} <span className="text-faint">({ctx.base_commit.slice(0, 8)})</span> → {ctx.head} <span className="text-faint">({ctx.head_commit.slice(0, 8)})</span></span>
                : <span>{ctx.head_commit.slice(0, 8)} · full scan</span>)}
            </div>
          </div>
        </div>
        <motion.button whileTap={{ scale: 0.97 }} onClick={() => go({ page: "investigate", id })}
          className="group inline-flex items-center gap-2 rounded-lg border border-accent/40 bg-accent/10 px-3.5 py-2 text-[13px] font-medium text-accent transition-colors hover:bg-accent/20">
          <Robot size={16} weight="duotone" /> Investigate with agents <ArrowRight size={13} className="transition-transform group-hover:translate-x-0.5" />
        </motion.button>
      </motion.header>

      <nav className="flex gap-1 overflow-x-auto border-b border-line text-[13.5px]" aria-label="Report views">
        {TABS.map(({ key, label, Icon }) => (
          <button key={key} onClick={() => setView(key)} aria-current={view === key ? "page" : undefined}
            className={`relative flex items-center gap-2 whitespace-nowrap px-3.5 pb-3 pt-1.5 transition-colors ${view === key ? "text-ink" : "text-muted hover:text-ink"}`}>
            <Icon size={15} weight={view === key ? "fill" : "regular"} className={view === key ? "text-accent" : ""} />{label}
            {view === key && <motion.span layoutId="results-tab" transition={{ type: "spring", stiffness: 420, damping: 34 }} className="absolute inset-x-2 -bottom-px h-0.5 rounded-full bg-accent" />}
          </button>
        ))}
      </nav>

      {err && <div className="panel px-5 py-4 text-sm text-crit">{err}</div>}
      <AnimatePresence mode="wait">
        <motion.div key={view} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0, transition: { duration: 0.35, ease } }} exit={{ opacity: 0, y: -6, transition: { duration: 0.15 } }}>
          {view === "overview" && <ResultsOverview id={id} ctx={ctx} onView={setView} />}
          {view === "graph" && <DepGraph project={project} />}
          {view === "scores" && <RiskScores project={project} fullScan={ctx ? !ctx.compare : false} />}
          {view === "fix" && <Remediation project={project} />}
        </motion.div>
      </AnimatePresence>
    </div>
  );
}
