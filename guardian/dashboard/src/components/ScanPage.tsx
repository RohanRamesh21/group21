import { AnimatePresence, motion } from "motion/react";
import { useEffect, useRef, useState } from "react";
import { ArrowLeft } from "@phosphor-icons/react";
import { getJSON, type Job } from "../api";
import type { Route, View } from "../route";
import { pageMotion } from "../ui";
import { ProjectResults } from "./ProjectResults";
import { ScanProgress } from "./ScanProgress";

/** Poll one scan job until it finishes. id "main" (the CLI report) has no job. */
export function useJob(id: string | null) {
  const [job, setJob] = useState<Job | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    setJob(null); setErr(null);
    if (!id || id === "main") return;
    let stop = false;
    let timer: ReturnType<typeof setTimeout>;
    const tick = () => getJSON<Job>(`/api/projects/${encodeURIComponent(id)}`)
      .then((j) => { if (stop) return; setJob(j); if (j.status === "running" || j.status === "queued") timer = setTimeout(tick, 700); })
      .catch((e) => !stop && setErr(String(e.message ?? e)));
    tick();
    return () => { stop = true; clearTimeout(timer); };
  }, [id]);
  return { job, err };
}

/** One scan: live pipeline while it runs, then the results. Watching a scan finish holds the completed pipeline briefly
 *  before the results slide in, so the last stages are seen to complete. */
export function ScanPage({ id, view, go }: { id: string; view: View; go: (r: Route) => void }) {
  const { job, err } = useJob(id);
  const sawRunning = useRef(false);
  const [reveal, setReveal] = useState(id === "main");
  useEffect(() => { sawRunning.current = false; setReveal(id === "main"); }, [id]);
  useEffect(() => {
    if (!job) return;
    if (job.status !== "done") { sawRunning.current = true; return; }
    if (!sawRunning.current) { setReveal(true); return; }
    const t = setTimeout(() => setReveal(true), 1400);
    return () => clearTimeout(t);
  }, [job?.status, job]);

  const phase = err ? "error" : reveal ? "results" : job ? "progress" : "loading";
  return (
    <div className="flex flex-col gap-4 pb-12">
      <button onClick={() => go({ page: "home" })} className="flex items-center gap-1.5 self-start text-[12.5px] text-muted transition-colors hover:text-ink">
        <ArrowLeft size={14} /> New scan
      </button>
      <AnimatePresence mode="wait">
        {phase === "error" && <motion.div key="err" {...pageMotion} className="panel px-5 py-4 text-sm text-crit">Could not load this scan: {err}</motion.div>}
        {phase === "loading" && <motion.div key="load" {...pageMotion} className="panel h-64 animate-pulse" />}
        {phase === "progress" && job && (
          <motion.div key="progress" {...pageMotion} className="flex flex-col gap-4">
            <ScanProgress job={job} />
            {job.status === "error" && (
              <button onClick={() => go({ page: "home" })} className="self-start rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white hover:brightness-110">Try another source</button>
            )}
          </motion.div>
        )}
        {phase === "results" && (
          <motion.div key="results" {...pageMotion}>
            <ProjectResults id={id} job={job} view={view} go={go} />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
