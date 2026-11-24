import { AnimatePresence, motion } from "motion/react";
import { useEffect, useMemo, useState } from "react";
import { Bug, Check, CloudArrowDown, Fingerprint, GitDiff, Gavel, Minus, Package, TreeStructure, FlowArrow, X } from "@phosphor-icons/react";
import type { Job } from "../api";
import { VerdictChip, ease } from "../ui";

/** The pipeline stages, in the order the backend reports them (guardian/projects.py STAGES). */
export const STAGES = [
  { key: "fetch", label: "Fetch", what: "Fetch the source safely", Icon: CloudArrowDown },
  { key: "inventory", label: "Inventory", what: "Find manifests, lockfiles and build files", Icon: Package },
  { key: "sbom", label: "SBOM & graph", what: "Build the SBOM and the dependency graph", Icon: TreeStructure },
  { key: "ci", label: "CI & images", what: "Check CI workflows and container images", Icon: FlowArrow },
  { key: "vulns", label: "Vulnerabilities", what: "Look up known vulnerabilities (OSV.dev + Grype)", Icon: Bug },
  { key: "compare", label: "Compare", what: "Scan the base version and label what changed", Icon: GitDiff },
  { key: "registry", label: "Provenance", what: "Registry signatures, provenance and publishers", Icon: Fingerprint },
  { key: "policy", label: "Verdict", what: "Policy-as-code and the final verdict", Icon: Gavel },
] as const;

type State = "pending" | "active" | "done" | "skipped" | "error";

export function stageStates(job: Job): State[] {
  const cur = STAGES.findIndex((s) => s.key === job.stage);
  const seen = new Set(job.steps.map((s) => s.stage));
  return STAGES.map((s, i) => {
    if (s.key === "compare" && job.mode === "single") return "skipped";
    if (job.status === "done") return seen.has(s.key) ? "done" : "skipped";
    if (i < cur) return seen.has(s.key) ? "done" : "skipped";
    if (i === cur || (cur < 0 && i === 0)) return job.status === "error" ? "error" : "active";
    return "pending";
  });
}

function useElapsed(job: Job) {
  const [now, setNow] = useState(() => Date.now() / 1000);
  const live = job.status === "running" || job.status === "queued";
  useEffect(() => {
    if (!live) return;
    const t = setInterval(() => setNow(Date.now() / 1000), 100);
    return () => clearInterval(t);
  }, [live]);
  return Math.max(0, (live ? now : job.updated ?? now) - job.created);
}

function Node({ state, Icon, i }: { state: State; Icon: (typeof STAGES)[number]["Icon"]; i: number }) {
  const ring = state === "active" ? "ring-accent/70 bg-accent/15 text-accent" : state === "done" ? "ring-ok/50 bg-ok/12 text-ok"
    : state === "error" ? "ring-crit/60 bg-crit/12 text-crit" : "ring-line bg-raised text-faint";
  return (
    <motion.div initial={{ scale: 0.4, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} transition={{ type: "spring", stiffness: 380, damping: 22, delay: i * 0.05 }}
      className="relative size-11 rounded-full bg-surface">
      <div className={`absolute inset-0 rounded-full ring-1 ring-inset transition-colors duration-500 ${ring}`} />
      {state === "active" && (<>
        <span className="ping-soft absolute inset-0 rounded-full bg-accent/30" />
        <svg className="absolute -inset-1 size-[52px] animate-spin [animation-duration:1.4s]" viewBox="0 0 52 52" aria-hidden>
          <circle cx="26" cy="26" r="24" fill="none" stroke="#4d8dff" strokeWidth="2" strokeLinecap="round" strokeDasharray="38 120" />
        </svg>
      </>)}
      <AnimatePresence initial={false}>
        <motion.span key={state} initial={{ scale: 0.3, rotate: -30, opacity: 0 }} animate={{ scale: 1, rotate: 0, opacity: 1 }} exit={{ scale: 0.3, opacity: 0, transition: { duration: 0.15 } }}
          transition={{ type: "spring", stiffness: 500, damping: 22 }} className="absolute inset-0 grid place-items-center">
          {state === "done" ? <Check size={18} weight="bold" /> : state === "error" ? <X size={18} weight="bold" /> : state === "skipped" ? <Minus size={18} /> : <Icon size={19} weight="duotone" />}
        </motion.span>
      </AnimatePresence>
    </motion.div>
  );
}

/** Live view of one scan: the stage rail fills as the pipeline advances and the log streams underneath. */
export function ScanProgress({ job, compact = false }: { job: Job; compact?: boolean }) {
  const states = useMemo(() => stageStates(job), [job]);
  const elapsed = useElapsed(job);
  const doneCount = states.filter((s) => s === "done" || s === "skipped").length;
  const active = STAGES[states.findIndex((s) => s === "active" || s === "error")] ?? null;
  const pct = job.status === "done" ? 1 : doneCount / STAGES.length;
  const log = job.steps.slice(compact ? -4 : -7);
  const title = job.status === "done" ? "Scan complete" : job.status === "error" ? "Scan failed" : job.status === "queued" ? "Queued" : "Scanning";

  return (
    <div className="panel relative overflow-hidden">
      {job.status === "running" || job.status === "queued" ? (
        <div className="absolute inset-x-0 top-0 h-px overflow-hidden"><div className="scanbar h-px w-1/3 bg-gradient-to-r from-transparent via-accent to-transparent" /></div>
      ) : null}
      <div className={`flex flex-wrap items-center gap-x-4 gap-y-2 ${compact ? "px-5 pt-4" : "px-6 pt-6"}`}>
        <div className="min-w-0 flex-1">
          <AnimatePresence mode="wait">
            <motion.div key={title} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }} transition={{ duration: 0.25 }}
              className={`font-semibold tracking-tight ${compact ? "text-lg" : "text-2xl"} ${job.status === "error" ? "text-crit" : ""}`}>
              {title} <span className="font-mono text-muted">{job.label}</span>
            </motion.div>
          </AnimatePresence>
          <div className="mt-1 text-[12.5px] text-muted">
            {job.kind === "git" ? "Git repository" : job.kind === "zip" ? "ZIP upload" : job.git ? "Local Git repository" : "Local folder"}
            {job.mode && <> · {job.mode === "compare" ? `comparing ${job.base ?? "previous commit"} → ${job.head ?? "latest"}` : "full scan"}</>}
          </div>
        </div>
        {job.status === "done" && <VerdictChip verdict={job.summary?.verdict} className="text-[13px]" />}
        <div className="text-right font-mono">
          <div className={`${compact ? "text-lg" : "text-2xl"} tabular-nums`}>{elapsed.toFixed(1)}s</div>
          <div className="text-[11px] text-faint">{Math.round(pct * 100)}% of stages</div>
        </div>
      </div>

      {/* stage rail */}
      <div className={`relative ${compact ? "px-5 py-5" : "px-6 py-8"}`}>
        <div className="relative grid grid-cols-8 items-start">
          <div className="absolute left-[6.25%] right-[6.25%] top-[22px] h-0.5 rounded-full bg-white/6" />
          <motion.div className="absolute left-[6.25%] top-[22px] h-0.5 rounded-full bg-gradient-to-r from-ok via-ok to-accent"
            initial={{ width: 0 }} animate={{ width: `${Math.max(0, Math.min(1, (doneCount - (job.status === "done" ? 1 : 0)) / (STAGES.length - 1))) * 87.5}%` }}
            transition={{ duration: 0.7, ease }} />
          {STAGES.map((s, i) => (
            <div key={s.key} className="relative flex flex-col items-center gap-2 text-center">
              <Node state={states[i]} Icon={s.Icon} i={i} />
              {!compact && <div className={`text-[11.5px] leading-tight transition-colors duration-500 ${states[i] === "active" ? "text-ink" : states[i] === "done" ? "text-ink/80" : "text-faint"}`}>
                {s.label}{states[i] === "skipped" && <div className="text-[10px] text-faint">not needed</div>}
              </div>}
            </div>
          ))}
        </div>
      </div>

      {/* what is happening now + streaming log */}
      <div className={`grid gap-4 border-t border-line ${compact ? "px-5 py-3" : "px-6 py-5 lg:grid-cols-[minmax(0,0.8fr)_minmax(0,1.4fr)]"}`}>
        {!compact && (
          <AnimatePresence mode="wait">
            <motion.div key={active?.key ?? job.status} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 10 }} transition={{ duration: 0.25 }}>
              <div className="text-[11px] uppercase tracking-wider text-faint">{job.status === "done" ? "Result" : job.status === "error" ? "Stopped at" : "Now"}</div>
              {job.status === "done" ? (
                <div className="mt-1 text-[13.5px] text-ink/90">{job.summary?.packages.toLocaleString()} components · {(job.summary?.reasons ?? [])[0] ?? "no reasons recorded"}</div>
              ) : (
                <div className="mt-1 text-[15px] font-medium">{active?.what ?? "Waiting for the scanner"}</div>
              )}
              {job.status === "error" && <div className="mt-2 text-[12.5px] text-crit">{job.message}</div>}
              {job.status !== "error" && job.status !== "done" && <div className="mt-2 text-[12px] text-muted">Every scanner runs in a no-network, read-only sandbox. Nothing from the project is installed or run.</div>}
            </motion.div>
          </AnimatePresence>
        )}
        <div className="rounded-lg bg-canvas/70 px-3.5 py-2.5 font-mono text-[11.5px] ring-1 ring-inset ring-line">
          <ol className="flex flex-col gap-1">
            <AnimatePresence initial={false}>
              {log.map((s, i) => {
                const n = job.steps.length - log.length + i;
                const last = i === log.length - 1;
                return (
                  <motion.li key={n} layout="position" initial={{ opacity: 0, y: 8 }} animate={{ opacity: last ? 1 : 0.55, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.3 }}
                    className="flex gap-3">
                    <span className="w-12 shrink-0 text-right text-faint tabular-nums">{s.t.toFixed(1)}s</span>
                    <span className={`min-w-0 ${last ? "text-ink" : "text-muted"} ${compact ? "truncate" : ""}`}>{s.msg}</span>
                  </motion.li>
                );
              })}
            </AnimatePresence>
            {!log.length && <li className="text-faint">waiting for the first step…</li>}
          </ol>
        </div>
      </div>
    </div>
  );
}
