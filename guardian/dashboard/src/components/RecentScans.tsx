import { AnimatePresence, motion } from "motion/react";
import { useEffect, useState } from "react";
import { CircleNotch, FileZip, FolderOpen, GithubLogo, Terminal, WarningCircle } from "@phosphor-icons/react";
import { ago, getJSON, type Context, type Job } from "../api";
import { VerdictChip, ease } from "../ui";

export interface ScanEntry { id: string; label: string; kind: Job["kind"] | "cli"; status: Job["status"]; created: number; verdict?: string;
  packages?: number; mode?: string; detail: string; error?: string }

/** Finished and running scans, newest first; the latest `guardian check` from the command line is listed as "main". */
export function useScans(poll = true) {
  const [jobs, setJobs] = useState<Job[] | null>(null);
  const [cli, setCli] = useState<Context | null>(null);
  const [tick, setTick] = useState(0);
  useEffect(() => {
    getJSON<Job[]>("/api/projects").then(setJobs).catch(() => setJobs([]));
  }, [tick]);
  useEffect(() => { getJSON<Context>("/api/context").then(setCli).catch(() => setCli(null)); }, []);
  const busy = (jobs ?? []).some((j) => j.status === "running" || j.status === "queued");
  useEffect(() => {
    if (!poll) return;
    const t = setInterval(() => setTick((n) => n + 1), busy ? 1500 : 8000);
    return () => clearInterval(t);
  }, [busy, poll]);
  const entries: ScanEntry[] = (jobs ?? []).map((j) => ({
    id: j.id, label: j.label.replace(/^(github\.com|gitlab\.com|bitbucket\.org)\//, ""), kind: j.kind, status: j.status, created: j.created,
    verdict: j.summary?.verdict, packages: j.summary?.packages, mode: j.mode, error: j.status === "error" ? j.message : undefined,
    detail: j.kind === "git" ? (j.base || j.head ? `${j.base ?? "previous"} → ${j.head ?? "latest"}` : "latest commit") : j.kind === "zip" ? "ZIP upload" : j.path ?? "local folder",
  }));
  if (cli) entries.push({ id: "main", label: cli.app, kind: "cli", status: "done", created: cli.scanned_at, verdict: cli.verdict, packages: cli.packages,
    mode: cli.compare ? "compare" : "single", detail: cli.compare ? `${cli.base_commit.slice(0, 8)} → ${cli.head_commit.slice(0, 8)} · guardian check` : "guardian scan" });
  entries.sort((a, b) => b.created - a.created);
  return { entries, loading: jobs === null, refresh: () => setTick((n) => n + 1) };
}

const ICON = { git: GithubLogo, zip: FileZip, path: FolderOpen, cli: Terminal };

export function RecentScans({ entries, onOpen, limit = 9, selected, dense = false }: {
  entries: ScanEntry[]; onOpen: (id: string) => void; limit?: number; selected?: string | null; dense?: boolean;
}) {
  const [all, setAll] = useState(false);
  const shown = all ? entries : entries.slice(0, limit);
  if (!entries.length) return null;
  return (
    <div className="flex flex-col gap-3">
      <motion.ul initial="initial" animate="animate" variants={{ animate: { transition: { staggerChildren: 0.035 } } }}
        className={`grid gap-2.5 ${dense ? "grid-cols-1" : "sm:grid-cols-2 xl:grid-cols-3"}`}>
        <AnimatePresence initial={false}>
          {shown.map((e) => {
            const Icon = ICON[e.kind];
            const running = e.status === "running" || e.status === "queued";
            return (
              <motion.li key={e.id} layout className="min-w-0" variants={{ initial: { opacity: 0, y: 10 }, animate: { opacity: 1, y: 0, transition: { duration: 0.4, ease } } }}
                exit={{ opacity: 0, scale: 0.96 }}>
                <motion.button onClick={() => onOpen(e.id)} whileHover={{ y: -2 }} whileTap={{ scale: 0.985 }} transition={{ type: "spring", stiffness: 400, damping: 26 }}
                  className={`group flex w-full items-center gap-3 rounded-xl border px-3.5 py-3 text-left transition-colors ${selected === e.id ? "border-accent/60 bg-accent/8" : "border-line bg-surface/70 hover:border-white/15 hover:bg-raised"}`}>
                  <span className={`grid size-9 shrink-0 place-items-center rounded-lg ${e.kind === "cli" ? "bg-white/5 text-muted" : "bg-accent/10 text-accent"}`}><Icon size={17} weight="duotone" /></span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-mono text-[12.5px] text-ink">{e.label}</span>
                    <span className="block truncate text-[11.5px] text-muted">{e.detail}</span>
                  </span>
                  <span className="flex shrink-0 flex-col items-end gap-1">
                    {running ? <span className="flex items-center gap-1.5 text-[11.5px] text-accent"><CircleNotch size={13} className="animate-spin" />scanning</span>
                      : e.status === "error" ? <span className="flex items-center gap-1 text-[11.5px] text-crit" title={e.error}><WarningCircle size={13} />failed</span>
                        : <VerdictChip verdict={e.verdict} className="!text-[10.5px]" />}
                    <span className="text-[10.5px] text-faint">{e.packages != null ? `${e.packages.toLocaleString()} components · ` : ""}{ago(e.created)}</span>
                  </span>
                </motion.button>
              </motion.li>
            );
          })}
        </AnimatePresence>
      </motion.ul>
      {entries.length > limit && (
        <button onClick={() => setAll((a) => !a)} className="self-start text-[12.5px] text-muted hover:text-ink">{all ? "Show fewer" : `Show all ${entries.length} scans`}</button>
      )}
    </div>
  );
}
