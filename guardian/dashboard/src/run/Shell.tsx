import { motion } from "motion/react";
import { FileArrowDown, FolderSimplePlus, Prohibit, SealCheck, ShieldCheck, Warning } from "@phosphor-icons/react";
import { spring } from "../ui";
import { q, st, type Sections, type Step, type StepId } from "./shared";

type Job = { id: string; label: string };

export function Verdict({ verdict, complete, size = "md" }: { verdict?: string | null; complete?: boolean; size?: "md" | "xl" }) {
  const v = (verdict ?? "none").toLowerCase();
  const tone = v === "block" ? "bg-crit/14 text-crit ring-crit/35" : v === "review" ? "bg-high/14 text-high ring-high/35" : v === "allow" ? "bg-ok/14 text-ok ring-ok/35" : "bg-info/12 text-info ring-info/30";
  const big = size === "xl";
  return (
    <motion.span key={v} initial={{ rotateX: 90, opacity: 0 }} animate={{ rotateX: 0, opacity: 1 }} transition={spring}
      className={`inline-flex items-center gap-2 rounded-xl font-mono font-semibold tracking-tight ring-1 ring-inset ${tone} ${big ? "px-5 py-3 text-[34px]" : "px-3 py-1.5 text-[14px]"}`}>
      {v === "block" ? <Prohibit weight="bold" /> : v === "allow" ? <SealCheck weight="bold" /> : <Warning weight="bold" />}
      {v.toUpperCase()}
      {complete === false && <span className="rounded bg-crit/20 px-1.5 text-[11px] tracking-normal">incomplete</span>}
    </motion.span>);
}

export function Header({ s, project, setProject, jobs, view, setView }: {
  s?: Sections; project: string | null; setProject: (p: string | null) => void; jobs: Job[];
  view: string; setView: (v: "scan" | "replay") => void;
}) {
  return (
    <header className="flex flex-wrap items-center gap-x-6 gap-y-3 px-6 pt-5">
      <div className="flex items-center gap-3">
        <div className="grid size-9 place-items-center rounded-lg bg-accent/15 ring-1 ring-inset ring-accent/30"><ShieldCheck size={20} weight="duotone" className="text-accent" /></div>
        <div className="leading-tight">
          <div className="text-[15px] font-semibold tracking-tight">Supply Chain Guardian</div>
          <div className="text-[11.5px] text-muted">Know what you build. Trust what you ship.</div>
        </div>
      </div>
      <label className="flex items-center gap-2 rounded-lg bg-surface px-2.5 py-1.5 text-[12px] text-muted ring-1 ring-line">
        <span className="sr-only">Run</span>
        <select value={project ?? ""} onChange={(e) => setProject(e.target.value || null)} className="max-w-[260px] bg-transparent text-[12.5px] text-ink outline-none">
          <option value="">Uptime Kuma · scenario PR</option>
          {jobs.map((j) => <option key={j.id} value={j.id}>{j.label} · {j.id}</option>)}
        </select>
      </label>
      {s && <span className="hidden font-mono text-[11.5px] text-faint lg:inline">{s.run.base_sha?.slice(0, 8) ?? "—"} → {s.run.head_sha?.slice(0, 8)}</span>}
      <div className="ml-auto flex items-center gap-2">
        {s && <Verdict verdict={s.run.verdict} complete={s.run.complete} />}
        <button onClick={() => setView("scan")} data-on={view === "scan"} className="inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-[12px] text-muted ring-1 ring-line transition hover:text-ink data-[on=true]:bg-raised data-[on=true]:text-ink"><FolderSimplePlus /> Scan a project</button>
        <button onClick={() => setView("replay")} data-on={view === "replay"} className="rounded-lg px-2.5 py-1.5 text-[12px] text-faint transition hover:text-ink data-[on=true]:bg-raised data-[on=true]:text-ink" title="An earlier recorded agent run, clearly labelled">Recorded demo</button>
        {s && <a href={`/api/report${q(project)}${project ? "&" : "?"}fmt=html`} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 rounded-lg px-2.5 py-1.5 text-[12px] text-muted ring-1 ring-line transition hover:text-ink"><FileArrowDown /> Report</a>}
      </div>
    </header>);
}

/** Journey navigation: the product's own steps, each with its real status. */
export function Journey({ steps, active, onPick }: { steps: Step[]; active: string; onPick: (id: StepId) => void }) {
  return (
    <nav aria-label="Run steps" className="scroll-thin mx-6 mt-4 overflow-x-auto">
      <ol className="flex min-w-max items-stretch gap-1 rounded-xl bg-surface/70 p-1 ring-1 ring-line">
        {steps.map((x, i) => {
          const S = st(x.status), on = active === x.id;
          return (
            <li key={x.id} className="flex items-center">
              <button onClick={() => onPick(x.id)} aria-current={on ? "step" : undefined}
                className={`relative flex min-w-[132px] flex-col items-start rounded-lg px-3 py-2 text-left transition-colors ${on ? "text-ink" : "text-muted hover:text-ink"}`}>
                {on && <motion.span layoutId="journey-on" transition={spring} className="absolute inset-0 -z-0 rounded-lg bg-raised ring-1 ring-inset ring-white/8" />}
                <span className="relative flex items-center gap-2 text-[12.5px] font-medium">
                  <span className="font-mono text-[10.5px] text-faint">{x.n === 0 ? "◎" : x.n}</span>{x.name}
                  <span className="relative ml-0.5 size-1.5">
                    {x.status === "waiting" && <span className={`ping-soft absolute inset-0 rounded-full ${S.dot}`} />}
                    <span className={`absolute inset-0 rounded-full ${S.dot}`} />
                  </span>
                </span>
                <span className="relative text-[10.5px] text-faint">{x.hint} · <span className={S.cls}>{x.status === "complete" ? x.detail || S.label : S.label}</span></span>
              </button>
              {i < steps.length - 1 && <span aria-hidden className="mx-0.5 h-px w-3 bg-line" />}
            </li>);
        })}
      </ol>
    </nav>);
}
