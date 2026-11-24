import { AnimatePresence, motion } from "motion/react";
import { useEffect, useMemo, useState } from "react";
import { MagnifyingGlass, X } from "@phosphor-icons/react";
import { RiskTag, spring } from "../ui";
import { Badge, SectionHead, st, type Finding, type Sections } from "./shared";

type Filter = "introduced" | "pre_existing" | "all";

function Stages({ stages }: { stages: { id: string; name?: string; status: string; detail?: string }[] }) {
  return (
    <ol className="panel scroll-thin flex overflow-x-auto p-2" aria-label="Scan stages">
      {stages.map((x, i) => {
        const S = st(x.status);
        return (
          <motion.li key={x.id} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ ...spring, delay: i * 0.04 }}
            className="flex min-w-[130px] flex-1 items-start gap-2 px-3 py-2" title={x.detail}>
            <S.Icon size={16} weight="fill" className={`mt-0.5 shrink-0 ${S.cls}`} />
            <span className="min-w-0"><span className="block text-[12px] font-medium">{x.name ?? x.id}</span>
              <span className="line-clamp-1 block text-[10.5px] text-faint">{x.detail ?? S.label}</span></span>
          </motion.li>);
      })}
    </ol>);
}

function ProofDrawer({ f, onClose }: { f: Finding | null; onClose: () => void }) {
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);
  return (
    <AnimatePresence>
      {f && (<>
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose} className="fixed inset-0 z-30 bg-black/40 backdrop-blur-[2px]" />
        <motion.aside role="dialog" aria-label="Proof for this finding" initial={{ x: 480 }} animate={{ x: 0 }} exit={{ x: 480 }} transition={spring}
          className="panel scroll-thin fixed inset-y-3 right-3 z-40 w-[min(480px,94vw)] overflow-y-auto p-5">
          <button onClick={onClose} aria-label="Close" className="float-right rounded p-1 text-muted hover:bg-raised hover:text-ink"><X /></button>
          <RiskTag risk={f.level} />
          <h3 className="mt-2 font-mono text-[14px] leading-snug">{f.title}</h3>
          <p className="mt-1 text-[12px] text-muted">{f.label.replace("_", " ")} · decision {f.decision} · priority {f.score}{f.floor ? ` · floor: ${f.floor}` : ""}</p>
          <h4 className="mt-5 flex items-center gap-2 text-[12px] font-semibold"><Badge kind="fact" /> Evidence recorded by the scan</h4>
          <dl className="mt-2 grid grid-cols-[120px_minmax(0,1fr)] gap-x-3 gap-y-1 text-[12px]">
            {Object.entries(f.evidence ?? {}).filter(([, v]) => v !== null && v !== "" && !(Array.isArray(v) && !v.length)).map(([k, v]) => (
              <div key={k} className="contents"><dt className="text-faint">{k}</dt><dd className="break-words font-mono text-[11.5px]">{typeof v === "object" ? JSON.stringify(v) : String(v)}</dd></div>))}
          </dl>
          {!!f.contributions?.length && (<>
            <h4 className="mt-5 text-[12px] font-semibold">How the priority was computed</h4>
            <ul className="mt-2 space-y-1.5 text-[12px]">
              {f.contributions.map((c, i) => (
                <li key={c.factor} className="grid grid-cols-[90px_1fr_36px] items-center gap-2 tabular-nums">
                  <span className="text-faint">{c.factor}</span>
                  <span className="h-1.5 overflow-hidden rounded-full bg-raised"><motion.span className="block h-full bg-accent" initial={{ width: 0 }} animate={{ width: `${Math.min(100, c.points * 2.5)}%` }} transition={{ ...spring, delay: i * 0.05 }} /></span>
                  <span className="text-right">{c.points}</span>
                  <span className="col-span-3 -mt-1 text-[11px] text-muted">{c.why}</span>
                </li>))}
            </ul></>)}
          {f.confidence && (<>
            <h4 className="mt-5 text-[12px] font-semibold">Confidence in the evidence: {f.confidence.band}</h4>
            <ul className="mt-1 space-y-1 text-[12px]">
              {Object.entries(f.confidence.dimensions).map(([k, d]) => (
                <li key={k} className="flex gap-2"><span className={`w-24 shrink-0 ${st(d.status === "ok" ? "complete" : d.status === "weak" ? "partial" : d.status === "missing" ? "failed" : "not_applicable").cls}`}>{k}</span><span className="text-muted">{d.why}</span></li>))}
            </ul></>)}
        </motion.aside></>)}
    </AnimatePresence>);
}

export function Detect({ s }: { s: Sections }) {
  const items: Finding[] = useMemo(() => s.findings?.items ?? [], [s]);
  const [filter, setFilter] = useState<Filter>("introduced");
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState<Finding | null>(null);
  const counts = { introduced: items.filter((f) => f.label === "introduced").length, pre_existing: items.filter((f) => f.label !== "introduced").length, all: items.length };
  const shown = items.filter((f) => (filter === "all" || (filter === "introduced" ? f.label === "introduced" : f.label !== "introduced"))
    && (!query || f.title.toLowerCase().includes(query.toLowerCase()))).slice(0, 300);
  return (
    <div className="flex flex-col gap-4">
      <SectionHead n={2} title="Detect and prioritise" sub="Vulnerability databases (OSV + Grype) and 14 supply-chain detectors check every component. Rules score each finding (floors → SSVC → priority) and decide the merge. No AI is involved here." />
      <Stages stages={s.run.stages ?? []} />
      <section className="panel flex flex-col p-3">
        <div className="flex flex-wrap items-center gap-2 px-1 pb-2">
          <div className="relative flex rounded-lg bg-canvas p-0.5 text-[12px] ring-1 ring-line">
            {([["introduced", "Introduced by this PR"], ["pre_existing", "Already there"], ["all", "All"]] as [Filter, string][]).map(([k, label]) => (
              <button key={k} onClick={() => setFilter(k)} className={`relative z-10 rounded-md px-3 py-1.5 transition-colors ${filter === k ? "text-ink" : "text-muted hover:text-ink"}`}>
                {filter === k && <motion.span layoutId="det-filter" transition={spring} className="absolute inset-0 -z-10 rounded-md bg-raised ring-1 ring-inset ring-white/8" />}
                {label} <span className="font-mono text-faint">{counts[k]}</span>
              </button>))}
          </div>
          <label className="ml-auto flex items-center gap-1.5 rounded-lg bg-canvas px-2 py-1.5 text-[12px] ring-1 ring-line">
            <MagnifyingGlass className="text-muted" /><span className="sr-only">Filter findings</span>
            <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter by package or advisory" className="w-56 bg-transparent placeholder:text-faint focus:outline-none" />
          </label>
        </div>
        <div className="grid grid-cols-[88px_minmax(0,1fr)_110px_70px_120px_80px] gap-3 border-b border-line px-3 pb-2 text-[11px] text-faint">
          <span>Level</span><span>Finding</span><span>Kind</span><span>Decision</span><span>Priority</span><span>Evidence</span>
        </div>
        <div className="scroll-thin max-h-[560px] overflow-y-auto">
          <AnimatePresence initial={false} mode="popLayout">
            {shown.map((f, i) => (
              <motion.button key={f.id} layout initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ ...spring, delay: Math.min(i, 14) * 0.02 }}
                onClick={() => setOpen(f)} className="grid w-full grid-cols-[88px_minmax(0,1fr)_110px_70px_120px_80px] items-center gap-3 rounded-lg px-3 py-2 text-left text-[12.5px] transition-colors hover:bg-raised focus-visible:outline focus-visible:outline-accent">
                <RiskTag risk={f.level} />
                <span className="truncate font-mono">{f.title}</span>
                <span className="truncate text-[11.5px] text-muted">{f.kind}</span>
                <span className="text-[11.5px]">{f.decision}</span>
                <span className="flex items-center gap-2 tabular-nums"><span className="h-1.5 w-16 overflow-hidden rounded-full bg-raised"><span className="block h-full rounded-full bg-accent" style={{ width: `${f.score}%` }} /></span>{f.score}</span>
                <span className={`w-fit rounded px-1.5 py-0.5 text-[10.5px] ${f.confidence?.band === "high" ? "bg-ok/10 text-ok" : f.confidence?.band === "medium" ? "bg-med/12 text-med" : "bg-crit/12 text-crit"}`}>{f.confidence?.band ?? "?"}</span>
              </motion.button>))}
          </AnimatePresence>
          {shown.length === 0 && <p className="px-3 py-8 text-center text-[12.5px] text-muted">{filter === "introduced" ? "This change introduced nothing risky." : "No findings match."}</p>}
        </div>
      </section>
      <ProofDrawer f={open} onClose={() => setOpen(null)} />
    </div>);
}
