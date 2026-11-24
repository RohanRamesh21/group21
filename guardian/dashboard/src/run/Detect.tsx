import { AnimatePresence, motion } from "motion/react";
import { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { MagnifyingGlass, X } from "@phosphor-icons/react";
import { RiskTag, spring } from "../ui";
import { Badge, SectionHead, st, type Finding, type Fix, type Sections } from "./shared";
import { AhpWeights } from "./scoring/AhpWeights";
import { Contextual, Fixes, TIER_SHORT } from "./scoring/Contextual";
import { Method } from "./scoring/Method";

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

function ProofDrawer({ f, fixes, onClose }: { f: Finding | null; fixes?: Fix[]; onClose: () => void }) {
  const drawer = useRef<HTMLElement>(null);
  useEffect(() => {
    if (!f) return;
    const previous = document.activeElement as HTMLElement | null;
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    drawer.current?.focus();
    const k = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
      if (e.key === "Tab") {
        const controls = drawer.current?.querySelectorAll<HTMLElement>('button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex="0"]');
        const first = controls?.[0], last = controls?.[controls.length - 1];
        if (!first) { e.preventDefault(); return; }
        if (e.shiftKey && (document.activeElement === first || document.activeElement === drawer.current)) { e.preventDefault(); last?.focus(); }
        else if (!e.shiftKey && (document.activeElement === last || document.activeElement === drawer.current)) { e.preventDefault(); first.focus(); }
      }
    };
    window.addEventListener("keydown", k);
    return () => { window.removeEventListener("keydown", k); document.body.style.overflow = overflow; previous?.focus(); };
  }, [f, onClose]);
  // Portal: each section is inside an animated (transformed) container, which would make `fixed` relative to it.
  return createPortal(
    <AnimatePresence>
      {f && (<>
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose} className="fixed inset-0 z-30 bg-black/40 backdrop-blur-[2px]" />
        <motion.aside ref={drawer} tabIndex={-1} role="dialog" aria-modal="true" aria-label="Proof for this finding" style={{ position: "fixed" }} initial={{ x: 480 }} animate={{ x: 0 }} exit={{ x: 480 }} transition={spring}
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
          {f.ssvc && (<>
            <h4 className="mt-5 text-[12px] font-semibold">SSVC decision path</h4>
            <p className="mt-1 text-[12px] text-muted">exploitation <b className="text-ink">{f.ssvc.exploitation}</b> · automatable <b className="text-ink">{f.ssvc.automatable}</b> · impact <b className="text-ink">{f.ssvc.technical_impact}</b> · importance <b className="text-ink">{f.ssvc.mission}</b> → <b className="text-ink">{f.decision}</b> ({f.ssvc.rule})</p></>)}
          {!!f.counterfactuals?.length && (<>
            <h4 className="mt-5 text-[12px] font-semibold">What would change the decision</h4>
            <ul className="mt-1 space-y-1 text-[12px]">{f.counterfactuals.map((c) => (
              <li key={c.if} className="flex gap-2"><span className="text-accent">If</span><span className="text-muted">{c.if}</span><span className="text-faint">→</span><span>{c.then}</span></li>))}</ul></>)}
          <Contextual f={f} />
          {fixes && fixes.length > 0 && <Fixes fixes={fixes} />}
          {f.confidence?.dimensions && (<>
            <h4 className="mt-5 text-[12px] font-semibold">Data-quality checks{f.confidence.data_checks ? `: ${f.confidence.data_checks.band}` : ""}</h4>
            <ul className="mt-1 space-y-1 text-[12px]">
              {Object.entries(f.confidence.dimensions).map(([k, d]) => (
                <li key={k} className="flex gap-2"><span className={`w-24 shrink-0 ${st(d.status === "ok" ? "complete" : d.status === "weak" ? "partial" : d.status === "missing" ? "failed" : "not_applicable").cls}`}>{k}</span><span className="text-muted">{d.why}</span></li>))}
            </ul></>)}
        </motion.aside></>)}
    </AnimatePresence>, document.body);
}

type View = "findings" | "method" | "ahp";

export function Detect({ s, project, refresh }: { s: Sections; project: string | null; refresh: () => void }) {
  const items: Finding[] = useMemo(() => s.findings?.items ?? [], [s]);
  const fixes: Record<string, Fix[]> = s.findings?.scoring?.fix_candidates ?? {};
  const [view, setView] = useState<View>("findings");
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
      <div className="relative flex w-fit max-w-full flex-wrap rounded-lg bg-surface p-0.5 text-[12.5px] ring-1 ring-line">
        {([["findings", "Findings & priority"], ["method", "How it's scored"], ["ahp", "AHP weights · AI-advised"]] as [View, string][]).map(([k, label]) => (
          <button key={k} onClick={() => setView(k)} className={`relative z-10 rounded-md px-3.5 py-1.5 transition-colors ${view === k ? "text-ink" : "text-muted hover:text-ink"}`}>
            {view === k && <motion.span layoutId="det-view" transition={spring} className="absolute inset-0 -z-10 rounded-md bg-raised ring-1 ring-inset ring-white/8" />}
            {label}
          </button>))}
      </div>
      {view === "method" && <Method s={s} />}
      {view === "ahp" && <AhpWeights project={project} onChanged={refresh} />}
      {view === "findings" && <section className="panel flex flex-col p-3">
        <div className="flex flex-wrap items-center gap-2 px-1 pb-2">
          <div className="relative flex max-w-full flex-wrap rounded-lg bg-canvas p-0.5 text-[12px] ring-1 ring-line">
            {([["introduced", "Introduced by this PR"], ["pre_existing", "Already there"], ["all", "All"]] as [Filter, string][]).map(([k, label]) => (
              <button key={k} onClick={() => setFilter(k)} className={`relative z-10 rounded-md px-3 py-1.5 transition-colors ${filter === k ? "text-ink" : "text-muted hover:text-ink"}`}>
                {filter === k && <motion.span layoutId="det-filter" transition={spring} className="absolute inset-0 -z-10 rounded-md bg-raised ring-1 ring-inset ring-white/8" />}
                {label} <span className="font-mono text-faint">{counts[k]}</span>
              </button>))}
          </div>
          <label className="ml-auto flex w-full items-center gap-1.5 rounded-lg bg-canvas px-2 py-1.5 text-[12px] ring-1 ring-line sm:w-auto">
            <MagnifyingGlass className="text-muted" /><span className="sr-only">Filter findings</span>
            <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Filter by package or advisory" className="w-full min-w-0 bg-transparent placeholder:text-faint focus:outline-none sm:w-56" />
          </label>
        </div>
        <div className="scroll-thin overflow-x-auto" role="region" aria-label="Scored findings" tabIndex={0}>
        <div className="min-w-[960px]">
        <div className="grid grid-cols-[88px_minmax(0,1fr)_96px_62px_112px_84px_74px_70px] gap-3 border-b border-line px-3 pb-2 text-[11px] text-faint">
          <span>Level</span><span>Finding</span><span>Kind</span><span>Decision</span><span>Priority</span><span title="90% range of the rank when every AHP weight varies ±20%">Rank range</span><span title="Estimated from a static import scan">Reachability</span><span>Confidence</span>
        </div>
        <div className="scroll-thin max-h-[560px] overflow-y-auto">
          <AnimatePresence initial={false} mode="popLayout">
            {shown.map((f, i) => (
              <motion.button key={f.id} layout initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ ...spring, delay: Math.min(i, 14) * 0.02 }}
                onClick={() => setOpen(f)} className="grid w-full grid-cols-[88px_minmax(0,1fr)_96px_62px_112px_84px_74px_70px] items-center gap-3 rounded-lg px-3 py-2 text-left text-[12.5px] transition-colors hover:bg-raised focus-visible:outline focus-visible:outline-accent">
                <RiskTag risk={f.level} />
                <span className="truncate font-mono">{f.title}</span>
                <span className="truncate text-[11.5px] text-muted">{f.kind}</span>
                <span className="text-[11.5px]">{f.decision}</span>
                <span className="flex items-center gap-2 tabular-nums"><span className="h-1.5 w-14 overflow-hidden rounded-full bg-raised"><span className="block h-full rounded-full bg-accent" style={{ width: `${f.score}%` }} /></span>{f.score}</span>
                <span className="font-mono text-[11px] tabular-nums text-muted">{f.rank_stability ? <>#{f.rank_stability.baseline_rank} <span className="text-faint">({f.rank_stability.rank_p05}–{f.rank_stability.rank_p95})</span></> : "—"}</span>
                <span className={`text-[11px] ${f.reachability?.tier === "imported" ? "text-ink" : f.reachability?.tier === "declared" ? "text-med" : "text-faint"}`}>{f.reachability ? TIER_SHORT[f.reachability.tier] : "—"}</span>
                <span className={`w-fit rounded px-1.5 py-0.5 text-[10.5px] ${f.confidence?.band === "high" ? "bg-ok/10 text-ok" : f.confidence?.band === "medium" ? "bg-med/12 text-med" : "bg-crit/12 text-crit"}`}>{f.confidence?.band ?? "?"}</span>
              </motion.button>))}
          </AnimatePresence>
          {shown.length === 0 && <p className="px-3 py-8 text-center text-[12.5px] text-muted">{query ? "No findings match your filter." : filter === "introduced" ? "This change introduced nothing risky." : "No findings match."}</p>}
        </div></div></div>
      </section>}
      <ProofDrawer f={open} fixes={open ? fixes[open.id] : undefined} onClose={() => setOpen(null)} />
    </div>);
}
