import { AnimatePresence, animate, motion, useMotionValue, useTransform } from "motion/react";
import { useEffect } from "react";
import { CheckCircle, Prohibit, ShieldCheck } from "@phosphor-icons/react";
import type { Meta, RunState } from "../types";
import { RISK, spring } from "../ui";

function CountUp({ value }: { value: number }) {
  const mv = useMotionValue(0);
  const text = useTransform(mv, (v) => Math.round(v).toLocaleString());
  useEffect(() => { const c = animate(mv, value, { duration: 1.1, ease: [0.16, 1, 0.3, 1] }); return () => c.stop(); }, [value, mv]);
  return <motion.span>{text}</motion.span>;
}

function Stat({ label, value, sub, tone }: { label: string; value: number; sub?: string; tone?: string }) {
  return (
    <div className="flex flex-col gap-1 px-5 py-4">
      <span className="text-xs text-muted">{label}</span>
      <span className={`font-mono text-3xl font-medium tracking-tight ${tone ?? "text-ink"}`}><CountUp value={value} /></span>
      {sub && <span className="text-[11px] text-faint">{sub}</span>}
    </div>
  );
}

function CoverageRing({ done, total }: { done: number; total: number }) {
  const pct = total ? done / total : 0;
  const C = 2 * Math.PI * 26;
  return (
    <div className="flex items-center gap-3 px-5 py-4">
      <svg width="64" height="64" viewBox="0 0 64 64" className="-rotate-90">
        <circle cx="32" cy="32" r="26" fill="none" stroke="rgb(255 255 255 / 0.08)" strokeWidth="6" />
        <motion.circle cx="32" cy="32" r="26" fill="none" stroke={pct === 1 ? RISK.low.hex : "#4d8dff"} strokeWidth="6"
          strokeLinecap="round" strokeDasharray={C} initial={{ strokeDashoffset: C }}
          animate={{ strokeDashoffset: C * (1 - pct) }} transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }} />
      </svg>
      <div className="flex flex-col">
        <span className="text-xs text-muted">Coverage (C3)</span>
        <span className="font-mono text-xl">{done}/{total}</span>
        <span className="text-[11px] text-faint">changed surfaces examined</span>
      </div>
    </div>
  );
}

export function Overview({ meta, state }: { meta: Meta | null; state: RunState | null }) {
  const findings = Object.values(state?.findings ?? {});
  const open = findings.filter((f) => f.status !== "cleared");
  const crit = open.filter((f) => f.risk === "critical").length;
  const v = state?.verdict;
  const phase = !state ? "idle" : v ? v.decision : state.status === "error" ? "error" : "running";

  return (
    <section className="grid grid-cols-1 gap-4 xl:grid-cols-[1.15fr_2fr]">
      <motion.div layout className={`panel overflow-hidden p-6 ${phase === "block" ? "glow-crit" : ""}`}>
        <AnimatePresence mode="wait">
          <motion.div key={phase} initial={{ opacity: 0, y: 12, filter: "blur(4px)" }} animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
            exit={{ opacity: 0, y: -10, filter: "blur(4px)" }} transition={spring} className="flex h-full flex-col gap-3">
            {phase === "idle" && (<>
              <div className="flex items-center gap-2 text-muted"><ShieldCheck size={18} /> Pre-merge check</div>
              <div className="text-3xl font-semibold tracking-tight">Ready to inspect this pull request</div>
              <p className="max-w-[52ch] text-sm leading-relaxed text-muted">Four agents examine what changed, prove every claim with evidence, and recommend block or merge. A human owns the final call.</p>
            </>)}
            {phase === "running" && (<>
              <div className="flex items-center gap-2 text-accent"><span className="relative flex size-2"><span className="ping-soft absolute inset-0 rounded-full bg-accent" /><span className="relative size-2 rounded-full bg-accent" /></span> Investigating</div>
              <div className="text-3xl font-semibold tracking-tight">Agents are gathering evidence</div>
              <div className="relative mt-2 h-1 overflow-hidden rounded-full bg-white/5"><div className="scanbar absolute inset-y-0 w-1/3 rounded-full bg-gradient-to-r from-transparent via-accent to-transparent" /></div>
              <p className="text-sm text-muted">{(state?.plan ?? []).slice(-1)[0] ?? "Lead is planning the investigation"}</p>
            </>)}
            {phase === "block" && (<>
              <div className="flex items-center gap-2 text-crit"><Prohibit size={18} weight="bold" /> Recommendation</div>
              <div className="text-4xl font-semibold tracking-tight text-crit">Block this merge</div>
              <p className="max-w-[60ch] text-sm leading-relaxed text-ink/80">{v?.rationale}</p>
            </>)}
            {phase === "safe_to_merge" && (<>
              <div className="flex items-center gap-2 text-ok"><CheckCircle size={18} weight="bold" /> Recommendation</div>
              <div className="text-4xl font-semibold tracking-tight text-ok">Safe to merge</div>
              <p className="max-w-[60ch] text-sm leading-relaxed text-ink/80">{v?.rationale}</p>
            </>)}
            {phase === "inconclusive" && (<>
              <div className="text-3xl font-semibold tracking-tight">Review required</div>
              <p className="max-w-[60ch] text-sm leading-relaxed text-muted">{v?.rationale}</p>
            </>)}
            {phase === "error" && (<>
              <div className="text-sm text-crit">Run failed</div>
              <p className="font-mono text-xs text-muted">{state?.error}</p>
            </>)}
          </motion.div>
        </AnimatePresence>
      </motion.div>

      <div className="panel grid grid-cols-2 divide-line md:grid-cols-5 md:divide-x">
        <Stat label="Components" value={meta?.components ?? 0} sub={`${meta?.lockfile_entries ?? 0} lockfile entries`} />
        <Stat label="Changed in PR" value={meta?.changed_packages ?? 0} sub="packages added or updated" />
        <Stat label="Install scripts" value={meta?.install_scripts ?? 0} sub="run code at npm install" />
        <Stat label="Open risks" value={open.length} sub={`${crit} critical`} tone={crit ? "text-crit" : "text-ink"} />
        <CoverageRing done={state?.coverage?.done.length ?? 0} total={state?.coverage?.required.length ?? 0} />
      </div>
    </section>
  );
}
