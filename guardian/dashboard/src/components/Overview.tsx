import { AnimatePresence, motion } from "motion/react";
import { CheckCircle, Prohibit, ShieldCheck } from "@phosphor-icons/react";
import type { Context } from "../api";
import type { RunState } from "../types";
import { agentOf, CountUp, RISK, spring } from "../ui";

function Stat({ label, value, sub, tone }: { label: string; value: number | null; sub?: string; tone?: string }) {
  return (
    <div className="flex flex-col gap-1 px-5 py-4">
      <span className="text-xs text-muted">{label}</span>
      <span className={`font-mono text-3xl font-medium tracking-tight ${tone ?? "text-ink"}`}>{value == null ? <span className="text-faint">–</span> : <CountUp value={value} />}</span>
      {sub && <span className="text-[11px] text-faint">{sub}</span>}
    </div>
  );
}

function CoverageRing({ done, total, focused }: { done: number; total: number; focused: boolean }) {
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
        <span className="text-xs text-muted">{focused ? "Evidence coverage" : "Agent coverage"}</span>
        <span className="font-mono text-xl">{done}/{total}</span>
        <span className="text-[11px] text-faint">required items complete</span>
      </div>
    </div>
  );
}

/** Headline of an agent run. Numbers come from the scan being investigated (none for the recorded example). */
export function Overview({ ctx, state, recorded, onEvidence }: { ctx: Context | null; state: RunState | null; recorded: boolean; onEvidence: (id: string) => void }) {
  const scan = recorded ? null : ctx;
  const findings = Object.values(state?.findings ?? {});
  const open = findings.filter((f) => f.status !== "cleared");
  const crit = open.filter((f) => f.risk === "critical").length;
  const v = state?.verdict;
  const required = state?.coverage?.required ?? [];
  const done = new Set(state?.coverage?.done ?? []);
  const gaps = required.filter((item) => !done.has(item));
  const packageGaps = gaps.filter((item) => item.startsWith("pkg:"));
  const focused = !!state?.focused;
  const questions = Object.entries(state?.review_questions ?? {});
  const reviewed = questions.filter(([id]) => done.has(id)).length;
  const scanEvidence = state?.scan_evidence ?? {};
  const reused = Object.entries(scanEvidence).filter(([id]) => id.startsWith("pkg:"));
  const phase = !state ? "idle" : v ? v.decision : state.status === "error" ? "error" : "running";

  return (
    <section className="grid grid-cols-1 gap-4 xl:grid-cols-[1.15fr_2fr]">
      <motion.div layout className={`panel overflow-hidden p-6 ${phase === "block" ? "glow-crit" : ""}`}>
        <AnimatePresence mode="wait">
          <motion.div key={phase} initial={{ opacity: 0, y: 12, filter: "blur(4px)" }} animate={{ opacity: 1, y: 0, filter: "blur(0px)" }}
            exit={{ opacity: 0, y: -10, filter: "blur(4px)" }} transition={spring} className="flex h-full flex-col gap-3">
            {phase === "idle" && (<>
              <div className="flex items-center gap-2 text-muted"><ShieldCheck size={18} /> Agent investigation</div>
              <div className="text-3xl font-semibold tracking-tight">{ctx ? <>Ready to investigate <span className="font-mono text-accent">{ctx.app}</span></> : "Pick a scan to investigate"}</div>
              <p className="max-w-[52ch] text-sm leading-relaxed text-muted">Start the investigation to review findings from this scan.</p>
            </>)}
            {phase === "running" && (<>
              <div className="flex items-center gap-2 text-accent"><span className="relative flex size-2"><span className="ping-soft absolute inset-0 rounded-full bg-accent" /><span className="relative size-2 rounded-full bg-accent" /></span> Investigating</div>
              <div className="text-3xl font-semibold tracking-tight">{focused ? "Reviewing material findings" : "Agents are gathering evidence"}</div>
              <div className="relative mt-2 h-1 overflow-hidden rounded-full bg-white/5"><div className="scanbar absolute inset-y-0 w-1/3 rounded-full bg-gradient-to-r from-transparent via-accent to-transparent" /></div>
              <p className="text-sm text-muted">{(state?.plan ?? []).at(-1) ?? (focused ? "Checking scan evidence and reviewing questions" : "Lead is planning the investigation")}</p>
            </>)}
            {phase === "block" && (<>
              <div className="flex items-center gap-2 text-crit"><Prohibit size={18} weight="bold" /> Recommendation</div>
              <div className="text-4xl font-semibold tracking-tight text-crit">Block this merge</div>
              <p className="max-w-[60ch] text-sm leading-relaxed text-ink/80">{v?.rationale}</p>
            </>)}
            {phase === "safe_to_merge" && (<>
              <div className="flex items-center gap-2 text-ok"><CheckCircle size={18} weight="bold" /> Recommendation</div>
              <div className="text-4xl font-semibold tracking-tight text-ok">{scan && !scan.compare ? "Snapshot review complete" : "Safe to merge"}</div>
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
        <Stat label="Components" value={scan ? scan.inventory.packages : null} sub={scan ? `${scan.inventory.direct} direct` : recorded ? "recorded example" : "from the scan"} />
        <Stat label="Changed packages" value={scan?.compare ? scan.changes.added + scan.changes.updated : null}
          sub={scan?.compare ? `${scan.changes.files} files changed` : scan ? "single snapshot" : undefined} />
        <Stat label="Install scripts" value={scan ? scan.inventory.install_scripts : null} sub="run code at install time" />
        <Stat label="Open findings" value={open.length} sub={`${crit} critical`} tone={crit ? "text-crit" : "text-ink"} />
        <CoverageRing done={done.size} total={required.length} focused={focused} />
      </div>
      {focused && (
        <section aria-labelledby="review-queue" className="panel overflow-hidden xl:col-span-2">
          <header className="flex flex-wrap items-start justify-between gap-3 border-b border-line px-5 py-4">
            <div><h2 id="review-queue" className="text-sm font-medium">Focused review</h2>
              <p className="mt-1 text-[12px] text-muted">{reviewed} of {questions.length} questions corroborated by Skeptic</p></div>
            <div className="flex flex-wrap gap-2 text-[12px]">
              <span className="rounded-lg bg-accent/10 px-3 py-1.5 text-accent">{reused.length} exact-version OSV checks reused</span>
              {packageGaps.length > 0 && <span className="rounded-lg bg-high/10 px-3 py-1.5 text-high">{packageGaps.length} OSV checks outstanding</span>}
            </div>
          </header>
          {questions.length ? (
            <ul className="scroll-thin max-h-[26rem] divide-y divide-line overflow-auto">
              {questions.map(([id, item]) => (
                <li key={id} className="flex flex-wrap items-start justify-between gap-2 px-5 py-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[13px]">
                      <span className="font-medium">{item.title.replaceAll("_", " ")}</span>
                      <span className="break-all font-mono text-[11px] text-muted">{item.component}</span>
                    </div>
                    <p className="mt-1 text-[12px] text-muted">{item.reason}</p>
                    <p className="mt-1 text-[11px] text-faint">{agentOf(item.role).name} · {item.severity}
                      {item.observations > 1 ? \` · \${item.observations} related findings\` : ""}
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-3 text-[11px]">
                    <span className={done.has(id) ? "text-ok" : "text-high"}>{done.has(id) ? "Corroborated" : "Pending"}</span>
                    <button onClick={() => onEvidence(item.evidence_id)} className="rounded border border-line px-2 py-1 text-accent hover:bg-raised">Evidence</button>
                  </div>
                </li>
              ))}
            </ul>
          ) : <p className="px-5 py-4 text-[12px] text-muted">{state?.status === "done" ? "No material findings entered the review queue." : "Guardian is preparing the review queue."}</p>}
          <details className="border-t border-line px-5 py-3 text-[12px]">
            <summary className="cursor-pointer text-muted">Scan evidence used in this investigation</summary>
            <ul className="scroll-thin mt-2 grid max-h-56 gap-1 overflow-auto sm:grid-cols-2 lg:grid-cols-3">
              {Object.entries(scanEvidence).map(([key, eid]) => <li key={key}>
                <button onClick={() => onEvidence(eid)} className="break-all text-left text-accent hover:underline">
                  {key === "scan:summary" ? "Scan summary" : key.slice(4)}
                </button>
              </li>)}
            </ul>
          </details>
        </section>
      )}
      {state && required.length > 0 && (!focused || packageGaps.length > 0) && (
        <details className="panel px-5 py-3 text-[12.5px] xl:col-span-2">
          <summary className="cursor-pointer font-medium">
            {focused ? "Evidence coverage" : "Agent coverage"} · {gaps.length ? `${gaps.length} outstanding` : "all required evidence reviewed"}
            {packageGaps.length ? ` · ${packageGaps.length} exact-version advisory lookups outstanding` : ""}
          </summary>
          <p className="mt-2 text-muted">Coverage tracks evidence required for this investigation. Component totals come from the saved scan.</p>
          {gaps.length > 0 && <ul className="mt-2 grid max-h-40 gap-1 overflow-auto font-mono text-[11px] text-muted sm:grid-cols-2 lg:grid-cols-3">
            {gaps.map((item) => <li key={item} className="break-all">{item.startsWith("pkg:") ? item.slice(4) : item}</li>)}
          </ul>}
        </details>
      )}
    </section>
  );
}
