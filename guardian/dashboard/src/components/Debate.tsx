import { AnimatePresence, motion } from "motion/react";
import { useMemo } from "react";
import type { FeedAudit, FeedItem, FeedMessage, RunState } from "../types";
import { agentOf, shortPurl, spring } from "../ui";

const DEBATE = new Set(["hypothesis", "challenge", "answer", "corroborate", "clear", "dispute"]);
const OUTCOME: Record<string, string> = { corroborate: "Confirmed", clear: "Cleared", dispute: "Disputed" };

export function Debate({ feed, state }: { feed: FeedItem[]; state: RunState | null }) {
  const threads = useMemo(() => {
    const by = new Map<string, FeedMessage[]>();
    for (const f of feed) if (f.type === "message" && DEBATE.has(f.kind) && f.finding_id) by.set(f.finding_id, [...(by.get(f.finding_id) ?? []), f]);
    return [...by.entries()].filter(([, ms]) => ms.some((m) => m.sender === "skeptic"));
  }, [feed]);
  const rules = feed.filter((f) => f.type === "audit" && ["rejected", "floor_intervention", "denied_tool"].includes(f.event)) as FeedAudit[];
  const missed = feed.filter((f) => f.type === "message" && f.kind === "missed_risk") as FeedMessage[];

  return (
    <section className="panel flex min-h-0 flex-col p-4">
      <div className="mb-3 flex items-center justify-between text-sm">
        <span className="font-medium">Skeptic review</span>
        <span className="text-xs text-muted">{rules.length} constitution interventions</span>
      </div>
      <div className="scroll-thin flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto">
        {!threads.length && !missed.length && <p className="text-sm text-muted">Every hypothesis is challenged here before it can reach the verdict.</p>}
        <AnimatePresence initial={false}>
          {threads.map(([fid, ms]) => {
            const f = state?.findings?.[fid];
            const end = [...ms].reverse().find((m) => OUTCOME[m.kind]);
            return (
              <motion.div key={fid} layout initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={spring}
                className="rounded-lg border border-line bg-raised/50 p-3">
                <div className="mb-2 flex items-center justify-between gap-2 text-[12px]">
                  <span className="truncate text-muted">{f ? `${f.type.replace("_", " ")} | ${f.component.startsWith("E-") ? "README" : shortPurl(f.component)}` : fid}</span>
                  {end && <span className={`rounded px-1.5 py-px text-[11px] ${end.kind === "clear" ? "bg-ok/12 text-ok" : end.kind === "dispute" ? "bg-med/12 text-med" : "bg-crit/12 text-crit"}`}>{OUTCOME[end.kind]}</span>}
                </div>
                <ol className="relative flex flex-col gap-2 border-l border-line pl-3">
                  {ms.map((m) => { const a = agentOf(m.sender); return (
                    <motion.li key={m.seq} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} className="relative text-[12px] leading-snug">
                      <span className="absolute -left-[17px] top-1 size-2 rounded-full ring-2 ring-surface" style={{ background: a.hex }} />
                      <span className="font-medium" style={{ color: a.hex }}>{a.name.split(" ").slice(-1)[0]}</span>
                      <span className="text-faint"> {m.kind}: </span>
                      <span className="text-ink/85">{m.claim}</span>
                    </motion.li>); })}
                </ol>
              </motion.div>
            );
          })}
          {missed.map((m) => (
            <motion.div key={m.seq} initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
              className="rounded-lg border border-high/30 bg-high/8 p-3 text-[12px]">
              <span className="font-medium text-high">Skeptic found a gap: </span><span className="text-ink/85">{m.claim}</span>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>
    </section>
  );
}
