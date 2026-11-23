import { AnimatePresence, motion } from "motion/react";
import { useMemo } from "react";
import { ArrowRight, Gavel, Prohibit, User, Warning } from "@phosphor-icons/react";
import type { FeedAudit, FeedItem, FeedMessage } from "../types";
import { RiskTag, agentOf, spring } from "../ui";

const LANES = ["lead", "hunter", "forensics", "skeptic"] as const;
// These tool calls are shown by the message, verdict or human row they produce.
const HIDDEN_TOOLS = new Set(["post_message", "submit_verdict", "ask_human"]);

const KIND_TONE: Record<string, string> = {
  hypothesis: "text-accent bg-accent/10", challenge: "text-high bg-high/10", answer: "text-ink bg-white/5",
  corroborate: "text-crit bg-crit/10", clear: "text-ok bg-ok/10", dispute: "text-med bg-med/10",
  missed_risk: "text-high bg-high/10", task_result: "text-ink bg-white/5", handoff: "text-ink bg-white/5",
};

export function AgentLanes({ feed, onEvidence }: { feed: FeedItem[]; onEvidence: (id: string) => void }) {
  const lanes = useMemo(() => {
    const now = feed.length ? feed[feed.length - 1].ts : 0;
    return LANES.map((a) => {
      const mine = feed.filter((f) => (f.type === "message" ? f.sender : f.agent) === a);
      const last = mine[mine.length - 1];
      const tools = mine.filter((f) => f.type === "audit" && f.event === "tool_call") as FeedAudit[];
      const lastTool = tools[tools.length - 1];
      return { a, active: !!last && now - last.ts < 1.8, tools: tools.length,
        msgs: mine.filter((f) => f.type === "message").length, lastTool: lastTool?.tool };
    });
  }, [feed]);

  const items = useMemo(() => feed.filter((f) => !(f.type === "audit" && (f.event === "run_start" || (f.event === "tool_call" && HIDDEN_TOOLS.has(String(f.tool)))))).slice(-60).reverse(), [feed]);

  return (
    <section className="panel flex min-h-0 flex-col">
      <div className="grid grid-cols-2 gap-2 border-b border-line p-3 md:grid-cols-4">
        {lanes.map(({ a, active, tools, msgs, lastTool }) => {
          const ag = agentOf(a);
          return (
            <motion.div key={a} animate={{ borderColor: active ? `${ag.hex}66` : "rgba(255,255,255,0.07)" }}
              className="relative flex items-center gap-3 rounded-lg border bg-raised/60 p-3">
              <div className="relative grid size-9 shrink-0 place-items-center rounded-lg" style={{ background: `${ag.hex}1f` }}>
                {active && <span className="ping-soft absolute inset-0 rounded-lg" style={{ background: `${ag.hex}55` }} />}
                <ag.Icon size={18} weight="duotone" style={{ color: ag.hex }} />
              </div>
              <div className="min-w-0">
                <div className="truncate text-[13px] font-medium">{ag.name}</div>
                <div className="truncate font-mono text-[11px] text-muted">
                  {active && lastTool ? lastTool : `${tools} tools | ${msgs} msgs`}
                </div>
              </div>
            </motion.div>
          );
        })}
      </div>

      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto p-3">
        {!items.length && <Empty />}
        <ul className="flex flex-col gap-1.5">
          <AnimatePresence initial={false}>
            {items.map((f) => (
              <motion.li key={f.seq} layout="position" initial={{ opacity: 0, x: -16, scale: 0.98 }} animate={{ opacity: 1, x: 0, scale: 1 }}
                exit={{ opacity: 0 }} transition={spring}>
                {f.type === "message" ? <MessageRow m={f} onEvidence={onEvidence} /> : <AuditRow e={f} onEvidence={onEvidence} />}
              </motion.li>
            ))}
          </AnimatePresence>
        </ul>
      </div>
    </section>
  );
}

function Empty() {
  return (
    <div className="grid h-full min-h-48 place-items-center text-center text-sm text-muted">
      <div className="flex flex-col items-center gap-2">
        <div className="flex -space-x-2">{LANES.map((a) => { const g = agentOf(a); return (
          <span key={a} className="grid size-8 place-items-center rounded-full ring-2 ring-surface" style={{ background: `${g.hex}26` }}><g.Icon size={15} style={{ color: g.hex }} /></span>); })}
        </div>
        Press Run check to watch the agents work
      </div>
    </div>
  );
}

export function EvidenceChips({ ids, onEvidence }: { ids: string[]; onEvidence: (id: string) => void }) {
  if (!ids?.length) return null;
  return (
    <span className="flex flex-wrap gap-1">
      {ids.map((id) => (
        <button key={id} onClick={() => onEvidence(id)}
          className="rounded border border-line bg-canvas/60 px-1.5 py-px font-mono text-[10.5px] text-muted transition hover:border-accent/50 hover:text-accent">
          {id}
        </button>
      ))}
    </span>
  );
}

function MessageRow({ m, onEvidence }: { m: FeedMessage; onEvidence: (id: string) => void }) {
  const s = agentOf(m.sender), r = agentOf(m.recipient);
  return (
    <div className="rounded-lg border border-line bg-raised/50 p-3">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <s.Icon size={14} weight="duotone" style={{ color: s.hex }} />
        <span className="font-medium" style={{ color: s.hex }}>{s.name}</span>
        <ArrowRight size={11} className="text-faint" />
        <span className="text-muted">{m.recipient === "board" ? "Board" : r.name}</span>
        <span className={`rounded px-1.5 py-px font-mono text-[10.5px] ${KIND_TONE[m.kind] ?? "bg-white/5 text-muted"}`}>{m.kind.replace("_", " ")}</span>
        {m.proposed_risk && <RiskTag risk={m.proposed_risk} />}
        {m.kind_of_claim && <span className="text-[10.5px] text-faint">{m.kind_of_claim}{m.confidence != null ? ` ${Math.round(m.confidence * 100)}%` : ""}</span>}
      </div>
      {m.claim && <p className="mt-1.5 text-[13px] leading-relaxed text-ink/90">{m.claim}</p>}
      <div className="mt-2"><EvidenceChips ids={m.evidence_ids} onEvidence={onEvidence} /></div>
    </div>
  );
}

function AuditRow({ e, onEvidence }: { e: FeedAudit; onEvidence: (id: string) => void }) {
  const ag = agentOf(e.agent);
  if (e.event === "tool_call") {
    const args = Object.entries(e.args ?? {}).map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`).join(", ");
    return (
      <div className="flex items-center gap-2 px-2 py-1 font-mono text-[11.5px] text-muted">
        <span className="size-1.5 shrink-0 rounded-full" style={{ background: ag.hex }} />
        <span className="shrink-0" style={{ color: ag.hex }}>{e.agent}</span>
        <span className="text-ink/80">{e.tool}</span>
        <span className="truncate text-faint">({args.slice(0, 110)})</span>
      </div>
    );
  }
  if (e.event === "rejected" || e.event === "denied_tool") {
    return (
      <motion.div initial={{ x: 0 }} animate={{ x: [0, -6, 6, -4, 4, 0] }} transition={{ duration: 0.45 }}
        className="flex items-start gap-2 rounded-lg border border-crit/30 bg-crit/8 px-3 py-2 text-[12.5px]">
        <Prohibit size={15} className="mt-0.5 shrink-0 text-crit" weight="bold" />
        <div><span className="font-medium text-crit">Constitution rejected {String(e.kind ?? e.tool)} from {ag.name}.</span>{" "}
          <span className="text-ink/80">{String(e.reason ?? "tool not on allow-list (C6)")}</span></div>
      </motion.div>
    );
  }
  if (e.event === "floor_intervention") {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-high/30 bg-high/8 px-3 py-2 text-[12.5px]">
        <Warning size={15} className="text-high" weight="bold" />
        <span><span className="font-medium text-high">Risk floor enforced (C2).</span> Case {String(e.case)} proposed{" "}
          <b>{String(e.proposed)}</b>, raised to <b>{String(e.floor)}</b> because a hard signal is present.</span>
      </div>
    );
  }
  if (e.event === "dispatch") {
    const to = agentOf(String(e.assignee));
    return (
      <div className="flex items-center gap-2 px-2 py-1 text-[12px] text-muted">
        <span className="text-accent">Lead</span> assigned <span className="font-mono">{String(e.task)}</span> to
        <span style={{ color: to.hex }}>{to.name}</span>
        <span className="truncate font-mono text-[11px] text-faint">{(e.scope as string[] | undefined)?.join(", ")}</span>
      </div>
    );
  }
  if (e.event === "human_request" || e.event === "ask_human") {
    return (
      <div className="flex items-start gap-2 rounded-lg border border-line bg-white/[0.03] px-3 py-2 text-[12.5px]">
        <User size={15} className="mt-0.5 text-ink" />
        <div className="flex flex-col gap-1">
          <span><span className="font-medium">{e.event === "human_request" ? "Lead asks a human:" : "Human answered:"}</span>{" "}
            <span className="text-ink/80">{String(e.event === "human_request" ? e.question : e.answer)}</span></span>
          {e.event === "ask_human" && <EvidenceChips ids={[String(e.evidence)]} onEvidence={onEvidence} />}
        </div>
      </div>
    );
  }
  if (e.event === "verdict") {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-crit/40 bg-crit/10 px-3 py-2 text-[13px]">
        <Gavel size={16} className="text-crit" weight="bold" />
        <span className="font-medium">Verdict submitted: {String(e.decision).replace(/_/g, " ")}</span>
      </div>
    );
  }
  return <div className="px-2 py-1 font-mono text-[11px] text-faint">{e.event}</div>;
}
