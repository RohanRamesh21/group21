import { motion } from "motion/react";
import { Broadcast, ClockCounterClockwise, Play, ShieldCheck } from "@phosphor-icons/react";
import type { Meta, RunState } from "../types";

type Mode = "replay" | "live";

export function TopBar({ meta, state, mode, setMode, onStart }: {
  meta: Meta | null; state: RunState | null; mode: Mode; setMode: (m: Mode) => void; onStart: () => void;
}) {
  const running = state?.status === "running" || state?.status === "starting";
  const liveReady = meta?.provider && meta.provider !== "replay";
  return (
    <header className="flex h-16 items-center gap-6 px-6">
      <div className="flex items-center gap-3">
        <div className="grid size-9 place-items-center rounded-lg bg-accent/15 ring-1 ring-inset ring-accent/30">
          <ShieldCheck size={20} weight="duotone" className="text-accent" />
        </div>
        <div className="leading-tight">
          <div className="text-[15px] font-semibold tracking-tight">Supply Chain Guardian</div>
          <div className="text-xs text-muted">Know what you build, trust what you ship</div>
        </div>
      </div>

      <div className="hidden items-center gap-2 rounded-lg border border-line bg-surface/70 px-3 py-1.5 font-mono text-xs text-muted lg:flex">
        <span className="text-ink">{meta?.repo ?? "uptime-kuma"}</span>
        <span className="text-faint">PR</span>
        <span>{meta?.base ?? "base"}</span>
        <span className="text-faint">into</span>
        <span className="text-ink">{meta?.head ?? "head"}</span>
      </div>

      <div className="ml-auto flex items-center gap-3">
        {meta?.model && (
          <span className="hidden rounded-md border border-line px-2 py-1 font-mono text-[11px] text-muted xl:inline">
            {meta.model.replace("anthropic/", "")}{meta.effort ? ` | ${meta.effort} effort` : ""}
          </span>
        )}
        {state && (
          <span className="font-mono text-xs text-muted">
            {state.run_id} <span className="text-faint">|</span> {state.elapsed.toFixed(0)}s
          </span>
        )}
        <div className="relative flex rounded-lg border border-line bg-surface p-0.5 text-xs">
          {(["replay", "live"] as Mode[]).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              disabled={running || (m === "live" && !liveReady)}
              title={m === "live" && !liveReady ? "No working LLM key in guardian/.env" : undefined}
              className="relative z-10 flex items-center gap-1.5 whitespace-nowrap rounded-md px-3 py-1.5 text-muted transition-colors enabled:hover:text-ink disabled:opacity-40 data-[on=true]:text-ink"
              data-on={mode === m}
            >
              {mode === m && <motion.span layoutId="mode-pill" className="absolute inset-0 -z-10 rounded-md bg-raised ring-1 ring-inset ring-line" />}
              {m === "replay" ? <ClockCounterClockwise size={14} /> : <Broadcast size={14} />}
              {m === "replay" ? "Replay" : "Live agents"}
            </button>
          ))}
        </div>
        <button
          onClick={onStart}
          disabled={running}
          className="flex shrink-0 items-center gap-2 whitespace-nowrap rounded-lg bg-accent px-4 py-2 text-sm font-medium text-white shadow-[inset_0_1px_0_rgb(255_255_255/0.25)] transition active:scale-[0.98] enabled:hover:brightness-110 disabled:opacity-50"
        >
          <Play size={14} weight="fill" />
          {running ? "Investigating" : "Run check"}
        </button>
      </div>
    </header>
  );
}
