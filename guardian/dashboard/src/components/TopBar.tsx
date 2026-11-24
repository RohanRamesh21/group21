import { motion } from "motion/react";
import { MagnifyingGlass, Robot, ShieldCheck } from "@phosphor-icons/react";
import type { Meta } from "../api";
import type { Route } from "../route";

const NAV = [
  { page: "scan", label: "Scan", Icon: MagnifyingGlass },
  { page: "investigate", label: "Investigate", Icon: Robot },
] as const;

/** Logo, the two pages, and whether live agents are available on this server. */
export function TopBar({ route, go, meta }: { route: Route; go: (r: Route) => void; meta: Meta | null }) {
  const active = route.page === "investigate" ? "investigate" : "scan";
  return (
    <header className="sticky top-0 z-20 border-b border-line/60 bg-canvas/75 backdrop-blur-xl">
      <div className="mx-auto flex h-16 max-w-[1600px] items-center gap-4 px-4 md:gap-8 md:px-6">
        <button onClick={() => go({ page: "home" })} className="flex items-center gap-3 text-left" aria-label="Home">
          <motion.div whileHover={{ rotate: -8, scale: 1.05 }} transition={{ type: "spring", stiffness: 400, damping: 15 }}
            className="grid size-9 place-items-center rounded-lg bg-accent/15 ring-1 ring-inset ring-accent/30">
            <ShieldCheck size={20} weight="duotone" className="text-accent" />
          </motion.div>
          <div className="hidden leading-tight sm:block">
            <div className="text-[15px] font-semibold tracking-tight">Supply Chain Guardian</div>
            <div className="text-xs text-muted">Know what you build, trust what you ship</div>
          </div>
        </button>

        <nav className="flex rounded-xl border border-line bg-surface/70 p-1 text-[13.5px]" aria-label="Pages">
          {NAV.map(({ page, label, Icon }) => (
            <button key={page} onClick={() => go(page === "scan" ? { page: "home" } : { page: "investigate", id: route.page === "scan" ? route.id : null })}
              aria-current={active === page ? "page" : undefined}
              className={`relative flex items-center gap-2 rounded-lg px-3.5 py-1.5 transition-colors ${active === page ? "text-ink" : "text-muted hover:text-ink"}`}>
              {active === page && <motion.span layoutId="nav-pill" transition={{ type: "spring", stiffness: 420, damping: 34 }} className="absolute inset-0 -z-0 rounded-lg bg-raised ring-1 ring-inset ring-line" />}
              <Icon size={15} weight={active === page ? "fill" : "regular"} className={`relative ${active === page ? "text-accent" : ""}`} />
              <span className="relative">{label}</span>
            </button>
          ))}
        </nav>

        <div className="ml-auto flex items-center gap-2 text-[11.5px] text-muted">
          {meta && (
            <span className="hidden items-center gap-1.5 rounded-md border border-line px-2 py-1 md:inline-flex" title={meta.live_available ? `LLM provider: ${meta.provider}` : "No LLM key: only the recorded example can run"}>
              <span className={`size-1.5 rounded-full ${meta.live_available ? "bg-ok" : "bg-faint"}`} />
              {meta.live_available ? `agents: ${meta.provider}` : "agents: recorded only"}
            </span>
          )}
        </div>
      </div>
    </header>
  );
}
