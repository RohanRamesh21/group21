import type { Risk } from "./types";
import { Crosshair, Detective, Robot, Scales, ShieldStar, User, Wrench } from "@phosphor-icons/react";
import { animate, motion, useMotionValue, useTransform } from "motion/react";
import { useEffect, type ReactNode } from "react";
import { VERDICT_TONE } from "./api";

export const RISK: Record<Risk, { text: string; bg: string; ring: string; label: string; hex: string }> = {
  critical: { text: "text-crit", bg: "bg-crit/12", ring: "ring-crit/40", label: "Critical", hex: "#f0525f" },
  high: { text: "text-high", bg: "bg-high/12", ring: "ring-high/40", label: "High", hex: "#f59e3b" },
  medium: { text: "text-med", bg: "bg-med/12", ring: "ring-med/40", label: "Medium", hex: "#d9b44a" },
  low: { text: "text-ok", bg: "bg-ok/12", ring: "ring-ok/40", label: "Low", hex: "#3ccf91" },
  info: { text: "text-info", bg: "bg-info/12", ring: "ring-info/30", label: "Info", hex: "#7d8494" },
};

export const AGENTS: Record<string, { name: string; role: string; Icon: typeof Robot; hex: string }> = {
  lead: { name: "Lead", role: "Plans, builds cases, decides", Icon: ShieldStar, hex: "#4d8dff" },
  hunter: { name: "Dependency Hunter", role: "Packages, registries, advisories", Icon: Crosshair, hex: "#a78bfa" },
  forensics: { name: "Change Forensics", role: "Diffs, commits, sensitive files", Icon: Detective, hex: "#38bdf8" },
  skeptic: { name: "Skeptic", role: "Challenges every claim", Icon: Scales, hex: "#f472b6" },
  fixer: { name: "Fixer", role: "Day 2 remediation", Icon: Wrench, hex: "#3ccf91" },
  human: { name: "Human reviewer", role: "Owns irreversible decisions", Icon: User, hex: "#e7e9ee" },
  system: { name: "Guardian", role: "Constitution and tools", Icon: Robot, hex: "#8a909c" },
};

export function agentOf(a?: string) { return AGENTS[a ?? "system"] ?? AGENTS.system; }

export function RiskTag({ risk, className = "" }: { risk: Risk; className?: string }) {
  const r = RISK[risk] ?? RISK.info;
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset ${r.bg} ${r.text} ${r.ring} ${className}`}>
      <span className="size-1.5 rounded-full" style={{ background: r.hex }} />
      {r.label}
    </span>
  );
}

export function shortPurl(c: string) {
  return c.replace("pkg:npm/", "").replace("%40", "@");
}

export const spring = { type: "spring" as const, stiffness: 260, damping: 28 };
export const ease = [0.16, 1, 0.3, 1] as const;

/** Page and panel transitions: every view enters and leaves the same way. */
export const pageMotion = {
  initial: { opacity: 0, y: 14, filter: "blur(6px)" },
  animate: { opacity: 1, y: 0, filter: "blur(0px)", transition: { duration: 0.45, ease } },
  exit: { opacity: 0, y: -8, filter: "blur(4px)", transition: { duration: 0.18 } },
};
/** Children of a list appear one after another. */
export const stagger = (step = 0.05, delay = 0) => ({ animate: { transition: { staggerChildren: step, delayChildren: delay } } });
export const rise = {
  initial: { opacity: 0, y: 12 },
  animate: { opacity: 1, y: 0, transition: { duration: 0.5, ease } },
};

export function CountUp({ value, duration = 1.1 }: { value: number; duration?: number }) {
  const mv = useMotionValue(0);
  const text = useTransform(mv, (v) => Math.round(v).toLocaleString());
  useEffect(() => { const c = animate(mv, value, { duration, ease }); return () => c.stop(); }, [value, mv, duration]);
  return <motion.span>{text}</motion.span>;
}

export function VerdictChip({ verdict, className = "" }: { verdict?: string | null; className?: string }) {
  if (!verdict) return null;
  const v = VERDICT_TONE[verdict];
  return (
    <motion.span key={verdict} initial={{ scale: 0.6, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} transition={{ type: "spring", stiffness: 420, damping: 18 }}
      className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-[12px] font-semibold uppercase tracking-wide ring-1 ring-inset ${v?.chip ?? "bg-raised text-muted ring-line"} ${className}`}>
      <span className="size-1.5 rounded-full bg-current" />{v?.label ?? verdict}
    </motion.span>
  );
}

/** Pill-style tab switcher; the highlight slides between options. `id` must be unique on the page. */
export function Segmented<T extends string>({ id, value, options, onChange, size = "md" }: {
  id: string; value: T; options: { value: T; label: ReactNode; disabled?: boolean; title?: string }[]; onChange: (v: T) => void; size?: "sm" | "md";
}) {
  return (
    <div role="tablist" className={`relative inline-flex rounded-lg border border-line bg-canvas/60 p-0.5 ${size === "sm" ? "text-xs" : "text-[13px]"}`}>
      {options.map((o) => (
        <button key={o.value} role="tab" aria-selected={value === o.value} disabled={o.disabled} title={o.title} onClick={() => onChange(o.value)}
          className={`relative z-10 flex items-center gap-1.5 whitespace-nowrap rounded-md transition-colors disabled:opacity-40 ${size === "sm" ? "px-2.5 py-1" : "px-3.5 py-1.5"} ${value === o.value ? "text-ink" : "text-muted enabled:hover:text-ink"}`}>
          {value === o.value && <motion.span layoutId={`seg-${id}`} transition={{ type: "spring", stiffness: 420, damping: 34 }}
            className="absolute inset-0 -z-10 rounded-md bg-raised shadow-[0_1px_0_rgb(255_255_255/0.06)_inset] ring-1 ring-inset ring-line" />}
          {o.label}
        </button>
      ))}
    </div>
  );
}
