import type { Risk } from "./types";
import { Crosshair, Detective, Robot, Scales, ShieldStar, User, Wrench } from "@phosphor-icons/react";

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
  const r = RISK[risk];
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

/** Links built from third-party data (advisory URLs) are clickable only when they are plain http(s) URLs: no
 *  javascript:, data: or other schemes. Model-written text is never turned into links anywhere in the dashboard. */
export function safeHref(u: unknown): string | undefined {
  try {
    const url = new URL(String(u ?? ""), window.location.origin);
    return url.protocol === "https:" || url.protocol === "http:" ? url.href : undefined;
  } catch {
    return undefined;
  }
}
