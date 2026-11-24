import { CheckCircle, CircleDashed, HandPalm, Lightning, Warning, XCircle } from "@phosphor-icons/react";
import type { Risk } from "../types";

/* Shared helpers and types for the run views. Every view renders only what the backend returns. */

export type Dim = { status: string; why: string };
export type Finding = {
  id: string; title: string; kind: string; label: string; level: Risk; severity?: string; decision: string; score: number; component?: string;
  floor?: string | null; confidence?: { band: string; dimensions: Record<string, Dim>; missing: string[] };
  evidence?: Record<string, unknown>; contributions?: { factor: string; points: number; why: string }[];
};
export type Sections = Record<string, any>;
export type RunModel = { run_id: string; generated: number; sections: Sections };

export const api = async (path: string, init?: RequestInit) => {
  const r = await fetch(path, init);
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body?.detail ?? `${r.status} ${r.statusText}`);
  return body;
};
export const q = (project: string | null) => (project ? `?project=${encodeURIComponent(project)}` : "");
export const jsonPost = (body: unknown) => ({ method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

export const STATUS: Record<string, { cls: string; dot: string; Icon: typeof CheckCircle; label: string }> = {
  complete: { cls: "text-ok", dot: "bg-ok", Icon: CheckCircle, label: "done" },
  passed: { cls: "text-ok", dot: "bg-ok", Icon: CheckCircle, label: "passed" },
  waiting: { cls: "text-high", dot: "bg-high", Icon: HandPalm, label: "needs you" },
  partial: { cls: "text-high", dot: "bg-high", Icon: Warning, label: "partial" },
  failed: { cls: "text-crit", dot: "bg-crit", Icon: XCircle, label: "failed" },
  skipped: { cls: "text-faint", dot: "bg-faint", Icon: CircleDashed, label: "skipped" },
  not_applicable: { cls: "text-faint", dot: "bg-faint", Icon: CircleDashed, label: "n/a" },
  not_run: { cls: "text-faint", dot: "bg-faint", Icon: CircleDashed, label: "not run" },
  pending: { cls: "text-muted", dot: "bg-faint", Icon: CircleDashed, label: "not started" },
  running: { cls: "text-accent", dot: "bg-accent", Icon: Lightning, label: "running" },
};
export const st = (s: string) => STATUS[s] ?? STATUS.pending;

export type StepId = "summary" | "discover" | "detect" | "investigate" | "fix" | "validate" | "report";
export type Step = { id: StepId; n: number; name: string; hint: string; status: string; detail: string };

/** The product journey, with each step's status computed from the run model (one place, used by nav and summary). */
export function journey(s: Sections | undefined): Step[] {
  if (!s) return [];
  const stages: { id: string; status: string }[] = s.run.stages ?? [];
  const bad = stages.some((x) => x.status === "failed") ? "failed" : stages.some((x) => x.status === "partial") ? "partial" : "complete";
  const inv = s.investigation, rem = s.remediation, val = s.validation;
  const intro = (s.findings?.items ?? []).filter((f: Finding) => f.label === "introduced").length;
  return [
    { id: "summary", n: 0, name: "Summary", hint: "decision & next step", status: s.run.verdict ? "complete" : "pending", detail: String(s.run.verdict ?? "").toUpperCase() },
    { id: "discover", n: 1, name: "Discover", hint: "components & graph", status: s.inventory?.summary ? "complete" : "pending", detail: `${s.inventory?.components?.length ?? 0} components` },
    { id: "detect", n: 2, name: "Detect", hint: "risks & priority", status: bad, detail: `${intro} introduced` },
    { id: "investigate", n: 3, name: "Investigate", hint: "4 agents", status: inv.status === "done" ? "complete" : inv.status === "partial" ? "partial" : "pending",
      detail: inv.cases ? `${inv.cases.length} cases` : "not started" },
    { id: "fix", n: 4, name: "Fix & approve", hint: "patch + your decision", status: rem.status === "approved" ? "complete" : rem.status === "rejected" ? "failed" : rem.status === "proposed" ? "waiting" : "pending",
      detail: rem.status === "proposed" ? "approval needed" : rem.status.replace("_", " ") },
    { id: "validate", n: 5, name: "Validate", hint: "isolated build & rescan", status: val.status === "executed" ? (val.gate?.validation === "passed" ? "complete" : val.gate?.validation === "incomplete" ? "partial" : "failed") : val.status === "refused" ? "failed" : "pending",
      detail: val.gate ? (val.gate.verified ? "verified" : val.gate.validation) : "after approval" },
    { id: "report", n: 6, name: "Report", hint: "evidence pack", status: "complete", detail: "HTML + JSON" },
  ];
}

export function Badge({ kind }: { kind: "fact" | "ai" | "human" | "rules" }) {
  const m = {
    fact: ["🔒", "verified fact", "bg-ok/10 text-ok"], ai: ["🤖", "AI inference", "bg-accent/12 text-accent"],
    human: ["👤", "human decision", "bg-ink/10 text-ink"], rules: ["⚙", "rules, no AI", "bg-white/6 text-muted"],
  }[kind];
  return <span className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10.5px] font-medium ${m[2]}`}>{m[0]} {m[1]}</span>;
}

export function SectionHead({ n, title, sub, right }: { n?: number; title: string; sub: string; right?: React.ReactNode }) {
  return (
    <header className="flex flex-wrap items-end gap-4">
      <div className="min-w-0">
        {n !== undefined && <div className="font-mono text-[11px] tracking-wide text-accent">STEP {n}</div>}
        <h1 className="text-[22px] font-semibold tracking-tight">{title}</h1>
        <p className="mt-0.5 max-w-[72ch] text-[13px] text-muted [text-wrap:pretty]">{sub}</p>
      </div>
      {right && <div className="ml-auto flex items-center gap-3">{right}</div>}
    </header>);
}
