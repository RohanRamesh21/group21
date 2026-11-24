import { motion } from "motion/react";
import { useState } from "react";
import { ArrowFatLineUp, ArrowsClockwise, ClockCounterClockwise, Eraser, FolderSimple, Handshake, PushPin, Trash, type Icon } from "@phosphor-icons/react";
import { spring } from "../../ui";
import type { Finding, Fix, Sections } from "../shared";

/* Remedies: the fix strategies Guardian uses. All are chosen by rules (advisory ranges, npm registry, detector type);
   no AI picks a remedy or a version. The approved fix plan wins; otherwise the best-ranked contextual fix option. */
export const REMEDY: Record<string, { label: string; short: string; Icon: Icon; tone: string; what: string }> = {
  upgrade_to_fixed: { label: "Upgrade to a fixed version", short: "Upgrade", Icon: ArrowFatLineUp, tone: "text-ok bg-ok/10",
    what: "Move a direct dependency to the smallest published version outside every affected advisory range (lockfile-only edit, scripts off)." },
  override_transitive: { label: "Override a transitive version", short: "Override", Icon: ArrowsClockwise, tone: "text-ok bg-ok/10",
    what: "Force a safe version of an indirect dependency through an npm override, without changing the package that pulls it in." },
  remove_package: { label: "Remove the package", short: "Remove", Icon: Trash, tone: "text-crit bg-crit/10",
    what: "The PR added a package with hard supply-chain signals (malware, look-alike name, untrusted source): take it out entirely." },
  restore_lock_entry: { label: "Restore the lockfile entry", short: "Restore", Icon: ClockCounterClockwise, tone: "text-high bg-high/10",
    what: "Same package and version as before, but the PR re-pointed where it downloads from and its checksum: put back the base commit's entry." },
  revert_change: { label: "Revert the change", short: "Revert", Icon: Eraser, tone: "text-high bg-high/10",
    what: "Restore a sensitive file (e.g. .npmrc, a workflow) to its content in the base commit." },
  pin_action_sha: { label: "Pin the action to a commit SHA", short: "Pin SHA", Icon: PushPin, tone: "text-accent bg-accent/10",
    what: "Reference a GitHub Action by its immutable commit SHA instead of a movable tag." },
  pin_image_digest: { label: "Pin the image by digest", short: "Pin digest", Icon: PushPin, tone: "text-accent bg-accent/10",
    what: "Reference a container image by its sha256 digest instead of a movable tag." },
  escalate: { label: "Escalate to a human", short: "Escalate", Icon: Handshake, tone: "text-med bg-med/10",
    what: "No safe automatic fix exists (no fixed version, or the choice needs a person): a reviewer decides, or accepts the risk." },
};

export type Remedy = { type: string; target?: string | null; from?: string | null; source: "fix plan" | "fix ranking"; detail?: string };

/** The remedy for one finding: the approved/proposed fix plan first, else the best-ranked contextual fix option. */
export function remedyFor(f: Finding, s: Sections): Remedy | null {
  const plan = (s.remediation?.candidates ?? []) as any[];
  const c = plan.find((x) => (x.finding_ids ?? []).includes(f.id));
  if (c) return { type: c.type, target: c.to, from: c.from, source: "fix plan", detail: c.package ?? c.file };
  const fx: Fix[] | undefined = s.findings?.scoring?.fix_candidates?.[f.id];
  if (fx?.length) return { type: fx[0].type, target: fx[0].target, source: "fix ranking" };
  return null;
}

export function RemedyChip({ r }: { r: Remedy | null }) {
  if (!r) return <span className="text-[11px] text-faint">—</span>;
  const m = REMEDY[r.type] ?? REMEDY.escalate;
  return (
    <span title={`${m.label}${r.target ? ` → ${r.target}` : ""} (${r.source})`} className={`inline-flex max-w-full items-center gap-1 truncate rounded px-1.5 py-0.5 text-[10.5px] font-medium ${m.tone}`}>
      <m.Icon size={11} weight="bold" />{m.short}{r.target ? <span className="font-mono">→{r.target}</span> : null}
    </span>);
}

const BAR: Record<string, string> = { upgrade_to_fixed: "bg-ok", override_transitive: "bg-ok/55", remove_package: "bg-crit", restore_lock_entry: "bg-high/70", revert_change: "bg-high",
  pin_action_sha: "bg-accent", pin_image_digest: "bg-accent/60", escalate: "bg-med" };

/** Size of a version change by npm semver rules (0.x minor bumps count as breaking). */
export function semverJump(from?: string | null, to?: string | null): "major" | "minor" | "patch" | null {
  const p = (v?: string | null) => (v ?? "").replace(/^[^\d]*/, "").split(/[.+-]/).slice(0, 3).map(Number);
  const a = p(from), b = p(to);
  if (a.length < 3 || b.length < 3 || [...a, ...b].some(Number.isNaN)) return null;
  if (a[0] !== b[0] || (a[0] === 0 && a[1] !== b[1])) return "major";
  return a[1] !== b[1] ? "minor" : a[2] !== b[2] ? "patch" : null;
}

const JUMP_TONE = { major: "text-crit bg-crit/10", minor: "text-high bg-high/10", patch: "text-ok bg-ok/10" } as const;
const SHOW = 5;

/** Rows for one remedy: version changes as package rows; restored files grouped by folder. */
type Row = { key: string; name: string; from: string | null; to: string | null; files: string[] | null };
function rowsFor(type: string, cs: any[]): Row[] {
  if (type !== "revert_change") return cs.map((c): Row => ({ key: String(c.id), name: c.package ?? c.file, from: c.from ?? null, to: c.to ?? null, files: null }));
  const by = new Map<string, string[]>();
  for (const c of cs) {
    const f: string = c.file ?? c.package ?? "";
    const dir = f.includes("/") ? f.slice(0, f.lastIndexOf("/") + 1) : "";
    by.set(dir, [...(by.get(dir) ?? []), f]);
  }
  return [...by.entries()].flatMap(([dir, files]): Row[] => (dir && files.length > 2
    ? [{ key: dir, name: dir, from: null, to: null, files }]
    : files.map((f) => ({ key: f, name: f, from: null, to: null, files: null }))));
}

function RemedyCard({ type, cs, i }: { type: string; cs: any[]; i: number }) {
  const [open, setOpen] = useState(false);
  const [dirOpen, setDirOpen] = useState<string | null>(null);
  const m = REMEDY[type] ?? REMEDY.escalate;
  const rows = rowsFor(type, cs);
  const jumps = cs.map((c) => semverJump(c.from, c.to)).filter(Boolean) as ("major" | "minor" | "patch")[];
  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ ...spring, delay: i * 0.06 }} className="flex flex-col rounded-lg bg-raised p-3">
      <div className="flex items-center gap-2"><span className={`grid size-7 place-items-center rounded-md ${m.tone}`}><m.Icon size={15} weight="bold" /></span>
        <span className="text-[12.5px] font-semibold">{m.label}</span><span className="ml-auto font-mono text-[12px] text-faint">×{cs.length}</span></div>
      <p className="mt-2 text-[11.5px] leading-snug text-muted">{m.what}</p>
      {jumps.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1 text-[10.5px]">{(["major", "minor", "patch"] as const).map((j) => {
          const n = jumps.filter((x) => x === j).length;
          return n ? <span key={j} className={`rounded px-1.5 py-0.5 font-medium ${JUMP_TONE[j]}`} title={j === "major" ? "may break the app: validation decides" : ""}>{n} {j}</span> : null;
        })}</div>)}
      <ul className="mt-2 space-y-0.5 font-mono text-[11px]">{(open ? rows : rows.slice(0, SHOW)).map((r) => (
        <li key={r.key}>
          {r.files ? (
            <button onClick={() => setDirOpen(dirOpen === r.key ? null : r.key)} className="flex w-full items-center gap-1.5 text-left hover:text-ink">
              <FolderSimple size={12} className="shrink-0 text-faint" /><span className="truncate">{r.name}</span><span className="ml-auto shrink-0 font-sans text-faint">{r.files.length} files {dirOpen === r.key ? "▴" : "▾"}</span></button>
          ) : (
            <div className="flex items-center gap-1.5"><span className="truncate">{r.name}</span>
              {r.to ? <span className="ml-auto shrink-0 text-ok">{r.from} → {r.to}</span> : null}
              {r.to && semverJump(r.from, r.to) === "major" ? <span className="shrink-0 rounded bg-crit/10 px-1 font-sans text-[9.5px] text-crit">major</span> : null}</div>)}
          {r.files && dirOpen === r.key && <ul className="ml-4 mt-0.5 space-y-0.5 text-faint">{r.files.map((f) => <li key={f} className="truncate">{f.split("/").pop()}</li>)}</ul>}
        </li>))}</ul>
      {rows.length > SHOW && <button onClick={() => setOpen((x) => !x)} className="mt-2 self-start text-[11.5px] text-accent hover:underline">{open ? "Show fewer" : `Show all ${rows.length}`}</button>}
    </motion.div>);
}

/** Fix & approve: which remedies this plan uses, the factors that matter for review, then compact cards. */
export function RemediesUsed({ s }: { s: Sections }) {
  const plan = (s.remediation?.candidates ?? []) as any[];
  if (!plan.length) return null;
  const groups: Record<string, any[]> = {};
  for (const c of plan) (groups[c.type] ??= []).push(c);
  const entries = Object.entries(groups).sort((a, b) => b[1].length - a[1].length);
  const jumps = plan.map((c) => semverJump(c.from, c.to)).filter(Boolean);
  const pkgs = plan.filter((c) => ["upgrade_to_fixed", "override_transitive", "restore_lock_entry"].includes(c.type)).length;
  const files = (groups.revert_change ?? []).length;
  const factors: [string, number | string, string][] = [
    ["changes in one patch", plan.length, ""], ["packages moved to a safe version", pkgs, ""], ["files restored to base", files, files > 10 ? "text-high" : ""],
    ["packages removed", (groups.remove_package ?? []).length, (groups.remove_package ?? []).length ? "text-crit" : ""],
    ["major version jumps", jumps.filter((j) => j === "major").length, jumps.some((j) => j === "major") ? "text-crit" : ""],
    ["escalated to a person", (groups.escalate ?? []).length, ""],
  ];
  return (
    <section className="panel p-4" aria-labelledby="remedies-h">
      <h2 id="remedies-h" className="text-[13px] font-semibold">Remedies used in this fix <span className="font-normal text-faint">· chosen by rules, no AI</span></h2>
      <div className="mt-3 flex h-2.5 overflow-hidden rounded-full bg-white/5" role="img" aria-label="share of each remedy">
        {entries.map(([t, cs]) => <motion.div key={t} title={`${(REMEDY[t] ?? REMEDY.escalate).label}: ${cs.length}`} className={BAR[t] ?? "bg-med"}
          initial={{ width: 0 }} animate={{ width: `${(cs.length / plan.length) * 100}%` }} transition={spring} />)}
      </div>
      <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-muted">{entries.map(([t, cs]) => (
        <span key={t} className="flex items-center gap-1"><span className={`size-2 rounded-sm ${BAR[t] ?? "bg-med"}`} />{cs.length} {(REMEDY[t] ?? REMEDY.escalate).short.toLowerCase()}</span>))}</div>
      <dl className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-6">{factors.map(([k, v, tone]) => (
        <div key={k} className="rounded-lg bg-canvas/50 px-3 py-2 ring-1 ring-line"><dd className={`font-mono text-[18px] tabular-nums ${tone}`}>{v}</dd><dt className="text-[10.5px] leading-tight text-faint">{k}</dt></div>))}</dl>
      {files > 10 && <p className="mt-2 text-[11.5px] text-high">Many files are restored to the base version. This usually means the pull request's base branch is far behind (the comparison includes unrelated commits). Check the PR's base before approving.</p>}
      <div className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        {entries.map(([type, cs], i) => <RemedyCard key={type} type={type} cs={cs} i={i} />)}
      </div>
    </section>);
}

/** One line for the Summary: how the risks will be remedied. */
export function remedySummary(s: Sections): string | null {
  const plan = (s.remediation?.candidates ?? []) as any[];
  if (!plan.length) return null;
  const n: Record<string, number> = {};
  for (const c of plan) n[c.type] = (n[c.type] ?? 0) + 1;
  return Object.entries(n).map(([t, k]) => `${k} × ${(REMEDY[t] ?? REMEDY.escalate).short.toLowerCase()}`).join(" · ");
}
