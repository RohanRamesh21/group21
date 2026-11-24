import { motion } from "motion/react";
import { ArrowFatLineUp, ArrowsClockwise, Eraser, Handshake, PushPin, Trash, type Icon } from "@phosphor-icons/react";
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

/** Fix & approve: which remedies this plan uses, explained in plain words. */
export function RemediesUsed({ s }: { s: Sections }) {
  const plan = (s.remediation?.candidates ?? []) as any[];
  if (!plan.length) return null;
  const groups: Record<string, any[]> = {};
  for (const c of plan) (groups[c.type] ??= []).push(c);
  return (
    <section className="panel p-4" aria-labelledby="remedies-h">
      <h2 id="remedies-h" className="text-[13px] font-semibold">Remedies used in this fix <span className="font-normal text-faint">· chosen by rules, no AI</span></h2>
      <div className="mt-3 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        {Object.entries(groups).map(([type, cs], i) => {
          const m = REMEDY[type] ?? REMEDY.escalate;
          return (
            <motion.div key={type} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ ...spring, delay: i * 0.06 }} className="rounded-lg bg-raised p-3">
              <div className="flex items-center gap-2"><span className={`grid size-7 place-items-center rounded-md ${m.tone}`}><m.Icon size={15} weight="bold" /></span>
                <span className="text-[12.5px] font-semibold">{m.label}</span><span className="ml-auto font-mono text-[12px] text-faint">×{cs.length}</span></div>
              <p className="mt-2 text-[11.5px] text-muted">{m.what}</p>
              <ul className="mt-2 space-y-0.5 font-mono text-[11px]">{cs.map((c) => (
                <li key={c.id} className="truncate">{c.package ?? c.file}{c.to ? <span className="text-ok"> {c.from} → {c.to}</span> : null}</li>))}</ul>
            </motion.div>);
        })}
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
