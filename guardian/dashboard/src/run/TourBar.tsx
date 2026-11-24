import { AnimatePresence, motion } from "motion/react";
import { ArrowLeft, ArrowRight, X } from "@phosphor-icons/react";
import { spring } from "../ui";
import type { StepId } from "./shared";

/* Guided flow for a live demo: opened by clicking Buddy (?tour=1). The presenter steps through the product's journey;
   each step says in one line what to point at. It only changes the view; it never triggers an action. */
const STEPS: { id: StepId; title: string; say: string }[] = [
  { id: "summary", title: "The decision", say: "GitHub Actions handed this PR to Guardian. Rules decided BLOCK / REVIEW / ALLOW and say why." },
  { id: "discover", title: "What we build", say: "Every component from the lockfile, as a graph. Click a package to see how it reaches the app." },
  { id: "detect", title: "What is risky, in what order", say: "OSV + Grype + 14 detectors. Floors → SSVC → AHP priority; open a finding for its proof, reachability and fix options." },
  { id: "investigate", title: "The 4 agents", say: "Lead plans, Investigators examine each case in parallel, the Verifier challenges, the Fixer explains. The Gatekeeper checks every AI sentence." },
  { id: "fix", title: "Fix + human approval", say: "The fix is computed by rules, not AI. A named person reviews the patch and approves exactly that patch hash." },
  { id: "validate", title: "Prove the fix", say: "Baseline vs fixed version in locked Docker sandboxes, then a rescan: corrected · passed · verified." },
  { id: "report", title: "Evidence pack", say: "One HTML + JSON report built from the same run: what was checked, what could not be, with hashes." },
];

export function TourBar({ view, setView, onEnd }: { view: string; setView: (v: StepId) => void; onEnd: () => void }) {
  const i = Math.max(0, STEPS.findIndex((s) => s.id === view));
  const s = STEPS[i];
  return (
    <AnimatePresence>
      <motion.div initial={{ y: -12, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={spring} role="region" aria-label="Guided demo"
        className="mx-6 mt-3 flex flex-wrap items-center gap-3 rounded-xl bg-accent/10 px-4 py-2.5 ring-1 ring-accent/35">
        <span className="rounded-md bg-accent px-2 py-0.5 font-mono text-[11px] font-semibold text-white">Step {i + 1} of {STEPS.length}</span>
        <div className="min-w-0 flex-1">
          <div className="text-[13px] font-semibold">{s.title}</div>
          <div className="text-[12px] text-muted">{s.say}</div>
        </div>
        <button disabled={i === 0} onClick={() => setView(STEPS[i - 1].id)} className="inline-flex items-center gap-1 rounded-md px-2.5 py-1.5 text-[12px] text-muted ring-1 ring-line transition hover:text-ink disabled:opacity-30"><ArrowLeft /> Back</button>
        {i < STEPS.length - 1
          ? <button onClick={() => setView(STEPS[i + 1].id)} className="inline-flex items-center gap-1 rounded-md bg-accent px-3 py-1.5 text-[12px] font-medium text-white transition hover:brightness-110 active:scale-[0.98]">Next: {STEPS[i + 1].title} <ArrowRight /></button>
          : <button onClick={onEnd} className="rounded-md bg-ok/90 px-3 py-1.5 text-[12px] font-medium text-canvas">Finish</button>}
        <button onClick={onEnd} aria-label="End the guided flow" className="rounded p-1 text-faint hover:text-ink"><X /></button>
      </motion.div>
    </AnimatePresence>);
}
