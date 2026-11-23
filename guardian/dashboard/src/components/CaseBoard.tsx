import { LayoutGroup, motion } from "motion/react";
import type { Finding, RunState } from "../types";
import { RISK, RiskTag, shortPurl, spring } from "../ui";
import { EvidenceChips } from "./AgentLanes";

const COLS: { key: string; title: string; match: Finding["status"][]; tone: string }[] = [
  { key: "candidate", title: "Detected", match: ["candidate", "needs_review"], tone: "text-muted" },
  { key: "disputed", title: "Disputed", match: ["disputed"], tone: "text-med" },
  { key: "corroborated", title: "Confirmed by Skeptic", match: ["corroborated"], tone: "text-crit" },
  { key: "cleared", title: "Cleared", match: ["cleared"], tone: "text-ok" },
];

const TYPE: Record<string, string> = {
  lockfile_tamper: "Lockfile tampering", source_change: "Sensitive file change", typosquat: "Look-alike package",
  suspicious_update: "Version update", prompt_injection: "Text aimed at AI reviewers", malicious_package: "Known malicious",
  known_vulnerability: "Known vulnerability",
};

export function CaseBoard({ state, onEvidence }: { state: RunState | null; onEvidence: (id: string) => void }) {
  const findings = Object.entries(state?.findings ?? {});
  const cases = Object.entries(state?.cases ?? {});
  return (
    <section className="panel flex min-h-0 flex-col p-4">
      <div className="mb-3 flex items-center justify-between text-sm">
        <span className="font-medium">Findings and cases</span>
        <span className="text-xs text-muted">{findings.length} findings | {cases.length} cases</span>
      </div>

      {cases.map(([id, c]) => (
        <motion.div key={id} layout initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={spring}
          className="mb-3 rounded-lg border p-3" style={{ borderColor: `${RISK[c.risk].hex}55`, background: `${RISK[c.risk].hex}0d` }}>
          <div className="flex flex-wrap items-center gap-2 text-[13px]">
            <span className="font-mono text-[11px] text-muted">{id}</span>
            <span className="font-medium">{c.title}</span>
            <RiskTag risk={c.risk} />
            <span className="rounded bg-white/5 px-1.5 py-px text-[11px] text-ink/80">{c.resolved ? c.verdict : "open"}</span>
            {c.resolved && <span className="text-[11px] text-faint">{Math.round(c.confidence * 100)}% confidence</span>}
          </div>
          {c.rationale && <p className="mt-1.5 text-[12.5px] leading-relaxed text-ink/80">{c.rationale}</p>}
        </motion.div>
      ))}

      <LayoutGroup>
        <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 md:grid-cols-4">
          {COLS.map((col) => {
            const fs = findings.filter(([, f]) => col.match.includes(f.status));
            return (
              <div key={col.key} className="flex min-h-24 flex-col gap-2 rounded-lg bg-canvas/40 p-2">
                <div className={`flex items-center justify-between px-1 text-[12px] ${col.tone}`}>
                  <span>{col.title}</span><span className="font-mono">{fs.length}</span>
                </div>
                {fs.map(([id, f]) => (
                  <motion.div key={id} layoutId={id} layout transition={spring}
                    className="rounded-lg border border-line bg-raised p-2.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[12.5px] font-medium">{TYPE[f.type] ?? f.type}</span>
                      <RiskTag risk={f.risk} />
                    </div>
                    <div className="mt-1 truncate font-mono text-[11px] text-muted">{f.component.startsWith("E-") ? "package README" : shortPurl(f.component)}</div>
                    <p className="mt-1 text-[11.5px] leading-snug text-ink/70">{f.summary}</p>
                    <div className="mt-1.5 flex items-center gap-2">
                      {f.hard_signal && <span className="rounded bg-crit/12 px-1.5 py-px text-[10px] text-crit">hard signal</span>}
                      {f.label && <span className="text-[10px] text-faint">{f.label.replace("_", "-")}</span>}
                    </div>
                    <div className="mt-1.5"><EvidenceChips ids={f.evidence_ids} onEvidence={onEvidence} /></div>
                  </motion.div>
                ))}
              </div>
            );
          })}
        </div>
      </LayoutGroup>
    </section>
  );
}
