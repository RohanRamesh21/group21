import type { Finding, Fix } from "../shared";

/* Contextual scoring cards (ported from the contextual-scoring branch's RiskScores view). All informational:
   none of them changes a level, decision, floor or verdict. */

const SIGNAL: Record<string, string> = { corroboration: "Sources agree", cvss_vector: "CVSS vector", exploit_data: "EPSS / KEV data",
  reachability: "Reachability", fix_evidence: "Fix evidence", evidence_completeness: "Evidence complete" };
const CONF_TONE: Record<string, string> = { high: "text-ok bg-ok/12 ring-ok/40", medium: "text-med bg-med/12 ring-med/40", low: "text-high bg-high/12 ring-high/40" };
export const TIER_TEXT: Record<string, string> = { imported: "Imported by first-party code", declared: "Declared, no import found", dev_only: "Dev-only (not shipped)", unknown: "Not determined" };
export const TIER_SHORT: Record<string, string> = { imported: "imported", declared: "declared", dev_only: "dev only", unknown: "unknown" };
const FIX_TEXT: Record<string, string> = { upgrade_to_fixed: "Upgrade to a fixed version", override_transitive: "Override the transitive version", remove_package: "Remove the package",
  revert_change: "Revert the change", pin_action_sha: "Pin the action to a commit SHA", pin_image_digest: "Pin the image by digest", escalate: "Escalate for security review" };

export function Contextual({ f }: { f: Finding }) {
  const c = f.confidence, r = f.reachability, k = f.rank_stability;
  if (!c?.signals && !r && !k) return null;
  return (
    <div className="mt-5 grid gap-3">
      {c?.signals && (
        <div className="rounded-lg px-3 py-2.5 ring-1 ring-line">
          <div className="mb-1.5 text-[11px] uppercase tracking-wide text-faint">Confidence</div>
          <div className="flex items-center gap-2"><span className={`rounded-md px-1.5 py-0.5 font-mono text-[11px] ring-1 ring-inset ${CONF_TONE[c.band]}`}>{c.band}</span>
            {c.value !== undefined && <span className="font-mono text-[13px]">{c.value.toFixed(2)}</span>}</div>
          <ul className="mt-2 space-y-0.5 text-[11.5px]">{Object.entries(c.signals).filter(([, v]) => v !== null).map(([n, v]) => (
            <li key={n} className="flex justify-between gap-2"><span className="text-muted">{SIGNAL[n] ?? n}</span>
              <span className={`font-mono ${v === 1 ? "text-ok" : v === 0 ? "text-high" : "text-med"}`}>{v === 1 ? "yes" : v === 0 ? "no" : "partly"}</span></li>))}</ul>
          {c.missing.length > 0 && <div className="mt-2 text-[11px] text-high">Missing: {c.missing.join("; ")}</div>}
          <div className="mt-2 text-[10.5px] text-faint">Evidence quality, not severity (AHP-weighted signals). Never changes the level.</div>
        </div>)}
      {r && (
        <div className="rounded-lg px-3 py-2.5 ring-1 ring-line">
          <div className="mb-1.5 text-[11px] uppercase tracking-wide text-faint">Reachability <span className="normal-case text-med">· estimated</span></div>
          <div className="text-[13px]">{TIER_TEXT[r.tier] ?? r.tier}</div>
          {r.via && <div className="mt-1 text-[11.5px] text-muted">through <span className="font-mono text-ink">{r.via}</span></div>}
          {r.evidence.length > 0 && <div className="mt-1.5 flex flex-wrap gap-1 font-mono text-[11px]">{r.evidence.slice(0, 3).map((e) => <span key={e} className="rounded bg-raised px-1.5 py-0.5">{e}</span>)}</div>}
          {r.note && <div className="mt-1.5 text-[11.5px] text-high">{r.note}</div>}
          <div className="mt-2 text-[10.5px] text-faint">{r.method}. Dynamic requires are missed, so “declared” means “none found”, not “unused”.</div>
        </div>)}
      {k && (
        <div className="rounded-lg px-3 py-2.5 ring-1 ring-line">
          <div className="mb-1.5 text-[11px] uppercase tracking-wide text-faint">Rank stability</div>
          <div className="text-[13px]">Rank <span className="font-mono">{k.baseline_rank}</span> <span className="text-muted">· 90% range</span> <span className="font-mono">{k.rank_p05}–{k.rank_p95}</span></div>
          {k.top5_share !== null && <div className="mt-1 text-[11.5px] text-muted">In the top 5 in <span className="font-mono text-ink">{Math.round(k.top5_share * 100)}%</span> of weight changes</div>}
          <div className="mt-2 text-[10.5px] text-faint">{k.draws} draws, each AHP weight ±{Math.round(k.delta * 100)}%, seed {k.seed}. Only order within a level can move.</div>
        </div>)}
    </div>);
}

export function Fixes({ fixes }: { fixes: Fix[] }) {
  return (
    <div className="mt-5">
      <div className="mb-1.5 text-[11px] uppercase tracking-wide text-faint">Fix options, ranked <span className="normal-case text-med">· forecast; a human approves, the sandbox verifies</span></div>
      <ul className="space-y-2">{fixes.map((x, i) => (
        <li key={x.id} className={`rounded-lg px-3 py-2.5 ring-1 ${i === 0 ? "bg-ok/5 ring-ok/40" : "ring-line"}`}>
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0"><div className="text-[13px] font-medium">{i === 0 && <span className="mr-1.5 rounded bg-ok/15 px-1 py-0.5 text-[10px] text-ok">best ranked</span>}{FIX_TEXT[x.type] ?? x.type}{x.target && <span className="ml-1 font-mono text-accent">{x.target}</span>}</div>
              <div className="mt-0.5 text-[11.5px] text-muted">clears {x.expected_risk_reduction.findings_cleared} finding(s) · {Math.round(x.expected_risk_reduction.component_share * 100)}% of this component’s risk
                {x.compat.semver ? ` · ${x.compat.semver} change` : ""} · compatibility risk {x.compat.risk}</div></div>
            <span className="shrink-0 font-mono text-lg tabular-nums">{x.fix_score.toFixed(1)}</span>
          </div>
          <div className="mt-1.5 text-[11px] text-faint">Rollback: {x.rollback}{x.compat.via_direct_parents?.length ? ` · via ${x.compat.via_direct_parents.join(", ")}` : ""}
            {x.compat.reason ? ` · ${x.compat.reason}` : ""} · not checked: {x.checks_not_run.join(", ").replace("_", " ")}</div>
        </li>))}</ul>
      <div className="mt-1 text-[11px] text-faint">Fix score 0–100 = AHP-weighted risk reduction, compatibility, footprint, rollback and evidence. Generated by rules; no AI proposes a version.</div>
    </div>);
}
