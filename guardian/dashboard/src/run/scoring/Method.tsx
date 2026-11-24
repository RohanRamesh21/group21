import { motion } from "motion/react";
import { spring } from "../../ui";
import type { Sections } from "../shared";

/* "How it's scored": floors -> SSVC -> AHP-weighted priority (ported from the contextual-scoring branch), plus the
   contextual layer (confidence, reachability, rank stability, fix ranking) and anything that could not be checked. */
const FACTOR: Record<string, string> = { exploitation: "Being attacked", impact: "Impact", exposure: "Exposure", introduced: "Introduced by PR", actionable: "Fix available" };
const frac = (x: number) => (x >= 1 ? String(Math.round(x * 100) / 100) : `1/${Math.round(1 / x)}`);

export function Method({ s }: { s: Sections }) {
  const sc = s.findings?.scoring ?? {};
  const base = sc.ahp, act = sc.ahp_active;
  if (!base) return <div className="panel p-6 text-[13px] text-muted">This run was scored before the scoring method was recorded. Rescan it.</div>;
  const a = act?.matrix ? { ...base, matrix: act.matrix, weights: act.weights, lambda_max: act.lambda_max, consistency_ratio: act.consistency_ratio ?? base.consistency_ratio } : base;
  const ctx = sc.contextual, rs = sc.rank_stability_summary, data = sc.data;
  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={spring} className="flex flex-col gap-4">
      <section className="panel grid gap-6 px-5 py-4 text-[12.5px] lg:grid-cols-3">
        <div>
          <div className="mb-2 font-medium text-ink">1 · Hard floors <span className="font-normal text-faint">(no agent or factor can lower these)</span></div>
          <ul className="space-y-1 text-muted">{Object.entries(sc.floors ?? {}).map(([k, f]: [string, any]) => (
            <li key={k}><span className="font-mono text-ink">{f.level}</span> · {f.why}</li>))}</ul>
        </div>
        <div>
          <div className="mb-2 font-medium text-ink">2 · SSVC decision <span className="font-normal text-faint">(adapted from CISA)</span></div>
          <p className="text-muted">Being attacked? (KEV = in the wild, EPSS ≥ {sc.epss_poc_threshold} = likely) → can it be automated? → total or partial impact (CVSS) → how important is the code (runtime direct / indirect / dev-only; a direct dependency with no first-party import found drops one step) → <span className="text-ink">Act · Attend · Track* · Track</span>.</p>
          <p className="mt-2 text-muted">Verdict: {s.findings?.method}.</p>
        </div>
        <div>
          <div className="mb-2 font-medium text-ink">3 · Priority score 0–100 = Σ weight × factor</div>
          <div className="scroll-thin overflow-x-auto"><table className="w-full font-mono text-[11.5px]">
            <thead><tr className="text-left text-faint"><th className="pr-2 font-normal">Factor</th>{a.criteria.map((c: string) => <th key={c} title={FACTOR[c]} className="px-1 text-right font-normal">{c.slice(0, 3)}</th>)}<th className="pl-2 text-right font-normal">Weight</th></tr></thead>
            <tbody>{a.criteria.map((c: string, i: number) => (
              <tr key={c} className="border-b border-line/60"><td className="py-0.5 pr-2 font-sans text-muted">{FACTOR[c]}</td>
                {a.matrix[i].map((x: number, j: number) => <td key={j} className="px-1 text-right text-faint">{frac(x)}</td>)}
                <td className="pl-2 text-right text-ink">{(a.weights[c] * 100).toFixed(1)}%</td></tr>))}</tbody>
          </table></div>
          <p className="mt-2 text-muted">Each factor is 0–1. Points = round(100 × weight × factor, 1); priority = round(sum of those points, 1). Findings sort by level first, then priority.</p>
          <p className="mt-2 text-muted">AHP pairwise matrix (Saaty 1–9).{a.lambda_max != null ? ` λmax ${a.lambda_max},` : ""} consistency ratio {a.consistency_ratio} (must be &lt; 0.10).</p>
          <p className={`mt-1 ${act && act.id !== "baseline" ? "text-accent" : "text-faint"}`}>{act && act.id !== "baseline" ? `Scored with the human-approved matrix ${act.id}${act.approved_by ? ` (approved by ${act.approved_by})` : ""}` : "Scored with the baseline matrix"}</p>
        </div>
      </section>
      <section className="panel grid gap-6 px-5 py-4 text-[12.5px] lg:grid-cols-3">
        <div>
          <div className="mb-2 font-medium text-ink">4 · Contextual layer <span className="font-normal text-faint">(informational; never changes a level)</span></div>
          <ul className="space-y-1 text-muted">
            <li><span className="text-ink">Confidence</span>: 6 evidence signals, AHP-weighted{ctx?.confidence_ahp ? ` (CR ${ctx.confidence_ahp.consistency_ratio})` : ""}</li>
            <li><span className="text-ink">Reachability</span>: static import scan of first-party code ({ctx?.reachability?.computed ?? 0} findings), estimated</li>
            <li><span className="text-ink">Fix ranking</span>: risk reduction, compatibility, footprint, rollback, evidence{ctx?.fix_ahp ? ` (CR ${ctx.fix_ahp.consistency_ratio})` : ""}</li>
          </ul>
        </div>
        <div>
          <div className="mb-2 font-medium text-ink">5 · Rank stability</div>
          {rs ? <p className="text-muted">{rs.draws} draws, every AHP weight varied ±{Math.round(rs.delta * 100)}% (seed {rs.seed}). Mean pair disorder in the top {rs.top_n}: <span className="font-mono text-ink">{rs.mean_pair_disorder_top}</span>. {rs.note}</p>
            : <p className="text-faint">Not computed for this run.</p>}
        </div>
        <div>
          <div className="mb-2 font-medium text-ink">Data used</div>
          {data && <p className="text-muted">EPSS for {data.epss_found}/{data.cves} CVEs · KEV matches {data.kev_matches} (catalog {data.kev_catalog_size}) · {data.advisories} advisories</p>}
          {(data?.errors ?? []).map((e: string) => <p key={e} className="text-high">{e}</p>)}
          {(ctx?.not_checked ?? []).map((e: string) => <p key={e} className="text-high">Not checked: {e}</p>)}
          {ctx?.human_checks?.length > 0 && <p className="mt-1 text-high">{ctx.human_checks.length} introduced high/critical finding(s) with low confidence need a human check.</p>}
        </div>
      </section>
    </motion.div>);
}
