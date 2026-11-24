import { animate, motion, useMotionValue, useTransform } from "motion/react";
import { useEffect } from "react";
import { ArrowRight, Fingerprint } from "@phosphor-icons/react";
import { spring } from "../ui";
import { Verdict } from "./Shell";
import { remedySummary } from "./scoring/Remedy";
import { Badge, st, type Finding, type Sections, type Step, type StepId } from "./shared";

function CountUp({ to }: { to: number }) {
  const v = useMotionValue(0);
  const text = useTransform(v, (x) => Math.round(x).toLocaleString());
  useEffect(() => { const c = animate(v, to, { duration: 0.9, ease: [0.16, 1, 0.3, 1] }); return c.stop; }, [to, v]);
  return <motion.span>{text}</motion.span>;
}

export function Summary({ s, steps, onPick }: { s: Sections; steps: Step[]; onPick: (id: StepId) => void }) {
  const items: Finding[] = s.findings?.items ?? [];
  const intro = items.filter((f) => f.label === "introduced");
  const crit = intro.filter((f) => f.level === "critical").length;
  const next = steps.find((x) => x.id !== "summary" && x.id !== "report" && x.status !== "complete");
  const kpis: [string, number, string, string?][] = [
    ["Components discovered", s.inventory?.components?.length ?? 0, "from lockfiles + SBOM"],
    ["Introduced by this PR", intro.length, "new risks only"],
    ["Critical introduced", crit, "block the merge", crit ? "text-crit" : ""],
    ["Already there before", items.length - intro.length, "reported, not blocking"],
    ["AI tokens (last run)", s.investigation?.usage?.run?.tokens ?? 0, !s.investigation?.cases ? "investigation not run" : (s.investigation.usage?.run?.calls ?? 0) === 0 ? "answered from cache (same evidence)" : `${s.investigation.usage.run.calls} calls · ${s.investigation.usage.run.cached_calls} cached`],
  ];
  return (
    <div className="flex flex-col gap-5">
      <motion.section initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={spring}
        className="panel grid gap-6 overflow-hidden p-6 lg:grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)]">
        <div>
          <div className="flex items-center gap-2 text-[12px] text-muted">Merge decision <Badge kind="rules" /></div>
          <div className="mt-3"><Verdict verdict={s.run.verdict} complete={s.run.complete} size="xl" /></div>
          <ul className="mt-4 space-y-1.5 text-[13px]">
            {(s.run.verdict_reasons ?? []).slice(0, 5).map((r: string, i: number) => (
              <motion.li key={r} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ ...spring, delay: 0.15 + i * 0.05 }} className="flex gap-2 text-muted">
                <span className="mt-2 size-1 shrink-0 rounded-full bg-crit" />{r}</motion.li>))}
          </ul>
          {remedySummary(s) && <p className="mt-3 text-[12.5px] text-muted"><span className="text-ink">Remedy</span> (rules): {remedySummary(s)} · {s.remediation?.status === "approved" ? "approved" : "waiting for your approval"}</p>}
          {s.before_after?.verdict_change?.after?.verdict && (
            <p className="mt-2 text-[12.5px] text-muted"><span className="text-ink">After the approved fix</span> (rescan): <b className={s.before_after.verdict_change.after.verdict === "allow" ? "text-ok" : "text-crit"}>{String(s.before_after.verdict_change.after.verdict).toUpperCase()}</b>
              {" "}· {s.before_after.verdict_change.after.introduced.total} risk(s) introduced · {s.validation?.gate?.verified ? "verified" : "not verified yet"}</p>)}
          {!s.run.complete && (s.run.incomplete_reasons ?? []).length > 0 && <p className="mt-3 text-[12px] text-high">Incomplete: {s.run.incomplete_reasons.join("; ")}</p>}
        </div>
        <dl className="grid grid-cols-[130px_minmax(0,1fr)] content-start gap-x-4 gap-y-2 rounded-xl bg-canvas/50 p-4 text-[12.5px] ring-1 ring-line">
          {[["Application", s.run.app], ["Change", `${s.run.base_sha?.slice(0, 10) ?? "—"} → ${s.run.head_sha?.slice(0, 10)}`], ["Coverage", `level ${s.run.capability_level}`],
            ["Confidence", s.confidence?.band], ["Audit chain", s.audit?.chain_ok ? "intact" : "BROKEN"], ["Scan report", s.run.scan_report?.sha256?.slice(0, 16)]].map(([k, v]) => (
            <div key={k} className="contents"><dt className="text-faint">{k}</dt><dd className="truncate font-mono text-[12px]">{k === "Scan report" && <Fingerprint className="mr-1 inline" />}{v ?? "—"}</dd></div>))}
        </dl>
      </motion.section>

      <section className="grid grid-cols-2 gap-3 md:grid-cols-5">
        {kpis.map(([label, n, sub, cls], i) => (
          <motion.div key={label} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ ...spring, delay: 0.05 * i }} className="panel px-4 py-3">
            <div className="text-[11.5px] text-muted">{label}</div>
            <div className={`mt-1 font-mono text-[26px] tabular-nums ${cls ?? ""}`}><CountUp to={n} /></div>
            <div className="text-[11px] text-faint">{sub}</div>
          </motion.div>))}
      </section>

      <section className="panel p-5">
        <div className="flex items-baseline justify-between">
          <h2 className="text-[14px] font-semibold">The journey of this change</h2>
          {next && <button onClick={() => onPick(next.id)} className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-[12.5px] font-medium text-white transition hover:brightness-110 active:scale-[0.98]">Next: {next.name} <ArrowRight /></button>}
        </div>
        <ol className="relative mt-4 grid gap-3 md:grid-cols-3 xl:grid-cols-6">
          {steps.filter((x) => x.id !== "summary").map((x, i) => {
            const S = st(x.status);
            return (
              <motion.li key={x.id} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ ...spring, delay: 0.08 + i * 0.05 }}>
                <button onClick={() => onPick(x.id)} className={`group flex h-full w-full flex-col gap-1 rounded-xl p-3 text-left ring-1 transition hover:bg-raised ${x.id === next?.id ? "bg-accent/6 ring-accent/40" : "ring-line"}`}>
                  <span className="flex items-center gap-2 text-[12.5px] font-medium"><S.Icon weight="fill" className={S.cls} /><span className="font-mono text-[10.5px] text-faint">{x.n}</span>{x.name}</span>
                  <span className="text-[11.5px] text-muted">{x.hint}</span>
                  <span className={`mt-auto text-[11px] ${S.cls}`}>{x.status === "complete" ? x.detail || S.label : S.label}</span>
                </button>
              </motion.li>);
          })}
        </ol>
      </section>
    </div>);
}
