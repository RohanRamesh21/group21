import { motion } from "motion/react";
import { useEffect, useState } from "react";
import { ArrowRight, CaretDown, CheckCircle, DownloadSimple, MinusCircle, WarningCircle } from "@phosphor-icons/react";
import type { Risk } from "../types";
import { RiskTag, spring } from "../ui";

interface Step { n: number; title: string; status: "done" | "nothing_found" | "error"; facts: string[]; note?: string | null; [k: string]: any }
interface Day1 { question: string; chain: string[]; repo: string; head_commit: string; base_commit: string; compare: boolean; mode: string; verdict?: string; steps: Step[] }

const STATUS = {
  done: { label: "Done", cls: "text-ok bg-ok/12 ring-ok/40", Icon: CheckCircle },
  nothing_found: { label: "Done · nothing found", cls: "text-info bg-info/12 ring-info/30", Icon: MinusCircle },
  error: { label: "Scanner problem", cls: "text-crit bg-crit/12 ring-crit/40", Icon: WarningCircle },
};
const VERDICT: Record<string, string> = { block: "border-crit/40 bg-crit/10 text-crit", review: "border-high/40 bg-high/10 text-high", allow: "border-ok/40 bg-ok/10 text-ok" };
const sev = (s: string) => (["critical", "high", "medium", "low", "info"].includes(s) ? (s as Risk) : "info");

function Path({ p }: { p: string[] }) {
  if (!p?.length) return <span className="text-faint">-</span>;
  return <span className="inline-flex flex-wrap items-center gap-1 font-mono text-[11.5px]">{p.map((x, i) => (
    <span key={i} className="inline-flex items-center gap-1">{i > 0 && <ArrowRight size={10} className="text-faint" />}<span className={i === p.length - 1 ? "text-ink" : "text-muted"}>{x}</span></span>))}</span>;
}

export function Day1Report({ project }: { project?: string }) {
  const [d, setD] = useState<Day1 | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState<Record<number, boolean>>({ 5: true });
  useEffect(() => {
    setD(null); setErr(null);
    fetch(`/api/day1${project ? `?project=${project}` : ""}`).then(async (r) => (r.ok ? setD(await r.json()) : setErr((await r.json()).detail))).catch((e) => setErr(String(e)));
  }, [project]);
  if (err) return <div className="panel px-5 py-4 text-sm text-crit">{err}</div>;
  if (!d) return <div className="panel px-5 py-4 text-sm text-muted">Loading Day 1 report…</div>;
  const q = project ? `project=${project}&` : "";

  return (
    <div className="flex flex-col gap-3">
      <section className="panel flex flex-col gap-3 px-5 py-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="text-[15px] font-medium">{d.question}</div>
          {d.verdict && <span className={`rounded-md border px-2 py-0.5 text-[12px] font-medium ${VERDICT[d.verdict] ?? ""}`}>verdict: {d.verdict}</span>}
        </div>
        <div className="flex flex-wrap items-center gap-1.5 text-[12px]">
          {d.chain.map((c, i) => (
            <span key={c} className="inline-flex items-center gap-1.5">{i > 0 && <ArrowRight size={12} className="text-faint" />}
              <span className="rounded-md bg-raised px-2 py-0.5 ring-1 ring-inset ring-line">{c}</span></span>))}
          <span className="ml-auto font-mono text-[11.5px] text-muted">{d.repo} · {d.compare ? `${d.base_commit.slice(0, 8)} → ${d.head_commit.slice(0, 8)}` : `${d.head_commit.slice(0, 8)} (full scan)`}</span>
        </div>
      </section>

      {d.steps.map((s) => {
        const st = STATUS[s.status] ?? STATUS.done;
        const isOpen = open[s.n] ?? false;
        return (
          <section key={s.n} className="panel">
            <button onClick={() => setOpen({ ...open, [s.n]: !isOpen })} className="flex w-full items-start gap-3 px-5 py-3.5 text-left">
              <span className="mt-0.5 grid size-6 shrink-0 place-items-center rounded-full bg-accent/15 font-mono text-[12px] text-accent">{s.n}</span>
              <div className="flex min-w-0 flex-1 flex-col gap-1">
                <div className="flex items-center gap-2">
                  <span className="font-medium">{s.title}</span>
                  <span className={`inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] ring-1 ring-inset ${st.cls}`}><st.Icon size={12} />{st.label}</span>
                </div>
                <ul className="space-y-0.5 text-[12.5px] text-muted">{s.facts.filter(Boolean).map((f, i) => <li key={i}>• {f}</li>)}</ul>
                {s.note && <div className="text-[12px] text-faint">{s.note}</div>}
              </div>
              <CaretDown size={16} className={`mt-1 text-muted transition-transform ${isOpen ? "rotate-180" : ""}`} />
            </button>
            {isOpen && <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={spring} className="border-t border-line px-5 py-3">
              {s.n === 1 && <Step1 s={s} />}
              {s.n === 2 && <Step2 s={s} q={q} />}
              {s.n === 3 && <Step3 s={s} />}
              {s.n === 4 && <Step4 s={s} />}
              {s.n === 5 && <Step5 s={s} />}
            </motion.div>}
          </section>);
      })}
    </div>
  );
}

const th = "px-2 py-1.5 text-left font-normal text-faint";
const td = "px-2 py-1.5 align-top";

function Step1({ s }: { s: Step }) {
  const un = Object.entries(s.unresolved ?? {});
  return (<div className="flex flex-col gap-2">
    {un.length > 0 && <div className="text-[12px] text-high">Could not resolve exact versions for: {un.map(([k]) => k).join(", ")} (declared ranges listed instead)</div>}
    <div className="max-h-[360px] overflow-auto">
      <table className="w-full text-[12px]"><thead className="sticky top-0 bg-surface"><tr><th className={th}>Component</th><th className={th}>Version</th><th className={th}>Ecosystem</th><th className={th}>Direct</th><th className={th}>Found in</th><th className={th}>Origin</th></tr></thead>
        <tbody>{s.sample.map((c: any, i: number) => (
          <tr key={i} className="border-t border-line/60"><td className={`${td} font-mono`}>{c.name}</td><td className={`${td} font-mono`}>{c.version || <span className="text-high">unpinned</span>}</td>
            <td className={td}>{c.ecosystem}</td><td className={td}>{c.direct ? "direct" : "transitive"}</td>
            <td className={`${td} font-mono text-muted`}>{c.source}{c.line ? `:${c.line}` : ""}</td><td className={`${td} text-muted`}>{c.origin}</td></tr>))}</tbody></table>
      {s.sample.length === 0 && <div className="py-2 text-[12.5px] text-muted">No components.</div>}
    </div></div>);
}

function Step2({ s, q }: { s: Step; q: string }) {
  return (<div className="flex flex-col gap-3 text-[12.5px]">
    <div className="flex flex-wrap gap-2">{s.sboms.map((x: any) => (
      <a key={x.format} href={`/api/sbom?${q}fmt=${x.format}`} className="inline-flex items-center gap-1.5 rounded-md bg-raised px-2.5 py-1 ring-1 ring-inset ring-line hover:text-accent">
        <DownloadSimple size={14} /> {x.file}</a>))}</div>
    <div className="flex flex-wrap gap-1.5">{Object.entries(s.origins as Record<string, number>).map(([k, v]) => <span key={k} className="rounded bg-raised px-2 py-0.5 font-mono text-[11.5px]">{k}: {v}</span>)}</div>
    {(s.images.length > 0 || s.actions.length > 0) && <div className="grid gap-3 lg:grid-cols-2">
      <div><div className="mb-1 text-faint">Container base images</div>{s.images.map((i: any, k: number) => (
        <div key={k} className="font-mono text-[11.5px]">{i.ref} <span className={i.digest ? "text-ok" : "text-high"}>{i.digest ? "pinned" : "tag only"}</span> <span className="text-faint">{i.dockerfile}:{i.line}</span></div>))}
        {s.images.length === 0 && <div className="text-muted">none</div>}</div>
      <div><div className="mb-1 text-faint">CI actions</div>{s.actions.map((a: any, k: number) => (
        <div key={k} className="font-mono text-[11.5px]">{a.uses} <span className={a.pinned_sha ? "text-ok" : "text-high"}>{a.pinned_sha ? "SHA-pinned" : "tag"}</span> <span className="text-faint">{a.workflow}</span></div>))}
        {s.actions.length === 0 && <div className="text-muted">none</div>}</div>
    </div>}
    <div className="text-faint">Full interactive graph: "Dependency graph" view.</div>
  </div>);
}

function Step3({ s }: { s: Step }) {
  if (!s.rows.length) return <div className="text-[12.5px] text-muted">No advisories matched.</div>;
  return (<div className="max-h-[420px] overflow-auto">
    <table className="w-full text-[12px]"><thead className="sticky top-0 bg-surface"><tr><th className={th}>Severity</th><th className={th}>Component</th><th className={th}>Advisory / CVE</th><th className={th}>Fix</th><th className={th}>Dependency path (traced to the source)</th><th className={th}>Status</th></tr></thead>
      <tbody>{s.rows.map((v: any, i: number) => (
        <tr key={i} className="border-t border-line/60">
          <td className={td}><RiskTag risk={sev(v.severity)} />{v.malicious && <div className="mt-1 text-[11px] text-crit">malicious</div>}</td>
          <td className={`${td} font-mono`}>{v.component}</td>
          <td className={td}><a className="font-mono hover:text-accent" href={`https://osv.dev/vulnerability/${v.id}`} target="_blank" rel="noreferrer">{v.id}</a>{v.cve && <div className="font-mono text-[11px] text-muted">{v.cve}</div>}
            <div className="text-[11px] text-faint">{v.summary}</div></td>
          <td className={`${td} font-mono`}>{v.fixed?.length ? v.fixed.join(", ") : <span className="text-faint">none</span>}</td>
          <td className={td}><Path p={v.path} /></td>
          <td className={`${td} text-muted`}>{v.label === "introduced" ? <span className="text-high">new</span> : "present before"}</td>
        </tr>))}</tbody></table></div>);
}

function Step4({ s }: { s: Step }) {
  const pc = s.package_changes ?? {};
  return (<div className="flex flex-col gap-3 text-[12.5px]">
    <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">{s.checks.map((c: any) => (
      <div key={c.check} className={`rounded-lg px-3 py-2 ring-1 ring-inset ${c.status === "found" ? "bg-high/8 ring-high/30" : "bg-raised ring-line"}`}>
        <div className="flex items-center justify-between"><span className="font-medium">{c.check}</span>
          <span className={c.status === "found" ? "text-high" : c.status === "n/a" ? "text-faint" : "text-ok"}>{c.status === "found" ? `${c.count} found` : c.status === "n/a" ? "not applicable" : "none found"}</span></div>
        {c.why && <div className="text-[11.5px] text-faint">{c.why}</div>}
        {c.examples.map((e: string, i: number) => <div key={i} className="mt-0.5 truncate text-[11.5px] text-muted" title={e}>{e}</div>)}
      </div>))}</div>
    {(pc.added?.length || pc.updated?.length || pc.removed?.length) ? <div className="font-mono text-[11.5px]">
      {pc.added?.length > 0 && <div><span className="text-ok">+ added</span> {pc.added.join(", ")}</div>}
      {pc.updated?.length > 0 && <div><span className="text-med">~ updated</span> {pc.updated.join(", ")}</div>}
      {pc.removed?.length > 0 && <div><span className="text-crit">- removed</span> {pc.removed.join(", ")}</div>}</div> : null}
    <div className="max-h-[320px] overflow-auto">{s.rows.map((r: any, i: number) => (
      <div key={i} className="flex items-start gap-2 border-t border-line/60 py-1.5">
        <RiskTag risk={sev(r.severity)} /><div className="min-w-0"><span className="font-mono">{r.type}</span> <span className="text-muted">· {r.component}</span>
          {r.label === "introduced" && <span className="ml-1 text-[11px] text-high">new</span>}
          <div className="text-[12px] text-muted">{r.summary}</div>{r.file && <div className="font-mono text-[11px] text-faint">{r.file}{r.line ? `:${r.line}` : ""}</div>}</div>
      </div>))}</div>
  </div>);
}

function Step5({ s }: { s: Step }) {
  if (!s.rows.length) return <div className="text-[12.5px] text-muted">No findings to evidence: nothing risky was detected.</div>;
  return (<div className="grid gap-2 lg:grid-cols-2">{s.rows.map((e: any, i: number) => (
    <div key={i} className="flex flex-col gap-1 rounded-lg bg-raised px-3 py-2.5 text-[12.5px] ring-1 ring-inset ring-line">
      <div className="flex items-center gap-2"><RiskTag risk={sev(e.level)} /><span className="font-medium">{e.what}</span><span className="ml-auto font-mono text-[11px] text-muted">{e.score} · {e.decision}</span></div>
      <div className="text-muted">{e.summary}</div>
      <div><span className="text-faint">Component:</span> <span className="font-mono">{e.component}</span> {e.label === "introduced" && <span className="text-[11px] text-high">new in this change</span>}</div>
      {e.path?.length > 0 && <div><span className="text-faint">Path:</span> <Path p={e.path} /></div>}
      {e.where && <div><span className="text-faint">Evidence:</span> <span className="font-mono text-[11.5px]">{e.where}</span></div>}
      {Object.keys(e.proof).length > 0 && <div className="flex flex-wrap gap-1.5">{Object.entries(e.proof).map(([k, v]) => (
        k === "url" ? <a key={k} href={String(v)} target="_blank" rel="noreferrer" className="rounded bg-surface px-1.5 py-0.5 text-[11px] hover:text-accent">advisory ↗</a> :
          <span key={k} className="rounded bg-surface px-1.5 py-0.5 font-mono text-[11px]">{k}: {String(v)}</span>))}</div>}
      <div className="text-[11.5px] text-faint">Why this level: {e.floor ? `hard floor (${e.floor})` : e.why.join(" · ")}</div>
    </div>))}</div>);
}
