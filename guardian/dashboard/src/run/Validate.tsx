import { useCallback, useEffect, useRef, useState } from "react";
import { api, jsonPost, q, SectionHead, st, type Sections } from "./shared";

function Validation({ project, s, refresh }: { project: string | null; s: Sections; refresh: () => void }) {
  const [state, setState] = useState<{ status?: string; message?: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const timer = useRef<number | null>(null);
  const v = s.validation;
  const poll = useCallback(() => {
    if (timer.current) window.clearInterval(timer.current);
    timer.current = window.setInterval(async () => {
      try {
        const r = await api(`/api/validation${q(project)}`);
        setState(r);
        if (r.gate || String(r.status ?? "").startsWith("error")) { window.clearInterval(timer.current!); refresh(); }
      } catch { /* 404 until the first result exists */ }
    }, 3000);
  }, [project, refresh]);
  useEffect(() => () => { if (timer.current) window.clearInterval(timer.current); }, []);
  const start = async () => { setErr(null); try { await api("/api/validate", jsonPost({ project })); setState({ status: "running" }); poll(); } catch (e) { setErr((e as Error).message); } };
  const g = v.gate;
  const table = (side: string) => v[side]?.stages && (
    <div>
      <h4 className="mb-1 text-[11.5px] font-medium text-muted">{side}</h4>
      <ul className="space-y-0.5 text-[12px]">{v[side].stages.map((x: any) => { const S = st(x.status); return (
        <li key={x.id} className="flex items-center gap-2"><S.Icon className={S.cls} weight="fill" /><span className="w-24">{x.id}</span><span className={`${S.cls}`}>{S.label}</span><span className="ml-auto tabular-nums text-faint">{x.seconds ? `${x.seconds}s` : ""}</span></li>); })}</ul>
    </div>);
  return (
    <section className="panel p-4" aria-labelledby="val-h">
      <h2 id="val-h" className="text-[13px] font-semibold">Validation</h2>
      {!g && (
        <div className="mt-2 text-[12.5px] text-muted">
          <p className="max-w-[60ch]">Builds and tests the baseline and the approved candidate in an isolated container (no secrets, no internet except the local registry), then rescans.</p>
          <button onClick={start} disabled={s.remediation.status !== "approved" || state?.status === "running"}
            className="mt-3 rounded-lg bg-accent px-3 py-1.5 text-[12.5px] font-medium text-white transition hover:brightness-110 active:scale-[0.98] disabled:opacity-40"
            title={s.remediation.status !== "approved" ? "A person must approve the fix first" : ""}>{state?.status === "running" ? "Validating…" : "Validate approved fix"}</button>
          {state?.status === "running" && <p className="mt-2 flex items-center gap-2 text-[12px]"><span className="relative size-2"><span className="ping-soft absolute inset-0 rounded-full bg-accent" /><span className="absolute inset-0 rounded-full bg-accent" /></span>{state.message ?? "starting"}</p>}
          {String(state?.status ?? "").startsWith("error") && <p role="alert" className="mt-2 text-crit">{state?.status}</p>}
        </div>)}
      {g && (
        <div className="mt-2">
          <div className="mb-2 flex flex-wrap items-center gap-3 text-[12px] text-muted">
            <span>Last run {v.finished ? new Date(v.finished * 1000).toLocaleString() : ""}</span>
            <button onClick={start} disabled={state?.status === "running"} className="rounded-md px-2.5 py-1 text-accent ring-1 ring-accent/40 transition hover:bg-accent/10 active:scale-[0.98] disabled:opacity-40">
              {state?.status === "running" ? "Validating…" : "Run validation again"}</button>
            {state?.status === "running" && <span className="text-accent">{state.message ?? "starting"}</span>}
          </div>
          <div className="flex flex-wrap gap-2 text-[12px]">
            <span className="rounded bg-raised px-2 py-1">target: <b className={g.target === "corrected" ? "text-ok" : "text-crit"}>{g.target}</b></span>
            <span className="rounded bg-raised px-2 py-1">validation: <b className={g.validation === "passed" ? "text-ok" : g.validation === "incomplete" ? "text-high" : "text-crit"}>{g.validation}</b></span>
            <span className="rounded bg-raised px-2 py-1">verified: <b className={g.verified ? "text-ok" : "text-crit"}>{g.verified ? "yes" : "no"}</b></span>
          </div>
          {g.reasons?.length > 0 && <ul className="mt-2 list-disc pl-5 text-[12px] text-muted">{g.reasons.map((r: string) => <li key={r}>{r}</li>)}</ul>}
          <div className="mt-3 grid gap-4 sm:grid-cols-2">{table("baseline")}{table("candidate")}</div>
        </div>)}
      {err && <p role="alert" className="mt-2 text-[12px] text-crit">{err}</p>}
    </section>);
}


export function Validate({ s, project, refresh }: { s: Sections; project: string | null; refresh: () => void }) {
  return (
    <div className="flex flex-col gap-4">
      <SectionHead n={5} title="Validate the approved fix" sub="Baseline and candidate are installed, built and tested in disposable containers (all capabilities dropped, non-root, no secrets, no internet except the local registry), then rescanned. “Verified” only when every required stage passed." />
      <Validation project={project} s={s} refresh={refresh} />
    </div>);
}
