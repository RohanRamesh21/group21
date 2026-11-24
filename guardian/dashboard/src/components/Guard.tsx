import { useEffect, useState } from "react";
import { ArrowClockwise, Gavel, Pulse, WarningCircle } from "@phosphor-icons/react";

interface Rule { id: string | null; message: string }
interface Policy { engine: string | null; decision: string | null; deny: Rule[]; warn: Rule[]; error: string | null; score_verdict?: string; verdict?: string; rule_files: string[] }
interface MonitorEntry { at: string; components: number; new_advisories: string[]; newly_exploited: string[]; verdict_before: string; verdict_after: string; error: string | null }

const TONE: Record<string, string> = { block: "text-crit", review: "text-high", allow: "text-ok" };
const q = (project?: string | null) => (project ? `?project=${encodeURIComponent(project)}` : "");

/** Policy-as-code result and continuous monitoring for one scanned project (stretch goals 5 and 6). */
export function Guard({ project }: { project?: string | null }) {
  return (
    <section className="grid gap-4 xl:grid-cols-2">
      <PolicyPanel project={project} />
      <MonitorPanel project={project} />
    </section>
  );
}

function PolicyPanel({ project }: { project?: string | null }) {
  const [p, setP] = useState<Policy | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    setP(null); setErr(null);
    fetch(`/api/policy${q(project)}`).then(async (r) => (r.ok ? setP(await r.json()) : setErr((await r.json()).detail))).catch(() => setErr("backend offline"));
  }, [project]);
  return (
    <div className="panel flex flex-col gap-2 px-5 py-4" data-testid="policy-panel">
      <div className="flex flex-wrap items-center gap-2">
        <Gavel size={17} className="text-accent" /><span className="font-medium">Policy as code</span>
        {p && <span className="text-[12px] text-muted">{p.engine ?? "not evaluated"} · {p.rule_files.join(", ")}</span>}
      </div>
      {err && <div className="text-[12.5px] text-crit">{err}</div>}
      {p && (<>
        <div className="flex flex-wrap gap-x-4 text-[12.5px]">
          <span>Final verdict <b className={TONE[p.verdict ?? ""] ?? ""}>{p.verdict ?? "-"}</b></span>
          <span className="text-muted">= stricter of risk score <b className={TONE[p.score_verdict ?? ""] ?? ""}>{p.score_verdict ?? "-"}</b> and policy <b className={TONE[p.decision ?? ""] ?? ""}>{p.decision ?? "not run"}</b></span>
        </div>
        {p.error && <div className="flex items-start gap-1.5 text-[12px] text-high"><WarningCircle size={14} className="mt-0.5 shrink-0" />Policy did not run: {p.error}</div>}
        <ul className="max-h-[170px] space-y-1 overflow-y-auto text-[12px]">
          {p.deny.map((r, i) => <li key={`d${i}`} className="flex gap-2"><span className="shrink-0 rounded bg-crit/15 px-1.5 font-mono text-[11px] text-crit">{r.id ?? "deny"}</span><span>{r.message}</span></li>)}
          {p.warn.map((r, i) => <li key={`w${i}`} className="flex gap-2"><span className="shrink-0 rounded bg-high/15 px-1.5 font-mono text-[11px] text-high">{r.id ?? "warn"}</span><span className="text-muted">{r.message}</span></li>)}
          {!p.error && !p.deny.length && !p.warn.length && <li className="text-muted">No policy rule fired.</li>}
        </ul>
        <div className="text-[11px] text-faint">deny = block the merge · warn = needs a human decision · rules in policies/*.rego, lists in guardian.yaml</div>
      </>)}
    </div>
  );
}

function MonitorPanel({ project }: { project?: string | null }) {
  const [hist, setHist] = useState<MonitorEntry[] | null>(null);
  const [interval, setIntervalMin] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    setHist(null); setErr(null);
    fetch(`/api/monitor${q(project)}`).then((r) => r.json()).then((d) => { setHist(d.history ?? []); setIntervalMin(d.interval_minutes ?? null); }).catch(() => setErr("backend offline"));
  }, [project]);
  const run = () => {
    setBusy(true); setErr(null);
    fetch(`/api/monitor/run${q(project)}`, { method: "POST" }).then(async (r) => {
      const d = await r.json();
      if (!r.ok) throw new Error(d.detail);
      setHist((h) => [d, ...(h ?? [])]);
    }).catch((e) => setErr(String(e.message ?? e))).finally(() => setBusy(false));
  };
  const last = hist?.[0];
  return (
    <div className="panel flex flex-col gap-2 px-5 py-4" data-testid="monitor-panel">
      <div className="flex items-center gap-2">
        <Pulse size={17} className="text-accent" /><span className="font-medium">Continuous monitoring</span>
        <span className="text-[12px] text-muted">{interval ? `automatic every ${interval} min` : "on demand (or `guardian watch --interval N`)"}</span>
        <button onClick={run} disabled={busy} className="ml-auto inline-flex items-center gap-1.5 rounded-md bg-accent/15 px-2.5 py-1 text-[12px] text-accent enabled:hover:bg-accent/25 disabled:opacity-50">
          <ArrowClockwise size={13} className={busy ? "animate-spin" : ""} />{busy ? "Checking…" : "Re-check now"}</button>
      </div>
      <p className="text-[12px] text-muted">Re-queries OSV.dev for every component of this scan and refreshes CISA KEV / EPSS, without rescanning the code. New advisories and newly exploited CVEs re-score the app.</p>
      {err && <div className="text-[12.5px] text-crit">{err}</div>}
      {hist && !last && <div className="text-[12.5px] text-faint">Not checked since the scan.</div>}
      {last && (
        <div className="rounded-lg bg-raised px-3 py-2 text-[12.5px] ring-1 ring-inset ring-line" data-testid="monitor-last">
          <div className="flex flex-wrap gap-x-3"><span className="font-mono text-muted">{last.at}</span><span>{last.components} versioned components checked</span>
            <span className={last.new_advisories.length ? "text-high" : "text-ok"}>{last.new_advisories.length} new advisories</span>
            <span className={last.newly_exploited.length ? "text-crit" : "text-ok"}>{last.newly_exploited.length} newly exploited</span>
            <span>verdict <b className={TONE[last.verdict_before]}>{last.verdict_before}</b> → <b className={TONE[last.verdict_after]}>{last.verdict_after}</b></span></div>
          {[...last.new_advisories, ...last.newly_exploited].slice(0, 6).map((a) => <div key={a} className="font-mono text-[11.5px] text-high">{a}</div>)}
          {last.error && <div className="text-[11.5px] text-high">{last.error}</div>}
        </div>)}
      {hist && hist.length > 1 && <div className="text-[11px] text-faint">{hist.length} checks recorded · previous: {hist.slice(1, 4).map((h) => h.at.slice(0, 16)).join(", ")}</div>}
    </div>
  );
}
