import { useEffect, useMemo, useRef, useState } from "react";
import { CheckCircle, CircleNotch, GitBranch, ShieldCheck, Wrench, XCircle } from "@phosphor-icons/react";

interface Action { id: string; kind: string; ecosystem: string; component: string; package?: string; from?: string; to?: string | null; automatable: boolean;
  findings: string[]; rationale: string; compatibility: string; commands: string[]; rollback: string }
interface Validation { id: string; created: number; actions: Action[]; applied: { id: string; component: string; ok: boolean; output: string }[];
  diffstat: string; patch_preview: string; fixed: string[]; still_present: string[]; new_problems: string[]; attempts: { attempt: number; package: string; rejected: string; because: string[]; next: string }[];
  verdict_before: string; verdict_after: string; build_and_tests: string; coverage_gaps?: string[]; ok: boolean; pr: string;
  approved: { by: string; at: number; branch: string; commit: string } | null }
interface Plan { plan: Action[]; validations: Validation[]; compare: boolean }

const KIND: Record<string, string> = { remove: "Remove", revert_package: "Revert version", revert_file: "Restore file", upgrade: "Upgrade", override: "Override (transitive)",
  edit_pin: "Update pin", manual: "Manual" };
const TONE: Record<string, string> = { block: "text-crit", review: "text-high", allow: "text-ok" };
const q = (project?: string | null) => (project ? `?project=${encodeURIComponent(project)}` : "");

/** Stretch goal 2 / Day 2 core: recommend fixes, validate them in the sandbox (rescan), then a human approves a local branch. */
export function Remediation({ project }: { project?: string | null }) {
  const [d, setD] = useState<Plan | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [job, setJob] = useState<{ id: string; status: string; log: string[]; error: string | null; result: Validation | null } | null>(null);
  const [cur, setCur] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  const load = () => fetch(`/api/remediation${q(project)}`).then(async (r) => (r.ok ? r.json() : Promise.reject((await r.json()).detail)))
    .then((x: Plan) => { setD(x); setCur((c) => c ?? x.validations[0]?.id ?? null); }).catch((e) => setErr(String(e)));
  useEffect(() => { setD(null); setErr(null); setSel(new Set()); setJob(null); setCur(null); load(); return () => { if (timer.current) clearInterval(timer.current); }; }, [project]);

  const validate = async () => {
    setErr(null);
    const r = await fetch("/api/remediation/validate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ project, ids: [...sel] }) });
    const b = await r.json();
    if (!r.ok) return setErr(b.detail);
    setJob({ id: b.job, status: "running", log: [], error: null, result: null });
    timer.current = setInterval(async () => {
      const j = await (await fetch(`/api/remediation/jobs/${b.job}`)).json();
      setJob(j);
      if (j.status !== "running") {
        if (timer.current) clearInterval(timer.current);
        if (j.result) { setCur(j.result.id); load(); }
      }
    }, 1200);
  };
  const auto = useMemo(() => (d?.plan ?? []).filter((a) => a.automatable), [d]);
  if (err && !d) return <div className="panel px-5 py-4 text-sm text-crit">{err}</div>;
  if (!d) return <div className="panel px-5 py-4 text-sm text-muted">Building the remediation plan…</div>;
  const v = d.validations.find((x) => x.id === cur) ?? null;

  return (
    <div className="flex flex-col gap-4">
      <section className="panel flex flex-col gap-2 px-5 py-4">
        <div className="flex flex-wrap items-center gap-2"><Wrench size={18} className="text-accent" /><span className="font-medium">Recommend → validate → approve</span>
          <span className="text-[12px] text-muted">{d.plan.length} fix(es), {auto.length} can be applied and validated automatically</span></div>
        <p className="text-[12.5px] text-muted">Guardian proposes one fix per problem (upgrade to the lowest safe release, override a transitive package, remove a package this change added, restore a tampered file).
          <b className="text-ink"> Validate</b> applies the selected fixes to a copy of the code inside the sandbox (npm can only reach the registry) and rescans before vs after; a version that has advisories of its own is replaced and retried.
          Nothing is built or run. <b className="text-ink">Approve</b> creates a local branch; Guardian never pushes or merges.</p>
        {err && <div className="text-[12.5px] text-crit">{err}</div>}
      </section>

      <section className="panel">
        <div className="flex items-center gap-3 border-b border-line px-4 py-2 text-[12.5px]">
          <button onClick={() => setSel(new Set(auto.map((a) => a.id)))} className="text-accent hover:underline">select all automatic</button>
          <button onClick={() => setSel(new Set())} className="text-muted hover:underline">clear</button>
          <span className="text-faint">{sel.size} selected</span>
          <button onClick={validate} disabled={!sel.size || job?.status === "running"} data-testid="validate-btn"
            className="ml-auto inline-flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-[13px] font-medium text-white enabled:hover:bg-accent/85 disabled:opacity-40">
            {job?.status === "running" ? <CircleNotch size={14} className="animate-spin" /> : <ShieldCheck size={14} />} Validate selected</button>
        </div>
        <div className="max-h-[420px] overflow-y-auto">
          {d.plan.map((a) => (
            <label key={a.id} className={`flex cursor-pointer items-start gap-3 border-b border-line/60 px-4 py-2.5 text-[12.5px] ${a.automatable ? "hover:bg-raised" : "opacity-80"}`}>
              <input type="checkbox" disabled={!a.automatable} checked={sel.has(a.id)} data-testid={`fix-${a.id}`}
                onChange={(e) => { const s = new Set(sel); e.target.checked ? s.add(a.id) : s.delete(a.id); setSel(s); }} className="mt-1 accent-[var(--color-accent)]" />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`rounded px-1.5 py-0.5 text-[11px] ${a.kind === "remove" || a.kind === "revert_file" || a.kind === "revert_package" ? "bg-crit/15 text-crit" : a.automatable ? "bg-accent/15 text-accent" : "bg-raised text-muted"}`}>{KIND[a.kind] ?? a.kind}</span>
                  <span className="font-mono">{a.component}</span>{a.to && <span className="font-mono text-ok">→ {a.to}</span>}
                  <span className="text-faint">{a.ecosystem} · fixes {a.findings.length} · {a.compatibility}</span>
                </div>
                <div className="text-muted">{a.rationale}</div>
                {a.commands.length > 0 && <div className="font-mono text-[11px] text-faint">{a.commands.join("  ·  ")}</div>}
              </div>
            </label>))}
          {!d.plan.length && <div className="px-4 py-6 text-sm text-muted">Nothing to fix: no finding has a remediation.</div>}
        </div>
      </section>

      {job && job.status !== "done" && (
        <section className="panel px-5 py-4" data-testid="validate-job">
          <div className="mb-1 font-medium">{job.status === "error" ? "Validation failed" : "Validating in the sandbox…"}</div>
          <ol className="max-h-[200px] space-y-0.5 overflow-y-auto font-mono text-[11.5px] text-muted">{job.log.map((l, i) => <li key={i}>{l}</li>)}</ol>
          {job.error && <div className="mt-2 text-[12.5px] text-crit">{job.error}</div>}
        </section>)}

      {d.validations.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 text-[12px]"><span className="text-faint">Validations:</span>
          {d.validations.map((x) => (
            <button key={x.id} onClick={() => setCur(x.id)} className={`rounded-md px-2 py-0.5 font-mono ${cur === x.id ? "bg-raised text-ink ring-1 ring-line" : "text-muted hover:text-ink"}`}>
              {x.id} {x.approved ? "· branch" : x.ok ? "· passed" : "· failed"}</button>))}
        </div>)}
      {v && <ValidationCard v={v} project={project} onApproved={load} />}
    </div>
  );
}

function ValidationCard({ v, project, onApproved }: { v: Validation; project?: string | null; onApproved: () => void }) {
  const [name, setName] = useState("");
  const [ok, setOk] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [showPatch, setShowPatch] = useState(false);
  const approve = async () => {
    setBusy(true); setErr(null);
    const r = await fetch("/api/remediation/approve", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ project, validation: v.id, approver: name, confirm: ok }) });
    const b = await r.json();
    setBusy(false);
    if (!r.ok) return setErr(b.detail);
    onApproved();
  };
  return (
    <section className="panel flex flex-col gap-3 px-5 py-4 text-[12.5px]" data-testid="validation-card">
      <div className="flex flex-wrap items-center gap-3">
        {v.ok ? <CheckCircle size={20} className="text-ok" /> : <XCircle size={20} className="text-crit" />}
        <span className="font-medium">{v.ok ? "Fix validated" : "Fix did not pass validation"}</span>
        <span>verdict <b className={TONE[v.verdict_before]}>{v.verdict_before}</b> → <b className={TONE[v.verdict_after]}>{v.verdict_after}</b></span>
        <span className="text-ok">{v.fixed.length} advisory(ies) fixed</span>
        <span className={v.new_problems.length ? "text-crit" : "text-ok"}>{v.new_problems.length} new problem(s)</span>
        <span className="font-mono text-faint">{v.id}</span>
      </div>
      <div className="grid gap-3 lg:grid-cols-2">
        <div>
          <div className="mb-1 text-faint">Applied</div>
          {v.applied.map((a, i) => <div key={i} className={a.ok ? "text-ok" : "text-crit"}>{a.ok ? "✓" : "✗"} {a.component} <span className="text-faint">{a.output.slice(-120)}</span></div>)}
          {v.attempts.map((a, i) => <div key={i} className="text-high">retry {a.attempt}: {a.package}@{a.rejected} rejected ({a.because.slice(0, 2).join(", ")}) → {a.next}</div>)}
          {v.new_problems.map((p) => <div key={p} className="text-crit">new: {p}</div>)}
          {v.coverage_gaps?.map((gap, i) => <div key={i} className="text-high">Check incomplete · {gap}</div>)}
          {v.still_present.length > 0 && <div className="text-high">still present: {v.still_present.slice(0, 5).join(", ")}</div>}
        </div>
        <div>
          <div className="mb-1 text-faint">Before / after</div>
          <pre className="whitespace-pre-wrap font-mono text-[11.5px] text-muted">{v.diffstat || "no file changes"}</pre>
          <div className="mt-1 text-[11.5px] text-faint">Build and tests: {v.build_and_tests}</div>
        </div>
      </div>
      <div className="flex gap-3 text-[12px]">
        <button onClick={() => setShowPatch((x) => !x)} className="text-accent hover:underline">{showPatch ? "hide" : "show"} patch and PR text</button>
      </div>
      {showPatch && <div className="grid gap-3 lg:grid-cols-2">
        <pre className="max-h-[320px] overflow-auto rounded-lg bg-raised p-3 font-mono text-[11px]">{v.patch_preview || "(empty)"}</pre>
        <pre className="max-h-[320px] overflow-auto whitespace-pre-wrap rounded-lg bg-raised p-3 text-[11.5px]">{v.pr}</pre>
      </div>}
      {v.approved ? (
        <div className="rounded-lg border border-ok/30 bg-ok/8 px-3 py-2" data-testid="approved">
          <div className="flex items-center gap-2"><GitBranch size={15} className="text-ok" />Approved by <b>{v.approved.by}</b>: local branch <span className="font-mono">{v.approved.branch}</span> ({v.approved.commit.slice(0, 10)})</div>
          <div className="mt-1 text-[11.5px] text-muted">Not pushed or merged. To open a draft PR on your fork: <span className="font-mono">git push origin {v.approved.branch} && gh pr create --draft --head {v.approved.branch}</span></div>
        </div>
      ) : v.ok ? (
        <div className="flex flex-wrap items-center gap-2 rounded-lg border border-accent/30 bg-accent/5 px-3 py-2">
          <span className="font-medium">Human approval</span>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="your name" data-testid="approver"
            className="rounded-md border border-line bg-raised px-2 py-1 text-[12.5px] outline-none focus:border-accent/60" />
          <label className="flex items-center gap-1.5 text-[12px]"><input type="checkbox" checked={ok} onChange={(e) => setOk(e.target.checked)} data-testid="approve-confirm" />
            I reviewed the patch; create a local branch (nothing is pushed or merged)</label>
          <button onClick={approve} disabled={!name.trim() || !ok || busy} data-testid="approve-btn"
            className="ml-auto rounded-md bg-accent px-3 py-1.5 text-[13px] font-medium text-white enabled:hover:bg-accent/85 disabled:opacity-40">Approve & create branch</button>
          {err && <div className="w-full text-[12px] text-crit">{err}</div>}
        </div>
      ) : <div className="text-[12px] text-high">This fix cannot be approved: fix the failures above or pick different fixes.</div>}
    </section>
  );
}
