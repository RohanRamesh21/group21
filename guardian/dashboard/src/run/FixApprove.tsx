import { Fragment, useCallback, useEffect, useState } from "react";
import { GitDiff } from "@phosphor-icons/react";
import { api, Badge, jsonPost, q, SectionHead, type Sections } from "./shared";
import { REMEDY, RemediesUsed, semverJump } from "./scoring/Remedy";

type Candidate = { id: string; type: string; package?: string; file?: string; from?: string; to?: string; rationale: string;
  expected_risk_reduction: Record<string, number>; compatibility?: { note?: string; semver_jump?: string }; rollback?: string;
  finding_ids: string[]; sources?: { url: string; sha256: string }[] };

/* ---------------------------------------------------------------- compact building blocks */

const ROWS = 8;

function folderChips(files: string[]) {
  const by = new Map<string, number>();
  for (const f of files) { const d = f.includes("/") ? f.slice(0, f.lastIndexOf("/") + 1) : f; by.set(d, (by.get(d) ?? 0) + 1); }
  return [...by.entries()].sort((x, y) => y[1] - x[1]);
}

type FileDiff = { file: string; add: number; del: number; text: string };
function splitPatch(t: string): FileDiff[] {
  const parts = t.split(/^(?=diff --git )/m).filter((x) => x.trim());
  return parts.map((txt) => {
    const m = txt.match(/^diff --git a\/(\S+) b\/(\S+)/);
    const lines = txt.split("\n");
    return { file: m ? (m[2] === "/dev/null" ? m[1] : m[2]) : "patch", text: txt,
      add: lines.filter((l) => l.startsWith("+") && !l.startsWith("+++")).length, del: lines.filter((l) => l.startsWith("-") && !l.startsWith("---")).length };
  });
}

function budgetText(err?: string): string | null {
  const m = err?.match(/month budget: (\d+) used \+ up to (\d+) for this call > (\d+)/);
  if (!m) return err ?? null;
  const f = (x: string) => Number(x).toLocaleString();
  return `Not run: Guardian's own monthly AI cap is nearly used (${f(m[1])} of ${f(m[3])} tokens); this review could need up to ${f(m[2])}. Nothing was sent to the model.`;
}

function CandidateTable({ cands }: { cands: Candidate[] }) {
  const [tab, setTab] = useState<string>("all");
  const [all, setAll] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const counts = cands.reduce((m: Record<string, number>, c) => ({ ...m, [c.type]: (m[c.type] ?? 0) + 1 }), {});
  // actionable fixes first; "escalate" items need a person and would otherwise bury them
  const order = (t: string) => ["remove_package", "restore_lock_entry", "revert_change", "upgrade_to_fixed", "override_transitive", "pin_action_sha", "pin_image_digest", "escalate"].indexOf(t);
  const list = cands.filter((c) => (tab === "all" ? true : c.type === tab)).sort((x, y) => order(x.type) - order(y.type));
  const rows = all ? list : list.slice(0, ROWS);
  return (
    <div className="mt-3">
      <div role="tablist" className="flex flex-wrap gap-1.5 text-[11.5px]">
        {[["all", cands.length] as [string, number], ...Object.entries(counts).sort((x, y) => order(x[0]) - order(y[0]))].map(([t, n]) => (
          <button key={t} role="tab" aria-selected={tab === t} onClick={() => { setTab(t); setAll(false); }}
            className={`rounded-full px-2.5 py-1 ring-1 transition ${tab === t ? "bg-accent/15 text-accent ring-accent/40" : "text-muted ring-line hover:text-ink"}`}>
            {t === "all" ? "All" : (REMEDY[t] ?? REMEDY.escalate).short} <span className="font-mono text-faint">{n}</span></button>))}
      </div>
      <div className="mt-2 overflow-hidden rounded-lg ring-1 ring-line">
        <table className="w-full text-[12px]">
          <thead className="bg-canvas/60 text-left text-[10.5px] uppercase tracking-wide text-faint">
            <tr><th className="px-3 py-1.5 font-medium">Remedy</th><th className="px-3 py-1.5 font-medium">Target</th><th className="px-3 py-1.5 font-medium">Change</th><th className="hidden px-3 py-1.5 font-medium md:table-cell">Removes (forecast)</th></tr>
          </thead>
          <tbody>{rows.map((c) => {
            const r = REMEDY[c.type] ?? REMEDY.escalate, j = semverJump(c.from, c.to);
            const removes = Object.entries(c.expected_risk_reduction ?? {}).filter(([, n]) => n).map(([k, n]) => `${n} ${k}`).join(", ") || "—";
            return (<Fragment key={c.id}>
              <tr onClick={() => setOpen(open === c.id ? null : c.id)} className="cursor-pointer border-t border-line hover:bg-white/[0.02]">
                <td className="px-3 py-1.5"><span className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10.5px] font-medium ${r.tone}`}><r.Icon size={11} weight="bold" />{r.short}</span></td>
                <td className="max-w-[280px] truncate px-3 py-1.5 font-mono" title={c.package ?? c.file}>{c.package ?? c.file}</td>
                <td className="px-3 py-1.5 font-mono">{c.to ? <span className="text-ok">{c.from} → {c.to}</span> : <span className="text-faint">—</span>}
                  {j === "major" && <span className="ml-1.5 rounded bg-crit/10 px-1 font-sans text-[9.5px] text-crit">major</span>}</td>
                <td className="hidden px-3 py-1.5 text-faint md:table-cell">{removes}</td>
              </tr>
              {open === c.id && (
                <tr className="bg-canvas/40"><td colSpan={4} className="px-3 pb-2.5 pt-1 text-[11.5px] text-muted">
                  <p>{c.rationale}</p>
                  <p className="mt-1 text-faint">{c.compatibility?.note ? `compatibility: ${c.compatibility.note} · ` : ""}{c.rollback ? `rollback: ${c.rollback}` : ""}</p>
                </td></tr>)}
            </Fragment>);
          })}</tbody>
        </table>
      </div>
      {list.length > ROWS && <button onClick={() => setAll((x) => !x)} className="mt-2 text-[11.5px] text-accent hover:underline">{all ? "Show fewer" : `Show all ${list.length}`}</button>}
    </div>);
}

function PatchBrowser({ text }: { text: string }) {
  const files = splitPatch(text);
  const [sel, setSel] = useState(files[0]?.file ?? null);
  const cur = files.find((f) => f.file === sel);
  const add = files.reduce((n, f) => n + f.add, 0), del = files.reduce((n, f) => n + f.del, 0);
  return (
    <div className="mt-2 grid gap-2 rounded-lg bg-canvas/60 p-2 ring-1 ring-line md:grid-cols-[260px_minmax(0,1fr)]">
      <div>
        <p className="px-1 pb-1 text-[11px] text-faint">{files.length} file(s) · <span className="text-ok">+{add}</span> <span className="text-crit">−{del}</span></p>
        <ul className="scroll-thin max-h-72 space-y-0.5 overflow-auto">{files.map((f) => (
          <li key={f.file}><button onClick={() => setSel(f.file)} className={`flex w-full items-center gap-2 rounded px-1.5 py-1 text-left font-mono text-[11px] ${sel === f.file ? "bg-accent/12 text-ink" : "text-muted hover:bg-white/[0.03]"}`}>
            <span className="truncate" title={f.file}>{f.file.includes("/") ? `…/${f.file.split("/").pop()}` : f.file}</span>
            <span className="ml-auto shrink-0 tabular-nums"><span className="text-ok">+{f.add}</span> <span className="text-crit">−{f.del}</span></span></button></li>))}</ul>
      </div>
      <pre className="scroll-thin max-h-80 overflow-auto rounded-md bg-canvas p-3 font-mono text-[11px] leading-relaxed">{(cur?.text ?? "").split("\n").map((l, i) => (
        <div key={i} className={l.startsWith("+") && !l.startsWith("+++") ? "text-ok" : l.startsWith("-") && !l.startsWith("---") ? "text-crit" : l.startsWith("@@") ? "text-accent" : "text-muted"}>{l || " "}</div>))}</pre>
    </div>);
}

function FixPlan({ project, s, refresh }: { project: string | null; s: Sections; refresh: () => void }) {
  const rem = s.remediation;
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [diff, setDiff] = useState<string | null>(null);
  const propose = async () => {
    setBusy(true); setErr(null);
    try { await api("/api/fix-plan", jsonPost({ project, include: [] })); refresh(); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };
  const [seenPatch, setSeenPatch] = useState(false);
  const showDiff = async () => { if (diff !== null) { setDiff(null); return; } const p = await api(`/api/fix-plan${q(project)}`); setDiff(p.patch_text || "(empty patch)"); setSeenPatch(true); };
  const files: string[] = rem.patch?.files ?? [];
  return (
    <section className="panel p-4" aria-labelledby="fix-h">
      <header className="flex items-baseline justify-between">
        <h2 id="fix-h" className="text-[13px] font-semibold">Recommended fix <span className="font-normal text-faint">· {rem.candidates?.length ?? 0} item(s), one patch</span></h2>
        {rem.status !== "not_started" && <span className="font-mono text-[11px] text-faint" title="SHA-256 of the exact patch you approve">patch {rem.patch?.patch_sha256?.slice(0, 12)}</span>}
      </header>
      {rem.status === "not_started" ? (
        <div className="mt-3">
          <p className="max-w-[60ch] text-[12.5px] text-muted">Fixes are computed from advisory ranges and the npm registry (no AI), then combined into one patch you can review.</p>
          <button disabled={busy} onClick={propose} className="mt-3 rounded-lg bg-accent px-3 py-1.5 text-[12.5px] font-medium text-white transition hover:brightness-110 active:scale-[0.98] disabled:opacity-50">{busy ? "Computing fixes…" : "Propose fixes"}</button>
        </div>
      ) : (<>
        <CandidateTable cands={rem.candidates as Candidate[]} />
        <div className="mt-4 flex flex-wrap items-center gap-1.5 text-[11.5px]">
          <span className="mr-1 text-faint">Files changed</span>
          {folderChips(files).map(([d, n]) => <span key={d} className="rounded-md bg-raised px-2 py-0.5 font-mono text-muted ring-1 ring-line">{d}{n > 1 ? <span className="ml-1 text-faint">×{n}</span> : null}</span>)}
          <button onClick={showDiff} className="ml-auto inline-flex items-center gap-1 rounded-md px-2.5 py-1 text-accent ring-1 ring-accent/40 transition hover:bg-accent/10"><GitDiff /> {diff === null ? "Review the patch" : "Hide patch"}</button>
        </div>
        {diff !== null && <PatchBrowser text={diff} />}
        <FixReview project={project} review={rem.review} refresh={refresh} names={Object.fromEntries((rem.candidates as Candidate[]).map((c) => [c.id, c.package ?? c.file ?? c.id]))} />
        <ApprovalPanel project={project} seenPatch={seenPatch} openPatch={() => { if (diff === null) showDiff(); }} refresh={refresh} />
      </>)}
      {err && <p role="alert" className="mt-2 text-[12px] text-crit">{err}</p>}
    </section>);
}

type ApprovalView = { contract: Record<string, string | null>; approval: any; valid: boolean; reason: string | null; audit_ok: boolean; audit_entries: number };

/* Human approval: shows exactly what is being signed, the live validity of the latest decision, and the form.
   The server enforces the same rules (name, reason, reviewed patch for approve; any change invalidates). */
function ApprovalPanel({ project, seenPatch, openPatch, refresh }: { project: string | null; seenPatch: boolean; openPatch: () => void; refresh: () => void }) {
  const [v, setV] = useState<ApprovalView | null>(null);
  const [who, setWho] = useState("");
  const [why, setWhy] = useState("");
  const [hours, setHours] = useState(24);
  const [reviewed, setReviewed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const load = useCallback(() => api(`/api/approval${q(project)}`).then(setV).catch((e) => setErr((e as Error).message)), [project]);
  useEffect(() => { load(); }, [load]);
  const decide = async (decision: "approve" | "reject") => {
    if (!who.trim() || !why.trim()) { setErr("Enter your name and a reason before deciding."); return; }
    if (decision === "approve" && !reviewed) { setErr("Open the patch and confirm you reviewed it before approving."); return; }
    setBusy(true); setErr(null);
    try { await api("/api/approval", jsonPost({ project, decision, approver: who, reason: why, hours, reviewed: decision === "approve" ? reviewed : false })); await load(); refresh(); }
    catch (e) { setErr((e as Error).message); } finally { setBusy(false); }
  };
  if (!v) return <div className="mt-4 h-24 animate-pulse rounded-lg bg-raised" />;
  const a = v.approval, k = v.contract;
  const short = (x?: string | null) => (x ? x.slice(0, 12) : "—");
  return (
    <div className="mt-4 border-t border-line pt-4">
      <h3 className="mb-2 flex items-center gap-2 text-[12.5px] font-semibold">Your decision <Badge kind="human" /></h3>
      {a && (
        <div className={`mb-3 rounded-lg p-3 text-[12.5px] ring-1 ${v.valid ? "bg-ok/8 ring-ok/30" : "bg-high/8 ring-high/30"}`}>
          <p><b>{a.decision === "approve" ? "Approved" : "Rejected"}</b> by <b>{a.approver}</b>: “{a.reason}”
            <span className="ml-2 text-[11px] text-faint">{new Date(a.created * 1000).toLocaleString()} · expires {new Date(a.expires * 1000).toLocaleString()}{a.reviewed_patch ? " · patch reviewed" : ""}</span></p>
          <p className={`mt-1 text-[12px] ${v.valid ? "text-ok" : "text-high"}`}>{v.valid ? "Valid: authorises validation of exactly this patch." : `Not valid: ${v.reason}`}</p>
        </div>)}
      <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.3fr)]">
      <dl className="grid content-start grid-cols-[110px_minmax(0,1fr)] gap-x-3 gap-y-0.5 rounded-lg bg-canvas/60 p-3 font-mono text-[11px] ring-1 ring-line">
        <dt className="font-sans text-faint">You sign</dt><dd className="font-sans text-muted">these exact values; any change makes the approval invalid</dd>
        <dt className="text-faint">base commit</dt><dd>{short(k.base_sha)}</dd>
        <dt className="text-faint">head commit</dt><dd>{short(k.head_sha)}</dd>
        <dt className="text-faint">patch SHA-256</dt><dd>{short(k.patch_sha256)}</dd>
        <dt className="text-faint">policy</dt><dd>{short(k.policy_sha256)}</dd>
        <dt className="text-faint">validation profile</dt><dd>{k.profile} · {short(k.profile_sha256)}</dd>
        <dt className="font-sans text-faint">audit log</dt><dd className={v.audit_ok ? "text-ok" : "text-crit"}>{v.audit_ok ? `hash chain intact · ${v.audit_entries} entries` : "hash chain BROKEN"}</dd>
      </dl>
      {v.valid ? <div /> : (<div>
        <div className="grid gap-2 sm:grid-cols-[160px_minmax(0,1fr)_120px]">
          <input aria-label="Your name" value={who} onChange={(e) => setWho(e.target.value)} placeholder="Your name" className="rounded-md bg-canvas px-2.5 py-1.5 text-[12.5px] outline-none ring-1 ring-line focus:ring-accent" />
          <input aria-label="Reason" value={why} onChange={(e) => setWhy(e.target.value)} placeholder="Why you approve or reject" className="rounded-md bg-canvas px-2.5 py-1.5 text-[12.5px] outline-none ring-1 ring-line focus:ring-accent" />
          <select aria-label="Approval lasts" value={hours} onChange={(e) => setHours(Number(e.target.value))} className="rounded-md bg-canvas px-2 py-1.5 text-[12px] ring-1 ring-line">
            <option value={1}>valid 1 hour</option><option value={8}>valid 8 hours</option><option value={24}>valid 24 hours</option><option value={72}>valid 3 days</option>
          </select>
        </div>
        <label className="mt-2 flex items-center gap-2 text-[12px] text-muted">
          <input type="checkbox" checked={reviewed} disabled={!seenPatch} onChange={(e) => setReviewed(e.target.checked)} className="accent-[var(--color-accent)]" />
          I reviewed the exact patch above
          {!seenPatch && <button onClick={openPatch} className="text-accent hover:underline">(open the patch first)</button>}
        </label>
        <div className="mt-2 flex gap-2">
          <button disabled={busy || !reviewed} onClick={() => decide("approve")} className="rounded-md bg-ok/90 px-3 py-1.5 text-[12.5px] font-medium text-canvas transition hover:bg-ok active:scale-[0.98] disabled:opacity-40">Approve</button>
          <button disabled={busy} onClick={() => decide("reject")} className="rounded-md px-3 py-1.5 text-[12.5px] text-crit ring-1 ring-crit/40 transition hover:bg-crit/10 active:scale-[0.98] disabled:opacity-50">Reject</button>
        </div></div>)}
      </div>
      {err && <p role="alert" className="mt-2 text-[12px] text-crit">{err}</p>}
    </div>);
}

function FixReview({ project, review, refresh, names }: { project: string | null; review: any; refresh: () => void; names: Record<string, string> }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const run = async () => { setBusy(true); setErr(null); try { await api("/api/fix-plan/review", jsonPost({ project, include: [] })); refresh(); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); } };
  if (!review || (review.status !== "done" && review.status !== "partial")) return (
    <div className="mt-3 flex flex-wrap items-center gap-2 text-[12px] text-muted">
      <button disabled={busy} onClick={run} className="rounded-md px-2.5 py-1 text-accent ring-1 ring-accent/40 transition hover:bg-accent/10 active:scale-[0.98] disabled:opacity-50">{busy ? "Reviewing…" : "AI review of this plan (1 call)"}</button>
      {review?.status === "unavailable" && <span className="text-high">{budgetText(review.error)}</span>}
      {err && <span role="alert" className="text-crit">{err}</span>}
    </div>);
  return (
    <div className="mt-3 rounded-lg bg-accent/5 p-3 text-[12px]">
      <div className="flex flex-wrap items-center gap-2"><Badge kind="ai" /><span className="text-muted">Fixer explains, Verifier questions · checked against the plan · cannot change the patch</span>
        {review.coverage && <span className="ml-auto text-[11px] text-faint">{review.coverage.reviewed}/{review.coverage.actionable} fixes reviewed{review.coverage.needs_person ? ` · ${review.coverage.needs_person} need a person` : ""}{review.coverage.not_reviewed?.length ? ` · ${review.coverage.not_reviewed.length} not reviewed (rule rationale stands)` : ""}</span>}</div>
      <ul className="scroll-thin mt-2 max-h-64 space-y-1 overflow-auto">{review.explanations.map((x: any, i: number) => <li key={"e" + i}><span className="font-mono text-ink">{names[x.candidate_id] ?? x.candidate_id}:</span> {x.text}</li>)}</ul>
      {review.challenges.length > 0 && <ul className="mt-2 space-y-1">{review.challenges.map((x: any, i: number) => <li key={"c" + i} className="text-high">⚑ <span className="font-mono">{names[x.candidate_id] ?? x.candidate_id}:</span> {x.concern}</li>)}</ul>}
      {review.rejected?.length > 0 && <p className="mt-1 text-[11px] text-faint">{review.rejected.length} sentence(s) dropped: mentioned values not in the plan</p>}
    </div>);
}


export function FixApprove({ s, project, refresh }: { s: Sections; project: string | null; refresh: () => void }) {
  return (
    <div className="flex flex-col gap-4">
      <SectionHead n={4} title="Fix and approve" sub="Fix versions are computed from advisory ranges and the npm registry (no AI), then combined into one patch. The Fixer may explain it, never change it. Your approval is bound to the patch's SHA-256, both commits, the policy and the validation profile." />
      <RemediesUsed s={s} />
      <FixPlan project={project} s={s} refresh={refresh} />
    </div>);
}
