import { motion } from "motion/react";
import { useCallback, useEffect, useState } from "react";
import { GitDiff } from "@phosphor-icons/react";
import { api, Badge, jsonPost, q, SectionHead, type Sections } from "./shared";

type Candidate = { id: string; type: string; package?: string; file?: string; from?: string; to?: string; rationale: string;
  expected_risk_reduction: Record<string, number>; compatibility?: { note?: string; semver_jump?: string }; rollback?: string;
  finding_ids: string[]; sources?: { url: string; sha256: string }[] };

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
  return (
    <section className="panel p-4" aria-labelledby="fix-h">
      <header className="flex items-baseline justify-between">
        <h2 id="fix-h" className="text-[13px] font-semibold">Recommended fix</h2>
        {rem.status !== "not_started" && <span className="font-mono text-[11px] text-faint" title="SHA-256 of the exact patch you approve">patch {rem.patch?.patch_sha256?.slice(0, 12)}</span>}
      </header>
      {rem.status === "not_started" ? (
        <div className="mt-3">
          <p className="max-w-[60ch] text-[12.5px] text-muted">Fixes are computed from advisory ranges and the npm registry (no AI), then combined into one patch you can review.</p>
          <button disabled={busy} onClick={propose} className="mt-3 rounded-lg bg-accent px-3 py-1.5 text-[12.5px] font-medium text-white transition hover:brightness-110 active:scale-[0.98] disabled:opacity-50">{busy ? "Computing fixes…" : "Propose fixes"}</button>
        </div>
      ) : (<>
        <ul className="mt-3 space-y-2">
          {(rem.candidates as Candidate[]).map((c) => (
            <motion.li key={c.id} layout className="rounded-lg bg-raised px-3 py-2.5">
              <div className="flex items-center gap-2 text-[12.5px]">
                <span className="rounded bg-accent/12 px-1.5 py-0.5 font-mono text-[10.5px] text-accent">{c.type}</span>
                <span className="font-mono">{c.package ?? c.file}{c.to ? ` ${c.from} → ${c.to}` : ""}</span>
              </div>
              <p className="mt-1 text-[12px] text-muted">{c.rationale}</p>
              <p className="mt-1 text-[11.5px] text-faint tabular-nums">removes {Object.entries(c.expected_risk_reduction).filter(([, n]) => n).map(([k, n]) => `${n} ${k}`).join(", ") || "nothing measurable"} (forecast){c.compatibility?.note ? ` · ${c.compatibility.note}` : ""}{c.rollback ? ` · rollback: ${c.rollback}` : ""}</p>
            </motion.li>))}
        </ul>
        <div className="mt-2 flex flex-wrap items-center gap-3 text-[11.5px] text-muted">
          <span>files: {(rem.patch?.files ?? []).join(", ") || "none"}</span>
          <button onClick={showDiff} className="inline-flex items-center gap-1 text-accent hover:underline"><GitDiff /> {diff === null ? "Show patch" : "Hide patch"}</button>
        </div>
        {diff !== null && <pre className="scroll-thin mt-2 max-h-72 overflow-auto rounded-lg bg-canvas p-3 font-mono text-[11px] leading-relaxed">{diff.split("\n").map((l, i) => <div key={i} className={l.startsWith("+") && !l.startsWith("+++") ? "text-ok" : l.startsWith("-") && !l.startsWith("---") ? "text-crit" : "text-muted"}>{l || " "}</div>)}</pre>}
        <FixReview project={project} review={rem.review} refresh={refresh} names={Object.fromEntries((rem.candidates as Candidate[]).map((c) => [c.id, c.package ?? c.file ?? c.id]))} />
        {rem.review?.status !== "done" && rem.pending?.length > 0 && <p className="mt-2 text-[11px] text-faint">Pending: {rem.pending.join("; ")}</p>}
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
      <dl className="mb-3 grid grid-cols-[110px_minmax(0,1fr)] gap-x-3 gap-y-0.5 rounded-lg bg-canvas/60 p-3 font-mono text-[11px] ring-1 ring-line">
        <dt className="font-sans text-faint">You sign</dt><dd className="font-sans text-muted">these exact values; any change makes the approval invalid</dd>
        <dt className="text-faint">base commit</dt><dd>{short(k.base_sha)}</dd>
        <dt className="text-faint">head commit</dt><dd>{short(k.head_sha)}</dd>
        <dt className="text-faint">patch SHA-256</dt><dd>{short(k.patch_sha256)}</dd>
        <dt className="text-faint">policy</dt><dd>{short(k.policy_sha256)}</dd>
        <dt className="text-faint">validation profile</dt><dd>{k.profile} · {short(k.profile_sha256)}</dd>
        <dt className="font-sans text-faint">audit log</dt><dd className={v.audit_ok ? "text-ok" : "text-crit"}>{v.audit_ok ? `hash chain intact · ${v.audit_entries} entries` : "hash chain BROKEN"}</dd>
      </dl>
      {!v.valid && (<>
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
        </div></>)}
      {err && <p role="alert" className="mt-2 text-[12px] text-crit">{err}</p>}
    </div>);
}

function FixReview({ project, review, refresh, names }: { project: string | null; review: any; refresh: () => void; names: Record<string, string> }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const run = async () => { setBusy(true); setErr(null); try { await api("/api/fix-plan/review", jsonPost({ project, include: [] })); refresh(); } catch (e) { setErr((e as Error).message); } finally { setBusy(false); } };
  if (!review || review.status !== "done") return (
    <div className="mt-3 flex flex-wrap items-center gap-2 text-[12px] text-muted">
      <button disabled={busy} onClick={run} className="rounded-md px-2.5 py-1 text-accent ring-1 ring-accent/40 transition hover:bg-accent/10 active:scale-[0.98] disabled:opacity-50">{busy ? "Reviewing…" : "AI review of this plan (1 call)"}</button>
      {review?.status === "unavailable" && <span className="text-high">last attempt: {review.error}</span>}
      {err && <span role="alert" className="text-crit">{err}</span>}
    </div>);
  return (
    <div className="mt-3 rounded-lg bg-accent/5 p-3 text-[12px]">
      <div className="flex items-center gap-2"><Badge kind="ai" /><span className="text-muted">Fixer explains, Verifier questions · checked against the plan · cannot change the patch</span></div>
      <ul className="mt-2 space-y-1">{review.explanations.map((x: any, i: number) => <li key={"e" + i}><span className="font-mono text-ink">{names[x.candidate_id] ?? x.candidate_id}:</span> {x.text}</li>)}</ul>
      {review.challenges.length > 0 && <ul className="mt-2 space-y-1">{review.challenges.map((x: any, i: number) => <li key={"c" + i} className="text-high">⚑ <span className="font-mono">{names[x.candidate_id] ?? x.candidate_id}:</span> {x.concern}</li>)}</ul>}
      {review.rejected?.length > 0 && <p className="mt-1 text-[11px] text-faint">{review.rejected.length} sentence(s) dropped: mentioned values not in the plan</p>}
    </div>);
}


export function FixApprove({ s, project, refresh }: { s: Sections; project: string | null; refresh: () => void }) {
  return (
    <div className="flex flex-col gap-4">
      <SectionHead n={4} title="Fix and approve" sub="Fix versions are computed from advisory ranges and the npm registry (no AI), then combined into one patch. The Fixer may explain it, never change it. Your approval is bound to the patch's SHA-256, both commits, the policy and the validation profile." />
      <FixPlan project={project} s={s} refresh={refresh} />
    </div>);
}
