import { motion } from "motion/react";
import { useEffect, useState } from "react";
import { ArrowRight, CheckCircle, DownloadSimple, Info, ShieldCheck, ShieldWarning, Warning } from "@phosphor-icons/react";
import { getJSON, q, type Context, type Level } from "../api";
import type { View } from "../route";
import type { Risk } from "../types";
import { CountUp, RISK, RiskTag, ease } from "../ui";

interface Top { id: string; title: string; level: Risk; decision: string; score: number; label: string; kind: string }

const LEVELS: Level[] = ["critical", "high", "medium", "low"];
const VERDICT = {
  block: { title: "Block this merge", Icon: ShieldWarning, cls: "border-crit/40 bg-crit/[0.07]", text: "text-crit", glow: true },
  review: { title: "Needs a human decision", Icon: Warning, cls: "border-high/40 bg-high/[0.07]", text: "text-high", glow: false },
  allow: { title: "No new high or critical risk", Icon: CheckCircle, cls: "border-ok/40 bg-ok/[0.06]", text: "text-ok", glow: false },
};
const item = { initial: { opacity: 0, y: 14 }, animate: { opacity: 1, y: 0, transition: { duration: 0.5, ease } } };
const sum = (o?: Partial<Record<Level, number>>) => LEVELS.reduce((n, l) => n + (o?.[l] ?? 0), 0);

function Card({ title, children, className = "", aside }: { title: string; children: React.ReactNode; className?: string; aside?: React.ReactNode }) {
  return (
    <motion.section variants={item} className={`panel flex flex-col gap-3 px-5 py-4 ${className}`}>
      <div className="flex items-baseline justify-between gap-2"><h3 className="text-[13.5px] font-medium">{title}</h3>{aside}</div>
      {children}
    </motion.section>
  );
}

function Stat({ label, value, sub, tone = "" }: { label: string; value: number; sub: string; tone?: string }) {
  return (
    <motion.div variants={item} className="flex flex-col gap-0.5 rounded-xl border border-line bg-surface/70 px-4 py-3">
      <span className="text-[11.5px] text-muted">{label}</span>
      <span className={`font-mono text-[26px] font-medium leading-tight tracking-tight ${tone}`}><CountUp value={value} /></span>
      <span className="truncate text-[11px] text-faint">{sub}</span>
    </motion.div>
  );
}

/** Headline of one scan: verdict, numbers, what the change introduced, and where to look next. */
export function ResultsOverview({ id, ctx, onView }: { id: string; ctx: Context | null; onView: (v: View) => void }) {
  const [top, setTop] = useState<Top[] | null>(null);
  useEffect(() => {
    getJSON<{ findings: Top[] }>(`/api/scores${q(id)}`).then((s) => setTop(s.findings.slice(0, 6))).catch(() => setTop([]));
  }, [id]);
  if (!ctx) return <div className="grid gap-4 md:grid-cols-3">{[0, 1, 2].map((i) => <div key={i} className="panel h-40 animate-pulse" />)}</div>;

  const v = VERDICT[(ctx.verdict ?? "review") as keyof typeof VERDICT] ?? VERDICT.review;
  const vul = ctx.vulnerabilities;
  const newVul = sum(vul.introduced), oldVul = sum(vul.pre_existing), fixedVul = sum(vul.fixed);
  const newTotal = newVul + ctx.signal_counts.introduced + (ctx.ci.introduced ?? 0);
  const maxBar = Math.max(1, ...LEVELS.map((l) => (vul.introduced[l] ?? 0) + (vul.pre_existing[l] ?? 0)));
  const ecos = Object.entries(ctx.inventory.ecosystems ?? {}).sort((a, b) => b[1] - a[1]);
  const ecoMax = Math.max(1, ...ecos.map(([, n]) => n));
  const fullAllow = !ctx.compare && ctx.verdict === "allow";

  return (
    <motion.div initial="initial" animate="animate" variants={{ animate: { transition: { staggerChildren: 0.06 } } }} className="flex flex-col gap-4">
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
        <motion.section variants={item} className={`relative overflow-hidden rounded-xl border px-6 py-5 ${fullAllow ? "border-line bg-surface" : v.cls} ${v.glow ? "glow-crit" : ""}`}>
          {fullAllow ? (
            <div className="flex items-start gap-3"><Info size={26} className="mt-0.5 shrink-0 text-accent" />
              <div><div className="text-2xl font-semibold tracking-tight">Full scan: nothing blocking</div>
                <p className="mt-1 text-[13px] text-muted">There was no earlier version to compare, so every finding counts as already present. Compare a base and head to get a merge verdict.</p></div></div>
          ) : (
            <div className="flex items-start gap-3.5">
              <motion.span initial={{ scale: 0.5, rotate: -20 }} animate={{ scale: 1, rotate: 0 }} transition={{ type: "spring", stiffness: 300, damping: 14, delay: 0.15 }}>
                <v.Icon size={34} weight="duotone" className={`shrink-0 ${v.text}`} />
              </motion.span>
              <div className="min-w-0">
                <div className={`text-[11.5px] uppercase tracking-wider ${v.text}`}>Recommendation{!ctx.compare && " · full scan"}</div>
                <div className={`text-3xl font-semibold tracking-tight ${v.text}`}>{v.title}</div>
                <motion.ul initial="initial" animate="animate" variants={{ animate: { transition: { staggerChildren: 0.07, delayChildren: 0.3 } } }} className="mt-2.5 space-y-1">
                  {ctx.reasons.slice(0, 5).map((r) => (
                    <motion.li key={r} variants={{ initial: { opacity: 0, x: -8 }, animate: { opacity: 1, x: 0 } }} className="flex gap-2 text-[13px] leading-snug text-ink/85">
                      <span className={`mt-1.5 size-1.5 shrink-0 rounded-full ${v.text} bg-current`} /><span className="min-w-0">{r}</span>
                    </motion.li>))}
                </motion.ul>
                <div className="mt-3 text-[11.5px] text-faint">Final verdict = the stricter of the risk score and policy-as-code{ctx.policy ? ` (policy: ${ctx.policy})` : ""}. A human makes the merge decision.</div>
              </div>
            </div>
          )}
        </motion.section>
        <motion.div variants={{ animate: { transition: { staggerChildren: 0.05 } } }} className="grid grid-cols-2 gap-3 sm:grid-cols-3">
          <Stat label="Components" value={ctx.inventory.packages ?? 0} sub={`${ctx.inventory.unique_name_versions ?? 0} unique name@version`} />
          <Stat label="Direct" value={ctx.inventory.direct ?? 0} sub={`${ctx.inventory.transitive ?? 0} transitive`} />
          <Stat label="Ship to production" value={ctx.inventory.runtime ?? 0} sub={`${ctx.inventory.dev_only ?? 0} dev-only`} />
          <Stat label="Advisories" value={newVul + oldVul} sub={`${newVul} new · ${fixedVul} fixed by this change`} tone={newVul ? "text-high" : ""} />
          <Stat label="New in this change" value={newTotal} sub={ctx.compare ? "vulnerabilities, signals, CI risks" : "full scan: nothing to compare"} tone={newTotal ? "text-crit" : "text-ok"} />
          <Stat label="Install scripts" value={ctx.inventory.install_scripts ?? 0} sub="run code at install time" />
        </motion.div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title={ctx.compare ? "Attack signals introduced by this change" : "Attack signals"} aside={<span className="text-[11.5px] text-faint">{ctx.signal_counts.pre_existing} more already present</span>}>
          {ctx.signals.length ? (
            <ul className="flex flex-col gap-2">
              {ctx.signals.map((s, i) => (
                <motion.li key={i} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.25 + i * 0.06, duration: 0.35 }}
                  className={`rounded-lg border px-3 py-2 ${s.hard_signal ? "border-crit/30 bg-crit/[0.06]" : "border-line bg-raised/60"}`}>
                  <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
                    <RiskTag risk={s.severity as Risk} /><span className="font-medium">{s.type.replace(/_/g, " ")}</span>
                    {s.hard_signal && <span className="rounded bg-crit/15 px-1.5 text-[10.5px] text-crit">hard signal</span>}
                    <span className="truncate font-mono text-[11.5px] text-muted">{s.component}</span>
                  </div>
                  <div className="mt-0.5 text-[12px] leading-snug text-ink/75">{s.summary}</div>
                  {s.file && <div className="mt-0.5 font-mono text-[10.5px] text-faint">{s.file}{s.line ? `:${s.line}` : ""}</div>}
                </motion.li>))}
            </ul>
          ) : (
            <div className="flex items-center gap-2 rounded-lg bg-ok/[0.06] px-3 py-3 text-[12.5px] text-ok"><ShieldCheck size={17} />
              {ctx.compare ? "No typosquats, tampered lockfiles, new install scripts, registry redirects or unpinned actions were introduced." : "Full scan: signals are listed as already present on the Risk scores view."}</div>
          )}
        </Card>

        <Card title="Known vulnerabilities by severity" aside={<button onClick={() => onView("scores")} className="flex items-center gap-1 text-[12px] text-accent hover:underline">scores <ArrowRight size={12} /></button>}>
          <div className="flex flex-col gap-2.5">
            {LEVELS.map((l, i) => {
              const n = vul.introduced[l] ?? 0, o = vul.pre_existing[l] ?? 0;
              return (
                <div key={l} className="grid grid-cols-[72px_1fr_88px] items-center gap-3 text-[12px]">
                  <RiskTag risk={l} />
                  <div className="relative h-3 overflow-hidden rounded-full bg-white/5">
                    <motion.div className="absolute inset-y-0 left-0 rounded-full" style={{ background: `${RISK[l].hex}55` }}
                      initial={{ width: 0 }} animate={{ width: `${((n + o) / maxBar) * 100}%` }} transition={{ duration: 0.9, delay: 0.2 + i * 0.08, ease }} />
                    <motion.div className="absolute inset-y-0 left-0 rounded-full" style={{ background: RISK[l].hex }}
                      initial={{ width: 0 }} animate={{ width: `${(n / maxBar) * 100}%` }} transition={{ duration: 0.9, delay: 0.35 + i * 0.08, ease }} />
                  </div>
                  <span className="text-right font-mono text-muted"><span className={n ? "text-ink" : ""}>{n} new</span> · {o}</span>
                </div>);
            })}
            <div className="text-[11px] text-faint">Solid = introduced by this change · faint = already present. Sources: {[ctx.scanners.osv != null && "OSV.dev", ctx.scanners.grype != null && "Grype"].filter(Boolean).join(" + ") || "OSV.dev + Grype"}
              {Object.keys(ctx.scanner_errors).length > 0 && <span className="text-high"> · not checked: {Object.keys(ctx.scanner_errors).join(", ")}</span>}</div>
          </div>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card title={ctx.compare ? "What changed" : "Scanned commit"}>
          {ctx.compare ? (
            <div className="flex flex-col gap-2 text-[12.5px]">
              <div className="flex gap-4 font-mono">
                <span><b className="text-ink">{ctx.changes.files}</b> <span className="text-muted">files</span></span>
                <span className="text-ok">+{ctx.changes.added}</span><span className="text-med">~{ctx.changes.updated}</span><span className="text-crit">−{ctx.changes.removed}</span>
                <span className="text-muted">packages</span>
              </div>
              {(["added", "updated", "removed"] as const).map((k) => ctx.package_changes[k].length > 0 && (
                <div key={k} className="flex flex-wrap gap-1">
                  {ctx.package_changes[k].map((p) => (
                    <span key={p} className={`rounded px-1.5 py-0.5 font-mono text-[11px] ${k === "added" ? "bg-ok/10 text-ok" : k === "updated" ? "bg-med/10 text-med" : "bg-crit/10 text-crit"}`}>{p}</span>))}
                </div>))}
              {!ctx.changes.added && !ctx.changes.updated && !ctx.changes.removed && <span className="text-muted">No package was added, updated or removed.</span>}
            </div>
          ) : <div className="font-mono text-[12.5px] text-muted">{ctx.head} · {ctx.head_commit}</div>}
        </Card>

        <Card title="Ecosystems" aside={<span className="text-[11.5px] text-faint">{ctx.inventory.manifests} manifests · {ctx.inventory.lockfiles} lockfiles</span>}>
          <div className="flex flex-col gap-1.5">
            {ecos.slice(0, 6).map(([e, n], i) => (
              <div key={e} className="grid grid-cols-[80px_1fr_52px] items-center gap-2 text-[12px]">
                <span className="truncate font-mono text-muted">{e}</span>
                <div className="h-2 overflow-hidden rounded-full bg-white/5"><motion.div className="h-full rounded-full bg-accent/70" initial={{ width: 0 }} animate={{ width: `${(n / ecoMax) * 100}%` }} transition={{ duration: 0.8, delay: 0.3 + i * 0.06, ease }} /></div>
                <span className="text-right font-mono">{n.toLocaleString()}</span>
              </div>))}
            {!ecos.length && <span className="text-[12.5px] text-muted">No components found.</span>}
          </div>
        </Card>

        <Card title="Supply-chain artefacts">
          <div className="flex flex-col gap-2 text-[12.5px]">
            <div className="flex flex-wrap gap-1.5">
              {ctx.sboms.map((f) => (
                <a key={f} href={`/api/sbom${q(id) ? `${q(id)}&` : "?"}fmt=${f}`} className="inline-flex items-center gap-1.5 rounded-md bg-raised px-2 py-1 text-[11.5px] ring-1 ring-inset ring-line transition-colors hover:text-accent hover:ring-accent/40">
                  <DownloadSimple size={13} />{f === "guardian" ? "Guardian CycloneDX" : f === "cyclonedx" ? "Syft CycloneDX" : "Syft SPDX"}</a>))}
              {!ctx.sboms.length && <span className="text-muted">No SBOM file was produced.</span>}
            </div>
            <div className="text-muted">CI actions <b className="font-mono text-ink">{ctx.ci.actions?.pinned ?? 0}/{ctx.ci.actions?.total ?? 0}</b> SHA-pinned · base images <b className="font-mono text-ink">{ctx.ci.images?.pinned ?? 0}/{ctx.ci.images?.total ?? 0}</b> digest-pinned</div>
            {ctx.sbom_agreement_pct != null && <div className="text-muted">SBOM agrees with the lockfile: <b className="font-mono text-ink">{ctx.sbom_agreement_pct}%</b></div>}
            <div className="text-muted">Sandbox: <span className="text-ink">{ctx.sandbox.engine ?? ctx.sandbox.mode ?? "unknown"}</span>{ctx.sandbox.all_isolated ? <span className="text-ok"> · every tool isolated</span> : ctx.sandbox.mode ? <span className="text-high"> · not all tools isolated</span> : null}</div>
          </div>
        </Card>
      </div>

      <Card title="Top risks" aside={<button onClick={() => onView("graph")} className="flex items-center gap-1 text-[12px] text-accent hover:underline">see them in the graph <ArrowRight size={12} /></button>}>
        {top === null ? <div className="h-16 animate-pulse rounded-lg bg-white/[0.03]" /> : top.length ? (
          <ul className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
            {top.map((f, i) => (
              <motion.li key={f.id} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 + i * 0.05 }}>
                <button onClick={() => onView("scores")} className="flex w-full items-center gap-2.5 rounded-lg border border-line bg-raised/60 px-3 py-2 text-left transition-colors hover:border-accent/40">
                  <RiskTag risk={f.level} className="shrink-0" />
                  <span className="min-w-0 flex-1"><span className="block truncate font-mono text-[12px]">{f.title}</span>
                    <span className="block text-[11px] text-muted">{f.label === "introduced" ? "new in this change" : "already present"} · {f.kind.replace("_", " ")}</span></span>
                  <span className="font-mono text-[13px]">{f.score.toFixed(0)}</span>
                </button>
              </motion.li>))}
          </ul>
        ) : <div className="text-[12.5px] text-muted">No findings to rank.</div>}
      </Card>
    </motion.div>
  );
}
