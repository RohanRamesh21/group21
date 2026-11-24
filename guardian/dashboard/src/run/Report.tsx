import { AnimatePresence, motion } from "motion/react";
import { useEffect, useState } from "react";
import { FileArrowDown, FileCode, Fingerprint, LinkSimple } from "@phosphor-icons/react";
import { spring } from "../ui";
import { q, SectionHead, st, type Sections } from "./shared";

function LiveEvents() {
  const [events, setEvents] = useState<any[]>([]);
  const [online, setOnline] = useState(false);
  useEffect(() => {
    const es = new EventSource("/api/trigger/stream");
    es.onopen = () => setOnline(true);
    es.onerror = () => setOnline(false);
    es.onmessage = () => undefined;
    const kinds = ["run_queued", "scan_started", "scan_finished", "run_stale", "event_ignored"];
    const on = (e: MessageEvent) => setEvents((xs) => [JSON.parse(e.data), ...xs].slice(0, 30));
    kinds.forEach((k) => es.addEventListener(k, on as EventListener));
    return () => es.close();
  }, []);
  return (
    <section className="panel p-4" aria-labelledby="live-h">
      <header className="flex items-center justify-between">
        <h2 id="live-h" className="text-[13px] font-semibold">Pull-request events</h2>
        <span className={`flex items-center gap-1.5 text-[11px] ${online ? "text-ok" : "text-faint"}`}><span className={`size-1.5 rounded-full ${online ? "bg-ok" : "bg-faint"}`} />{online ? "connected" : "offline"}</span>
      </header>
      {events.length === 0 ? <p className="mt-2 text-[12px] text-muted">No PR events yet. They appear here when GitHub Actions (or the polling backup) sends one.</p> : (
        <ul className="mt-2 space-y-1 text-[12px]">
          <AnimatePresence initial={false}>{events.map((e) => (
            <motion.li key={e.seq} initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} className="flex gap-2 font-mono text-[11.5px]">
              <span className="text-faint tabular-nums">#{e.seq}</span><span className="text-accent">{e.kind}</span><span className="truncate text-muted">{e.data?.repo ? `${e.data.repo}#${e.data.pr}` : ""} {e.data?.verdict ?? ""}</span>
            </motion.li>))}</AnimatePresence>
        </ul>)}
    </section>);
}


const TITLES: Record<string, string> = { run: "Run & decision", inventory: "Inventory & SBOMs", findings: "Findings", investigation: "Investigation",
  remediation: "Recommended & approved action", validation: "Validation", before_after: "Before / after", remaining_risk: "Remaining risk", confidence: "Confidence", audit: "Audit chain", limits: "What was not checked", next: "Next steps" };

export function Report({ s, project }: { s: Sections; project: string | null }) {
  const sep = project ? "&" : "?";
  return (
    <div className="flex flex-col gap-4">
      <SectionHead n={6} title="Guardian report" sub="One evidence pack built from this run's files: the same model this dashboard shows. Every section says what was checked and what could not be checked."
        right={<><a href={`/api/report${q(project)}${sep}fmt=html`} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 rounded-lg bg-accent px-3 py-1.5 text-[12.5px] font-medium text-white hover:brightness-110"><FileArrowDown /> Open HTML report</a>
          <a href={`/api/report${q(project)}${sep}fmt=json`} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[12.5px] text-muted ring-1 ring-line hover:text-ink"><FileCode /> JSON</a></>} />
      <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-5">
        {Object.keys(s).map((k, i) => {
          const v = s[k] ?? {};
          const status = v.status ?? (k === "audit" ? (v.chain_ok ? "complete" : "failed") : "complete");
          const S = st(status === "done" || status === "executed" || status === "approved" || status === "proposed" ? "complete" : status === "not_started" ? "pending" : status);
          return (
            <motion.div key={k} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ ...spring, delay: i * 0.04 }} className="panel p-3.5">
              <div className="font-mono text-[10.5px] text-faint">{String(i + 1).padStart(2, "0")}</div>
              <div className="mt-0.5 text-[13px] font-medium">{TITLES[k] ?? k}</div>
              <div className={`mt-1 flex items-center gap-1 text-[11.5px] ${S.cls}`}><S.Icon weight="fill" />{String(status).replace("_", " ")}</div>
            </motion.div>);
        })}
      </section>
      <div className="grid gap-4 lg:grid-cols-2">
        <section className="panel p-4 text-[12.5px]">
          <h2 className="flex items-center gap-2 text-[13px] font-semibold"><Fingerprint /> Integrity</h2>
          <dl className="mt-2 grid grid-cols-[140px_minmax(0,1fr)] gap-y-1.5">
            <dt className="text-faint">Scan report</dt><dd className="truncate font-mono text-[11.5px]">{s.run.scan_report?.sha256}</dd>
            <dt className="text-faint">Audit chain</dt><dd className={s.audit?.chain_ok ? "text-ok" : "text-crit"}>{s.audit?.chain_ok ? "intact (hash-chained)" : "BROKEN"}</dd>
            {s.remediation?.patch && <><dt className="text-faint">Patch</dt><dd className="truncate font-mono text-[11.5px]">{s.remediation.patch.patch_sha256}</dd></>}
            {s.investigation?.packet_sha256 && <><dt className="text-faint">Evidence packet</dt><dd className="truncate font-mono text-[11.5px]">{s.investigation.packet_sha256}</dd></>}
          </dl>
        </section>
        <LiveEvents />
      </div>
      <p className="flex items-center gap-1.5 text-[11.5px] text-faint"><LinkSimple /> The PR trigger posts guardian/scan and guardian/validation statuses and one comment when GitHub Actions sends events.</p>
    </div>);
}
