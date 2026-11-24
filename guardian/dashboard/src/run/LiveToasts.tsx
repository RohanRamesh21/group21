import { AnimatePresence, motion } from "motion/react";
import { useEffect, useRef, useState } from "react";
import { ArrowRight, GitPullRequest, Prohibit, SealCheck, Warning, X } from "@phosphor-icons/react";
import { spring } from "../ui";
import type { StepId } from "./shared";

/* Live pull-request events from the GitHub trigger (server-sent events with resume). A new PR shows a toast; with
   "follow" on, the dashboard switches to it when its scan finishes. Titles are untrusted text, rendered as text only. */

type Toast = { id: number; project: string; pr: number; title: string; kind: string; verdict?: string; text: string; view?: StepId };

export function LiveToasts({ project, onOpen, onRunsChanged, onCurrentChanged }: {
  project: string | null; onOpen: (p: string, v?: StepId) => void; onRunsChanged: () => void; onCurrentChanged: () => void;
}) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [follow, setFollow] = useState(true);
  const [online, setOnline] = useState(false);
  const ref = useRef({ project, follow, onOpen, onRunsChanged, onCurrentChanged });
  ref.current = { project, follow, onOpen, onRunsChanged, onCurrentChanged };

  useEffect(() => {
    let es: EventSource | null = null;
    let closed = false;
    fetch("/api/trigger/current").then((r) => r.json()).then((cur) => {
      if (closed) return;
      es = new EventSource(`/api/trigger/stream?since=${cur.last_seq ?? 0}`);  // only new events, not history
      es.onopen = () => setOnline(true);
      es.onerror = () => setOnline(false);
      const push = (t: Omit<Toast, "id">) => setToasts((xs) => [{ ...t, id: Date.now() + Math.random() }, ...xs].slice(0, 4));
      const on = (kind: string, fn: (d: any) => void) => es!.addEventListener(kind, (m) => fn(JSON.parse((m as MessageEvent).data).data ?? {}));
      on("run_queued", (d) => { ref.current.onRunsChanged(); push({ project: d.project, pr: d.pr, title: d.title, kind: "queued", text: "opened · scanning" }); });
      on("scan_finished", (d) => {
        ref.current.onRunsChanged();
        push({ project: d.project, pr: d.pr, title: d.title, kind: "finished", verdict: d.verdict, text: `scan finished: ${String(d.verdict ?? "incomplete").toUpperCase()}` });
        if (ref.current.follow) ref.current.onOpen(d.project, "summary");
        else if (d.project === ref.current.project) ref.current.onCurrentChanged();
      });
      on("agents_started", (d) => d.project === ref.current.project && ref.current.onCurrentChanged());
      on("agents_finished", (d) => d.project === ref.current.project && ref.current.onCurrentChanged());
      on("approval_needed", (d) => push({ project: d.project, pr: d.pr, title: "", kind: "approval", text: "agents finished · your approval is needed", view: "fix" }));
      on("validation_finished", (d) => { if (d.project === ref.current.project) ref.current.onCurrentChanged(); push({ project: d.project, pr: d.pr, title: "", kind: "validation", text: d.description ?? "validation finished", view: "validate" }); });
      on("github_post", (d) => { if (String(d.result).startsWith("post failed")) push({ project: d.project, pr: d.pr, title: "", kind: "error", text: `GitHub ${d.what} not posted: ${d.result}` }); });
    }).catch(() => setOnline(false));
    return () => { closed = true; es?.close(); };
  }, []);

  useEffect(() => { if (!toasts.length) return; const t = window.setTimeout(() => setToasts((xs) => xs.slice(0, -1)), 12000); return () => window.clearTimeout(t); }, [toasts]);

  const icon = (t: Toast) => t.kind === "error" ? <Warning className="text-crit" /> : t.verdict === "block" ? <Prohibit className="text-crit" /> : t.verdict === "allow" ? <SealCheck className="text-ok" /> : t.verdict === "review" ? <Warning className="text-high" /> : <GitPullRequest className="text-accent" />;
  return (<>
    <div className="pointer-events-none fixed bottom-4 right-4 z-50 flex w-[360px] flex-col gap-2">
      <AnimatePresence initial={false}>{toasts.map((t) => (
        <motion.div key={t.id} layout initial={{ opacity: 0, x: 40, scale: 0.96 }} animate={{ opacity: 1, x: 0, scale: 1 }} exit={{ opacity: 0, x: 40 }} transition={spring}
          className="pointer-events-auto panel flex items-start gap-3 p-3 text-[12.5px]" role="status">
          <span className="mt-0.5 text-[16px]">{icon(t)}</span>
          <div className="min-w-0 flex-1">
            <div className="font-medium">PR #{t.pr}{t.title ? <span className="text-muted"> · {t.title}</span> : null}</div>
            <div className="text-muted">{t.text}</div>
            {t.project && t.kind !== "error" && <button onClick={() => { onOpen(t.project, t.view); setToasts((xs) => xs.filter((x) => x.id !== t.id)); }} className="mt-1 inline-flex items-center gap-1 text-accent hover:underline">Open <ArrowRight /></button>}
          </div>
          <button aria-label="Dismiss" onClick={() => setToasts((xs) => xs.filter((x) => x.id !== t.id))} className="text-faint hover:text-ink"><X /></button>
        </motion.div>))}</AnimatePresence>
    </div>
    <div className="fixed bottom-4 left-4 z-40 flex items-center gap-2 rounded-full bg-surface/90 px-3 py-1.5 text-[11px] text-muted ring-1 ring-line">
      <span className={`size-1.5 rounded-full ${online ? "bg-ok" : "bg-faint"}`} />{online ? "Live PR events" : "PR events offline"}
      <label className="ml-1 flex items-center gap-1"><input type="checkbox" checked={follow} onChange={(e) => setFollow(e.target.checked)} className="accent-[var(--color-accent)]" />follow new PRs</label>
    </div>
  </>);
}
