import { AnimatePresence, motion } from "motion/react";
import { useEffect, useState } from "react";
import { ShieldWarning, X } from "@phosphor-icons/react";
import type { Evidence } from "../types";

const SUSPICIOUS = /(ai reviewers?|ignore (all )?previous|mark it benign|approve the merge|registry=|postinstall|http:\/\/\S+)/i;

export function EvidenceDrawer({ runId, id, onClose }: { runId: string | null; id: string | null; onClose: () => void }) {
  const [ev, setEv] = useState<Evidence | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    if (!id || !runId) return; setEv(null); setErr(null);
    fetch(`/api/runs/${runId}/evidence/${id}`).then(async (r) => (r.ok ? setEv(await r.json()) : setErr("Evidence not found"))).catch(() => setErr("Backend offline"));
  }, [id, runId]);
  useEffect(() => { const k = (e: KeyboardEvent) => e.key === "Escape" && onClose(); window.addEventListener("keydown", k); return () => window.removeEventListener("keydown", k); }, [onClose]);

  let body = ev?.content ?? "";
  try { if (body.trim().startsWith("{")) body = JSON.stringify(JSON.parse(body), null, 2); } catch { /* keep raw */ }

  return (
    <AnimatePresence>
      {id && (
        <>
          <motion.div className="fixed inset-0 z-30 bg-canvas/50" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose} />
          <motion.aside className="fixed inset-y-0 right-0 z-30 flex w-full max-w-xl flex-col border-l border-line bg-surface"
            initial={{ x: "100%" }} animate={{ x: 0 }} exit={{ x: "100%" }} transition={{ type: "spring", stiffness: 300, damping: 32 }}>
            <div className="flex items-start gap-3 border-b border-line p-4">
              <div className="min-w-0 flex-1">
                <div className="font-mono text-sm">{id}</div>
                {ev && <div className="mt-1 text-xs text-muted">{ev.source}{ev.path ? ` | ${ev.path}` : ""} | {ev.kind}</div>}
              </div>
              <button onClick={onClose} aria-label="Close evidence" className="rounded-md p-1 text-muted hover:bg-white/5 hover:text-ink"><X size={18} /></button>
            </div>
            {ev?.untrusted && (
              <div className="flex items-start gap-2 border-b border-high/20 bg-high/8 px-4 py-2.5 text-xs text-high">
                <ShieldWarning size={16} className="shrink-0" /> Untrusted content from the change under review. Agents see it wrapped as data and never follow it (C5).
              </div>
            )}
            <div className="scroll-thin min-h-0 flex-1 overflow-auto p-4">
              {err && <p className="text-sm text-crit">{err}</p>}
              {!ev && !err && <div className="flex flex-col gap-2">{[80, 64, 72, 40].map((w) => <div key={w} className="h-3 animate-pulse rounded bg-white/5" style={{ width: `${w}%` }} />)}</div>}
              {ev && (
                <pre className="font-mono text-[12px] leading-relaxed whitespace-pre-wrap break-words text-ink/85">
                  {body.split("\n").map((line, i) => (
                    <div key={i} className={SUSPICIOUS.test(line) ? "-mx-2 rounded bg-crit/12 px-2 text-crit" : line.startsWith("+") ? "text-ok/90" : line.startsWith("-") ? "text-crit/80" : ""}>{line || " "}</div>
                  ))}
                </pre>
              )}
            </div>
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  );
}
