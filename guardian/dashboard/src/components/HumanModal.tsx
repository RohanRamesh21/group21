import { AnimatePresence, motion } from "motion/react";
import { useEffect, useState } from "react";
import { User } from "@phosphor-icons/react";
import type { RunState } from "../types";

export function HumanModal({ state, onAnswer }: { state: RunState | null; onAnswer: (questionId: string, choice: number) => Promise<boolean> }) {
  const q = state?.pending_human;
  const [left, setLeft] = useState(0);
  const [pending, setPending] = useState<string | null>(null);
  useEffect(() => {
    if (!q) return; setLeft(q.timeout);
    const t = setInterval(() => setLeft((s) => Math.max(0, s - 1)), 1000);
    return () => clearInterval(t);
  }, [q?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <AnimatePresence>
      {q && (
        <motion.div className="fixed inset-0 z-40 grid place-items-center bg-canvas/70 p-6 backdrop-blur-sm"
          initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
          <motion.div role="dialog" aria-modal="true" aria-labelledby="hq" className="panel w-full max-w-lg p-6"
            initial={{ y: 24, scale: 0.97 }} animate={{ y: 0, scale: 1 }} exit={{ y: 12, opacity: 0 }}
            transition={{ type: "spring", stiffness: 280, damping: 26 }}>
            <div className="flex items-center gap-2 text-sm text-muted">
              <User size={16} /> Guardian requests reviewer context
              <span className="ml-auto font-mono text-xs">{left}s</span>
            </div>
            <h2 id="hq" className="mt-3 text-lg font-medium leading-snug">{q.question}</h2>
            <p className="mt-2 text-xs text-muted">Your answer supplies context for the assessment. Policy still governs the recommendation.</p>
            <div className="mt-5 flex flex-wrap gap-2">
              {q.options.map((o, i) => (
                <button key={o} disabled={pending === q.id || left === 0} onClick={async () => {
                  setPending(q.id);
                  try {
                    if (await onAnswer(q.id, i)) return;
                  } catch {
                    // The request can be retried while this question is still open.
                  }
                  setPending(null);
                }}
                  className={`rounded-lg px-4 py-2 text-sm font-medium transition active:scale-[0.98] ${i === q.options.length - 1 ? "bg-accent text-white hover:brightness-110" : "border border-line bg-raised text-ink hover:border-white/20"}`}>
                  {o}
                </button>
              ))}
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
