import { useEffect, useRef, useState } from "react";
import { ArrowClockwise, CircleNotch } from "@phosphor-icons/react";
import { api } from "./shared";

/* A scan saved by an older Guardian version: say so plainly and offer a rescan of the same commits with the current
   engine. Progress comes from the project's own job record; the old results are kept by the server, not deleted. */
export function OutdatedRun({ project, message, onDone }: { project: string | null; message: string; onDone: () => void }) {
  const [state, setState] = useState<"idle" | "running" | "error">("idle");
  const [step, setStep] = useState<string>("");
  const [err, setErr] = useState<string | null>(null);
  const timer = useRef<number | null>(null);
  useEffect(() => () => { if (timer.current) window.clearInterval(timer.current); }, []);
  const start = async () => {
    if (!project) return;
    setErr(null);
    try {
      await api(`/api/projects/${encodeURIComponent(project)}/rescan`, { method: "POST" });
      setState("running");
      timer.current = window.setInterval(async () => {
        const all = await api("/api/projects");
        const j = (all.jobs ?? all).find((x: { id: string }) => x.id === project);
        if (!j) return;
        setStep(j.steps?.[j.steps.length - 1]?.msg ?? j.message ?? "");
        if (j.status === "done") { window.clearInterval(timer.current!); onDone(); }
        if (j.status === "error") { window.clearInterval(timer.current!); setState("error"); setErr(j.message); }
      }, 1500);
    } catch (e) { setState("error"); setErr((e as Error).message); }
  };
  return (
    <div role="alert" className="panel p-8 text-[13px]">
      <p className="font-medium text-ink">This scan was made by an older version of Guardian.</p>
      <p className="mt-1 max-w-[70ch] text-muted">{message.replace(/^outdated:\s*/, "")} The rescan uses the same commits and the repository copy already on disk; the old results are kept.</p>
      {state === "running"
        ? <p className="mt-4 flex items-center gap-2 text-accent"><CircleNotch className="animate-spin" /> Rescanning… <span className="text-muted">{step}</span></p>
        : <button onClick={start} className="mt-4 inline-flex items-center gap-2 rounded-lg bg-accent px-3.5 py-2 text-[13px] font-medium text-white transition hover:brightness-110 active:scale-[0.98]"><ArrowClockwise /> Rescan with the current engine</button>}
      {err && <p className="mt-2 text-crit">{err}</p>}
    </div>);
}
