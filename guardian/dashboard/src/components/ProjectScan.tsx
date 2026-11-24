import { AnimatePresence, motion } from "motion/react";
import { useEffect, useRef, useState } from "react";
import { CircleNotch, CheckCircle, FileZip, Flask, GitBranch, ShieldCheck, WarningCircle } from "@phosphor-icons/react";
import { Day1Report } from "./Day1Report";
import { DepGraph } from "./DepGraph";
import { RiskScores } from "./RiskScores";
import { spring } from "../ui";

interface Job {
  id: string; kind: "zip" | "git" | "local"; label: string; status: "queued" | "running" | "done" | "error"; message: string; created: number;
  steps: { t: number; msg: string }[]; mode?: "single" | "compare"; note?: string | null;
  summary?: { packages: number; verdict: string; reasons: string[]; head_commit: string; base_commit: string };
}

export function ProjectScan() {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [sel, setSel] = useState<string | null>(null);
  const [view, setView] = useState<"day1" | "scores" | "graph">("day1");
  const [url, setUrl] = useState("");
  const [base, setBase] = useState("");
  const [head, setHead] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [drag, setDrag] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const [boxes, setBoxes] = useState<{ name: string; branches: string[] }[]>([]);
  const [box, setBox] = useState({ name: "", base: "scenario/base", head: "scenario/s3-s9" });
  useEffect(() => {
    fetch("/api/sandbox").then((r) => r.json()).then((b) => { setBoxes(b); if (b[0]) setBox((x) => ({ ...x, name: b[0].name })); }).catch(() => {});
  }, []);
  const runLocal = async () => {
    setErr(null);
    const r = await fetch("/api/projects/local", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(box) });
    const d = await r.json();
    if (!r.ok) return setErr(d.detail);
    setSel(d.id); refresh();
  };
  const branches = boxes.find((b) => b.name === box.name)?.branches ?? [];

  const refresh = () => fetch("/api/projects").then((r) => r.json()).then(setJobs).catch(() => {});
  useEffect(() => { refresh(); }, []);
  const busy = jobs.some((j) => j.status === "queued" || j.status === "running");
  useEffect(() => {
    if (!busy) return;
    const t = setInterval(refresh, 1500);
    return () => clearInterval(t);
  }, [busy]);

  const upload = async (file: File) => {
    setErr(null);
    const fd = new FormData(); fd.append("file", file);
    const r = await fetch("/api/projects/zip", { method: "POST", body: fd });
    const d = await r.json();
    if (!r.ok) return setErr(d.detail);
    setSel(d.id); refresh();
  };
  const clone = async () => {
    setErr(null);
    const r = await fetch("/api/projects/git", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url, base, head }) });
    const d = await r.json();
    if (!r.ok) return setErr(d.detail);
    setSel(d.id); refresh();
  };
  const cur = jobs.find((j) => j.id === sel) ?? null;

  return (
    <div className="flex flex-col gap-4">
      <section className="grid gap-4 lg:grid-cols-3">
        <div onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)}
          onDrop={(e) => { e.preventDefault(); setDrag(false); const f = e.dataTransfer.files[0]; if (f) upload(f); }}
          className={`panel flex flex-col gap-3 px-5 py-4 transition-colors ${drag ? "border-accent/60 bg-accent/5" : ""}`}>
          <div className="flex items-center gap-2 font-medium"><FileZip size={18} className="text-accent" /> Upload a project folder (.zip)</div>
          <p className="text-[12.5px] text-muted">Drop any zipped project here: npm, Python, Go, Java, Rust, Ruby, PHP, .NET, browser extensions, plain HTML/JS. Guardian finds every manifest and lockfile, vendored libraries, CDN scripts, CI workflows and Dockerfiles.</p>
          <div className="flex items-center gap-3">
            <button onClick={() => fileRef.current?.click()} className="rounded-md bg-accent px-3 py-1.5 text-[13px] font-medium text-white hover:bg-accent/85">Choose .zip</button>
            <span className="text-[12px] text-faint">or drag it here · max 200 MB</span>
            <input ref={fileRef} type="file" accept=".zip" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; if (f) upload(f); e.target.value = ""; }} />
          </div>
        </div>
        <div className="panel flex flex-col gap-3 px-5 py-4">
          <div className="flex items-center gap-2 font-medium"><GitBranch size={18} className="text-accent" /> Scan a public Git repository</div>
          <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://github.com/owner/repo"
            className="rounded-md border border-line bg-raised px-3 py-1.5 font-mono text-[12.5px] outline-none focus:border-accent/60" />
          <div className="grid grid-cols-2 gap-2">
            <input value={base} onChange={(e) => setBase(e.target.value)} placeholder="base (optional, e.g. v1.2.0)"
              className="rounded-md border border-line bg-raised px-3 py-1.5 font-mono text-[12px] outline-none focus:border-accent/60" />
            <input value={head} onChange={(e) => setHead(e.target.value)} placeholder="head (optional, branch / tag / commit)"
              className="rounded-md border border-line bg-raised px-3 py-1.5 font-mono text-[12px] outline-none focus:border-accent/60" />
          </div>
          <div className="flex items-center gap-3">
            <button onClick={clone} disabled={!url} className="rounded-md bg-accent px-3 py-1.5 text-[13px] font-medium text-white enabled:hover:bg-accent/85 disabled:opacity-40">Scan repository</button>
            <span className="text-[12px] text-faint">Without base, the latest commit is compared with the one before it.</span>
          </div>
        </div>
        <div className="panel flex flex-col gap-3 px-5 py-4">
          <div className="flex items-center gap-2 font-medium"><Flask size={18} className="text-accent" /> Local sandbox (attack scenarios)</div>
          <p className="text-[12.5px] text-muted">Planted attacks stay on this laptop. Runs exactly the terminal <span className="font-mono">guardian check</span>.</p>
          <select value={box.name} onChange={(e) => setBox({ ...box, name: e.target.value })}
            className="rounded-md border border-line bg-raised px-3 py-1.5 font-mono text-[12.5px] outline-none focus:border-accent/60">
            {boxes.map((b) => <option key={b.name} value={b.name}>sandbox/{b.name}</option>)}</select>
          <div className="grid grid-cols-2 gap-2">
            {(["base", "head"] as const).map((k) => (
              <select key={k} value={box[k]} onChange={(e) => setBox({ ...box, [k]: e.target.value })} title={k}
                className="rounded-md border border-line bg-raised px-2 py-1.5 font-mono text-[12px] outline-none focus:border-accent/60">
                {branches.map((b) => <option key={b} value={b}>{k}: {b}</option>)}</select>))}
          </div>
          <div className="flex items-center gap-3">
            <button onClick={runLocal} disabled={!box.name} className="rounded-md bg-accent px-3 py-1.5 text-[13px] font-medium text-white enabled:hover:bg-accent/85 disabled:opacity-40">Scan sandbox</button>
            <span className="text-[12px] text-faint">base = before, head = the pull request</span>
          </div>
        </div>
      </section>
      <div className="flex items-center gap-2 text-[12px] text-muted"><ShieldCheck size={15} className="text-ok" />
        Safe by design: nothing from the project is installed or run · ZIPs are checked for unsafe paths and symlinks · Git clones are read-only (https on GitHub, GitLab or Bitbucket, no hooks, no submodules).</div>
      {err && <div className="rounded-lg border border-crit/30 bg-crit/8 px-4 py-2 text-sm text-crit">{err}</div>}

      {jobs.length > 0 && (
        <section className="panel">
          <ul>{jobs.map((j) => (
            <li key={j.id}>
              <button onClick={() => setSel(j.id)} className={`flex w-full items-center gap-3 border-b border-line px-4 py-2.5 text-left hover:bg-raised ${sel === j.id ? "bg-raised" : ""}`}>
                {j.status === "done" ? <CheckCircle size={17} className="text-ok" /> : j.status === "error" ? <WarningCircle size={17} className="text-crit" /> :
                  <CircleNotch size={17} className="animate-spin text-accent" />}
                <span className="font-mono text-[12.5px]">{j.label}</span>
                <span className="text-[12px] text-muted">{j.kind === "zip" ? "upload" : j.kind === "local" ? "sandbox" : "git"}{j.mode ? ` · ${j.mode === "compare" ? "PR compare" : "full scan"}` : ""}</span>
                <span className="ml-auto truncate text-[12px] text-muted">{j.status === "done" && j.summary ? `${j.summary.packages} packages · verdict ${j.summary.verdict}` : j.message}</span>
              </button>
            </li>))}</ul>
        </section>)}

      <AnimatePresence mode="wait">
        {cur && cur.status !== "done" && (
          <motion.div key={cur.id + cur.status} initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={spring} className="panel px-5 py-4">
            <div className="mb-2 font-medium">{cur.status === "error" ? "Scan failed" : "Scanning…"}</div>
            <ol className="space-y-1 font-mono text-[12px] text-muted">{cur.steps.map((s, i) => <li key={i}><span className="text-faint">{s.t.toFixed(1)}s</span> {s.msg}</li>)}</ol>
            {cur.status === "error" && <div className="mt-2 text-[12.5px] text-crit">{cur.message}</div>}
          </motion.div>)}
      </AnimatePresence>

      {cur && cur.status === "done" && (
        <div className="flex flex-col gap-3">
          <div className="flex items-center gap-1 text-sm">
            {([["day1", "Day 1 report"], ["scores", "Risk scores"], ["graph", "Dependency graph"]] as const).map(([k, l]) => (
              <button key={k} onClick={() => setView(k)} className={`rounded-md px-3 py-1 ${view === k ? "bg-raised text-ink" : "text-muted hover:text-ink"}`}>{l}</button>))}
            {cur.mode === "compare" && cur.summary && <span className="ml-3 font-mono text-[12px] text-faint">{cur.summary.base_commit.slice(0, 8)} → {cur.summary.head_commit.slice(0, 8)}</span>}
          </div>
          {view === "day1" ? <Day1Report project={cur.id} /> : view === "scores" ? <RiskScores project={cur.id} fullScan={cur.mode !== "compare"} /> : <DepGraph project={cur.id} />}
        </div>)}
    </div>
  );
}
