import { AnimatePresence, motion } from "motion/react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { ArrowRight, CaretDown, CircleNotch, FileZip, FolderOpen, GitBranch, GithubLogo, UploadSimple, X } from "@phosphor-icons/react";
import { ago, getJSON, rememberReviewToken, startScan, type Source, type Sources } from "../api";
import { Segmented } from "../ui";

type Kind = Source["kind"];
const field = "w-full rounded-lg border border-line bg-canvas/70 px-3.5 py-2.5 font-mono text-[13px] text-ink outline-none transition placeholder:text-faint focus:border-accent/60 focus:ring-4 focus:ring-accent/10";

/** One form for every source Guardian can scan: a public Git URL, a ZIP upload or a folder on this machine. */
export function SourceInput({ onStarted, investigate = false, allowScanOnly = false, id = "src", autoFocus = false }: {
  onStarted: (projectId: string, investigation: boolean) => void;
  investigate?: boolean; allowScanOnly?: boolean; id?: string; autoFocus?: boolean;
}) {
  const [kind, setKind] = useState<Kind>("git");
  const [url, setUrl] = useState("");
  const [path, setPath] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [base, setBase] = useState("");
  const [head, setHead] = useState("");
  const [compare, setCompare] = useState(false);
  const [workingTree, setWorkingTree] = useState(false);
  const [baseline, setBaseline] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [shake, setShake] = useState(0);
  const [drag, setDrag] = useState(false);
  const [hints, setHints] = useState<Sources | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  useEffect(() => { getJSON<Sources>("/api/sources").then(setHints).catch(() => setHints(null)); }, []);
  useEffect(() => setErr(null), [kind]);

  const ready = kind === "git" ? url.trim().length > 0 : kind === "zip" ? !!file : path.trim().length > 0;
  const useWorkingTree = kind === "path" && workingTree;
  const savedBaseline = kind !== "git" && !compare && !useWorkingTree ? baseline || undefined : undefined;
  const refs = compare || useWorkingTree
    ? { base: base.trim() || undefined, head: useWorkingTree ? undefined : head.trim() || undefined } : {};

  const submit = async (withInvestigation: boolean) => {
    if (!ready || busy) return;
    setBusy(true); setErr(null);
    try {
      const src: Source = kind === "git" ? { kind, url: url.trim(), ...refs }
        : kind === "zip" ? { kind, file: file!, baseline_project: baseline || undefined }
        : { kind, path: path.trim(), ...refs, working_tree: useWorkingTree, baseline_project: savedBaseline };
      const result = await startScan(src, withInvestigation);
      rememberReviewToken(result);
      onStarted(result.id, !!result.run_id);
    } catch (x) {
      setErr(x instanceof Error ? x.message : String(x));
      setShake((n) => n + 1);
    } finally {
      setBusy(false);
    }
  };

  const pick = (f?: File | null) => { if (f) { setFile(f); setErr(null); } };

  return (
    <form onSubmit={(e: FormEvent) => { e.preventDefault(); void submit(investigate); }} className="flex flex-col gap-4">
      <Segmented id={`${id}-kind`} value={kind} onChange={setKind} options={[
        { value: "git", label: <><GithubLogo size={15} weight="duotone" />Git URL</> },
        { value: "zip", label: <><FileZip size={15} weight="duotone" />ZIP upload</> },
        { value: "path", label: <><FolderOpen size={15} weight="duotone" />Local path</> },
      ]} />

      <AnimatePresence mode="wait" initial={false}>
        <motion.div key={kind} initial={{ opacity: 0, x: 10 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -10 }} transition={{ duration: 0.18 }}>
          {kind === "git" && (
            <label className="block">
              <span className="sr-only">Repository URL</span>
              <input autoFocus={autoFocus} value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://github.com/owner/repository" className={field} spellCheck={false} />
              <span className="mt-1.5 block text-[11.5px] text-faint">Public repositories on {hints?.git_hosts.join(", ") ?? "github.com, gitlab.com, bitbucket.org"} · cloned read-only, nothing checked out</span>
            </label>
          )}
          {kind === "path" && (
            <label className="block">
              <span className="sr-only">Folder on this machine</span>
              <input autoFocus={autoFocus} value={path} onChange={(e) => setPath(e.target.value)} placeholder={`${hints?.path_roots[0] ?? "/home/you"}/projects/my-app`} className={field} spellCheck={false} />
              <span className="mt-1.5 block text-[11.5px] text-faint">Git repositories use commits by default. Plain folders are captured as snapshots.
                {hints && <> Allowed under {hints.path_roots.join(", ")}.</>}</span>
            </label>
          )}
          {kind === "zip" && (
            <div onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)}
              onDrop={(e) => { e.preventDefault(); setDrag(false); pick(e.dataTransfer.files[0]); }}
              onClick={() => fileRef.current?.click()} role="button" tabIndex={0} onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && fileRef.current?.click()}
              className={`group relative flex cursor-pointer items-center gap-4 overflow-hidden rounded-lg border border-dashed px-4 py-4 transition-colors ${drag ? "border-accent bg-accent/8" : "border-white/15 bg-canvas/50 hover:border-accent/50"}`}>
              <motion.div animate={drag ? { y: [0, -4, 0] } : { y: 0 }} transition={drag ? { repeat: Infinity, duration: 0.9 } : {}}
                className="grid size-10 shrink-0 place-items-center rounded-lg bg-accent/12 text-accent"><UploadSimple size={20} weight="bold" /></motion.div>
              {file ? (
                <div className="min-w-0 flex-1">
                  <div className="truncate font-mono text-[13px] text-ink">{file.name}</div>
                  <div className="text-[11.5px] text-muted">{(file.size / 1024 / 1024).toFixed(1)} MB · ready to scan</div>
                </div>
              ) : (
                <div className="min-w-0 flex-1">
                  <div className="text-[13px] text-ink">Drop a zipped project here, or click to choose</div>
                  <div className="text-[11.5px] text-muted">Any language · up to {hints?.max_zip_mb ?? 200} MB · unsafe paths and symlinks are rejected</div>
                </div>
              )}
              {file && <button type="button" aria-label="Remove file" onClick={(e) => { e.stopPropagation(); setFile(null); }} className="rounded p-1 text-muted hover:bg-white/5 hover:text-ink"><X size={15} /></button>}
              <input ref={fileRef} type="file" accept=".zip" className="hidden" onChange={(e) => { pick(e.target.files?.[0]); e.target.value = ""; }} />
            </div>
          )}
        </motion.div>
      </AnimatePresence>

      {kind === "path" && (
        <label className="flex items-start gap-2 text-[12.5px]">
          <input type="checkbox" checked={workingTree} onChange={(e) => setWorkingTree(e.target.checked)} className="mt-0.5 accent-accent" />
          <span>Include uncommitted changes
            <span className="mt-0.5 block text-[11.5px] text-faint">For a local Git checkout. Reads saved edits and new, non-ignored files into a private snapshot.</span>
          </span>
        </label>
      )}
      {useWorkingTree && (
        <label className="block text-[12.5px]">
          <span className="mb-1 block text-muted">Base commit for working-tree comparison</span>
          <input value={base} onChange={(e) => setBase(e.target.value)} placeholder="HEAD (current commit)" className={field} spellCheck={false} />
        </label>
      )}
      {kind !== "zip" && !useWorkingTree && (
        <div>
          <button type="button" onClick={() => setCompare((c) => !c)} aria-expanded={compare} className="flex items-center gap-1.5 whitespace-nowrap text-[12.5px] text-muted transition-colors hover:text-ink">
            <GitBranch size={14} className="shrink-0" /> Compare two versions (base → head)
            <CaretDown size={12} className={`transition-transform duration-300 ${compare ? "rotate-180" : ""}`} />
            {!compare && <span className="hidden text-faint sm:inline">· default: the latest commit against the one before it</span>}
          </button>
          <AnimatePresence initial={false}>
            {compare && (
              <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.25 }} className="overflow-hidden">
                <div className="grid grid-cols-1 gap-2 pt-2.5 sm:grid-cols-[1fr_auto_1fr] sm:items-center">
                  <input value={base} onChange={(e) => setBase(e.target.value)} placeholder="base: tag, branch or commit (e.g. v1.2.0)" className={field} spellCheck={false} />
                  <ArrowRight size={14} className="hidden text-faint sm:block" />
                  <input value={head} onChange={(e) => setHead(e.target.value)} placeholder="head: tag, branch or commit (default: latest)" className={field} spellCheck={false} />
                </div>
                {kind === "path" && <div className="mt-1.5 text-[11.5px] text-faint">Only used when the folder is a Git repository.</div>}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}
      {(kind === "zip" || kind === "path" && !useWorkingTree && !compare) && (
        <label className="block text-[12.5px]">
          <span className="mb-1 block text-muted">Previous snapshot</span>
          <select className={field} value={baseline} onChange={(e) => setBaseline(e.target.value)}>
            <option value="">None · review this snapshot</option>
            {hints?.baselines?.map((snapshot) => <option value={snapshot.id} key={snapshot.id}>{snapshot.label} · {ago(snapshot.created)}</option>)}
          </select>
          <span className="mt-1 block text-[11.5px] text-faint">For ZIPs and plain folders. Scan an earlier copy first, then select it here to see changes.</span>
        </label>
      )}

      <div className="flex flex-wrap items-center gap-3">
        <motion.button type="submit" disabled={!ready || busy} whileTap={{ scale: 0.97 }}
          className="group inline-flex items-center gap-2 rounded-lg bg-accent px-5 py-2.5 text-sm font-medium text-white shadow-[inset_0_1px_0_rgb(255_255_255/0.25),0_8px_24px_-10px_rgb(77_141_255/0.8)] transition enabled:hover:brightness-110 disabled:opacity-40 disabled:shadow-none">
          {busy ? <CircleNotch size={16} className="animate-spin" /> : null}
          {busy ? "Starting…" : investigate ? "Scan & investigate" : "Run scan"}
          {!busy && <ArrowRight size={15} weight="bold" className="transition-transform group-enabled:group-hover:translate-x-0.5" />}
        </motion.button>
        {investigate && allowScanOnly && <button type="button" disabled={!ready || busy} onClick={() => void submit(false)}
          className="rounded-lg border border-line px-4 py-2.5 text-sm text-muted enabled:hover:text-ink disabled:opacity-40">Scan only</button>}
        <AnimatePresence>
          {err && (
            <motion.div key={shake} role="alert" initial={{ opacity: 0, x: 0 }} animate={{ opacity: 1, x: [0, -6, 6, -3, 3, 0] }} exit={{ opacity: 0 }} transition={{ duration: 0.4 }}
              className="min-w-0 flex-1 text-[12.5px] text-crit">{err}</motion.div>
          )}
        </AnimatePresence>
      </div>
    </form>
  );
}
