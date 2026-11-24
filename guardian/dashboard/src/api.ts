/** Backend calls and the shapes the scan pages share. "main" is the report written by `guardian check` on the CLI. */
export type Verdict = "block" | "review" | "allow";
export type Level = "critical" | "high" | "medium" | "low" | "info";

export interface JobStep { t: number; msg: string; stage?: string | null }
export interface Job {
  id: string; kind: "zip" | "git" | "path"; label: string; status: "queued" | "running" | "done" | "error"; message: string;
  created: number; updated?: number; steps: JobStep[]; stage?: string | null; mode?: "single" | "compare";
  url?: string; path?: string; git?: boolean; base?: string | null; head?: string | null; base_default?: boolean;
  summary?: { packages: number; verdict: Verdict; reasons: string[]; head_commit: string; base_commit: string; ecosystems?: Record<string, number> };
}

export interface Context {
  project: string | null; app: string; base: string; head: string; base_commit: string; head_commit: string; compare: boolean;
  verdict?: Verdict; reasons: string[]; policy?: string | null; packages?: number; scanned_at: number;
  inventory: { packages: number; unique_name_versions: number; direct: number; transitive: number; runtime: number; dev_only: number;
    install_scripts: number; unpinned: number; ecosystems: Record<string, number>; manifests: number; lockfiles: number; workflows: number;
    actions: number; base_images: number; edges: number };
  changes: { files: number; added: number; updated: number; removed: number };
  package_changes: { added: string[]; updated: string[]; removed: string[] };
  vulnerabilities: Record<"introduced" | "pre_existing" | "fixed", Partial<Record<Level, number>>>;
  scanners: Record<string, number>; scanner_errors: Record<string, string>;
  ci: { actions: { total: number; pinned: number } | null; images: { total: number; pinned: number } | null; introduced: number; pre_existing: number };
  signals: { type: string; severity: Level; component: string; summary: string; hard_signal: boolean; file?: string | null; line?: number | null }[];
  signal_counts: { introduced: number; pre_existing: number; not_checked: number };
  sandbox: { mode?: string; engine?: string; all_isolated?: boolean; tools?: string[] };
  provenance?: { scope?: string; checked?: number; signed?: number; attested?: number; errors?: string[] } | null;
  sbom_agreement_pct?: number | null; sboms: string[];
}

export interface Meta { provider: string; live_available: boolean; replay_available: boolean; model?: string; effort?: string | null }
export interface Sources { path_roots: string[]; git_hosts: string[]; max_zip_mb: number }

export type Source =
  | { kind: "git"; url: string; base?: string; head?: string }
  | { kind: "zip"; file: File }
  | { kind: "path"; path: string; base?: string; head?: string };

/** Query string for report endpoints: no parameter = the CLI report. */
export const q = (project?: string | null) => (project && project !== "main" ? `?project=${encodeURIComponent(project)}` : "");
export const apiProject = (id: string | null) => (id && id !== "main" ? id : null);

export async function getJSON<T>(url: string): Promise<T> {
  const r = await fetch(url);
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.detail ?? `request failed (${r.status})`);
  return body as T;
}

export async function postJSON<T>(url: string, data: unknown): Promise<T> {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.detail ?? `request failed (${r.status})`);
  return body as T;
}

/** Start a scan of any source; resolves to the new project id. */
export async function startScan(src: Source): Promise<string> {
  if (src.kind === "zip") {
    const fd = new FormData();
    fd.append("file", src.file);
    const r = await fetch("/api/projects/zip", { method: "POST", body: fd });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(body.detail ?? "upload failed");
    return body.id;
  }
  const { kind, ...rest } = src;
  return (await postJSON<{ id: string }>(`/api/projects/${kind}`, rest)).id;
}

export function ago(ts: number) {
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(ts * 1000).toLocaleDateString([], { day: "numeric", month: "short" });
}

export const VERDICT_TONE: Record<string, { text: string; chip: string; label: string }> = {
  block: { text: "text-crit", chip: "bg-crit/12 text-crit ring-crit/40", label: "Block" },
  review: { text: "text-high", chip: "bg-high/12 text-high ring-high/40", label: "Review" },
  allow: { text: "text-ok", chip: "bg-ok/12 text-ok ring-ok/40", label: "Allow" },
};
