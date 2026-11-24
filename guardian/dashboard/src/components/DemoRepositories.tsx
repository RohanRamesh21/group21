import { ArrowRight, CircleNotch } from "@phosphor-icons/react";
import { useEffect, useState } from "react";
import { getJSON, postJSON, rememberReviewToken, type ExampleApp, type StartedProject } from "../api";

export function DemoRepositories({ investigate, onStarted }: { investigate: boolean; onStarted: (id: string, investigation: boolean) => void }) {
  const [apps, setApps] = useState<ExampleApp[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    getJSON<ExampleApp[]>("/api/examples").then(setApps).catch((err) => setError(String(err.message ?? err)));
  }, []);

  async function scan(app: ExampleApp) {
    setBusy(app.name);
    setError("");
    try {
      const result = await postJSON<StartedProject>("/api/projects/example", { name: app.name, investigate });
      rememberReviewToken(result);
      onStarted(result.id, !!result.run_id);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  }

  if (!apps.length && !error) return null;
  return (
    <section aria-labelledby="demo-repositories" className="panel overflow-hidden">
      <div className="border-b border-line px-5 py-4">
        <h2 id="demo-repositories" className="text-[15px] font-medium">Demo repositories</h2>
        <p className="mt-1 text-[12px] text-muted">Compare pinned releases with {investigate ? "focused agent review for material findings" : "the deterministic scanner"}.</p>
      </div>
      <ul className="grid divide-y divide-line md:grid-cols-2 md:gap-px md:divide-none md:bg-line">
        {apps.map((app) => (
          <li key={app.name} className="flex items-center justify-between gap-3 bg-surface px-5 py-3">
            <div className="min-w-0">
              <div className="flex flex-wrap items-baseline gap-x-2">
                <span className="text-[13px] font-medium">{app.name}</span>
                <span className="font-mono text-[11px] text-muted">{app.base} → {app.head}</span>
              </div>
              <div className="mt-0.5 text-[11px] text-muted">{app.language}</div>
            </div>
            <button type="button" aria-label={`${investigate ? "Scan and investigate" : "Scan"} ${app.name}`} disabled={busy !== null} onClick={() => void scan(app)}
              className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-line px-2.5 py-1.5 text-[12px] text-accent enabled:hover:bg-raised disabled:opacity-45">
              {busy === app.name ? <><CircleNotch size={13} className="animate-spin" /> Starting…</> : <>{investigate ? "Run workflow" : "Scan"} <ArrowRight size={13} /></>}
            </button>
          </li>
        ))}
      </ul>
      {error && <p role="alert" className="px-5 py-3 text-[12px] text-crit">{error}</p>}
    </section>
  );
}
