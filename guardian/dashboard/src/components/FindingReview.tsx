import { useEffect, useState, type FormEvent } from "react";

type Action = "confirm" | "challenge" | "defer";
type Status = "unreviewed" | "confirmed" | "challenged" | "deferred" | "reopened";

export interface ReviewDisposition {
  key: string;
  revision: string;
  status: Status;
  reason: "evidence_changed" | "deferral_expired" | null;
  latest_id: number | null;
}

interface ReviewEvent {
  id: number;
  action: Action;
  reviewer: string;
  rationale: string;
  owner: string | null;
  due_date: string | null;
  created_at: string;
  head_commit: string;
}

interface ReviewReport {
  review: ReviewDisposition;
  history: ReviewEvent[];
}

export const REVIEW_LABEL: Record<Status, string> = {
  unreviewed: "Unreviewed", confirmed: "Confirmed", challenged: "Challenged", deferred: "Deferred", reopened: "Reopened",
};

const ACTION_LABEL: Record<Action, string> = { confirm: "Confirm", challenge: "Challenge", defer: "Defer" };
const EVENT_LABEL: Record<Action, string> = { confirm: "Confirmed", challenge: "Challenged", defer: "Deferred" };

function message(body: { detail?: unknown }) {
  if (typeof body.detail === "string") return body.detail;
  if (Array.isArray(body.detail)) return body.detail.map((issue) => issue.msg).join(" ");
  return "The review could not be loaded or saved.";
}

export function FindingReview({ project, disposition, onSaved, onRefresh }: {
  project?: string | null;
  disposition: ReviewDisposition;
  onSaved: (review: ReviewDisposition) => void;
  onRefresh: () => void;
}) {
  const [history, setHistory] = useState<ReviewEvent[] | null>(null);
  const [previousId, setPreviousId] = useState(disposition.latest_id);
  const [action, setAction] = useState<Action | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ text: string; refresh: boolean } | null>(null);
  const [saved, setSaved] = useState(false);
  const url = `/api/reviews/${disposition.key}`;
  const query = new URLSearchParams(project ? { project } : undefined);
  const endpoint = `${url}?${query}`;
  const exportQuery = new URLSearchParams(query);
  exportQuery.set("download", "true");

  useEffect(() => {
    const controller = new AbortController();
    fetch(endpoint, { signal: controller.signal }).then(async (response) => {
      const body = await response.json();
      if (!response.ok) {
        setError({ text: message(body), refresh: true });
        return;
      }
      const report: ReviewReport = body;
      if (report.review.revision !== disposition.revision || report.review.latest_id !== disposition.latest_id) {
        setError({ text: "The scan or review history changed. Refresh Risk scores to continue.", refresh: true });
        return;
      }
      setHistory(report.history);
      setPreviousId(report.review.latest_id);
    }).catch((err) => {
      if (!controller.signal.aborted) setError({ text: String(err.message ?? err), refresh: true });
    });
    return () => controller.abort();
    // The parent remounts this form when the scan revision or selected finding changes.
    // A successful save updates the timeline directly.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [endpoint, disposition.revision]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!action || busy) return;
    const fields = new FormData(event.currentTarget);
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ revision: disposition.revision, previous_id: previousId, action,
          reviewer: fields.get("reviewer"), rationale: fields.get("rationale"),
          owner: action === "defer" ? fields.get("owner") : null,
          due_date: action === "defer" ? fields.get("due_date") : null }),
      });
      const body = await response.json();
      if (!response.ok) {
        setError({ text: message(body), refresh: response.status === 404 || response.status === 409 });
        return;
      }
      const report: ReviewReport = body;
      setHistory(report.history);
      setPreviousId(report.review.latest_id);
      onSaved(report.review);
      setAction(null);
      setSaved(true);
    } catch (err) {
      setError({ text: err instanceof Error ? err.message : "The review could not be saved.", refresh: false });
    } finally {
      setBusy(false);
    }
  }

  const field = "w-full rounded-md border border-line bg-raised px-2.5 py-1.5 text-ink focus:border-accent";
  return (
    <section aria-label="Finding review" className="space-y-3 rounded-lg border border-line px-3 py-3 text-[12.5px]">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="font-medium text-ink">Finding review</h3>
        <span className={`rounded bg-raised px-2 py-0.5 ${disposition.status === "reopened" ? "text-high" : "text-muted"}`}>
          {REVIEW_LABEL[disposition.status]}
        </span>
        {!!history?.length && <a href={`${url}?${exportQuery}`} className="ml-auto text-accent hover:underline">Download review</a>}
      </div>
      {disposition.reason && <p className="text-high">{disposition.reason === "evidence_changed"
        ? "The evidence changed since the last review." : "The deferral is past its due date."}</p>}
      <div className="flex flex-wrap gap-2">
        {(Object.keys(ACTION_LABEL) as Action[]).map((item) => (
          <button key={item} type="button" aria-pressed={action === item} disabled={!history || busy || error?.refresh}
            onClick={() => { setAction(action === item ? null : item); setSaved(false); }}
            className={`rounded-md px-2.5 py-1 ring-1 ring-inset ring-line enabled:hover:text-ink disabled:opacity-50 ${action === item ? "bg-accent/15 text-accent" : "bg-raised text-muted"}`}>
            {ACTION_LABEL[item]}
          </button>
        ))}
      </div>
      {action && <form onSubmit={submit} className="space-y-2">
        <p className="text-muted">{action === "confirm" ? "Record why the evidence supports the finding." : action === "challenge"
          ? "Describe the assumption or evidence you dispute. Include a file or ticket reference if available."
          : "Record who will follow up and when. The scan verdict still applies."}</p>
        <label className="block text-muted">Your name<input className={field} name="reviewer" maxLength={80} required /></label>
        <label className="block text-muted">Rationale<textarea className={field} name="rationale" rows={2} maxLength={2000} required /></label>
        {action === "defer" && <div className="grid gap-2 sm:grid-cols-2">
          <label className="block text-muted">Owner<input className={field} name="owner" maxLength={80} required /></label>
          <label className="block text-muted">Due date (UTC)<input className={field} name="due_date" type="date"
            min={new Date().toISOString().slice(0, 10)} required /></label>
        </div>}
        <button type="submit" disabled={busy || error?.refresh} className="rounded-md bg-accent/20 px-3 py-1.5 text-accent enabled:hover:bg-accent/30 disabled:opacity-50">
          {busy ? "Saving…" : "Save review"}
        </button>
      </form>}
      {saved && <p role="status" className="text-ok">Review saved.</p>}
      {error && <div className="flex flex-wrap gap-2" role="alert"><p className="text-high">{error.text}</p>
        {error.refresh && <button onClick={onRefresh} className="text-accent hover:underline">Refresh Risk scores</button>}
      </div>}
      {!!history?.length && <ol aria-label="Review history" className="space-y-2 border-t border-line pt-2">
        {history.map((entry) => <li key={entry.id} className="space-y-0.5 border-l border-line pl-2">
          <div className="break-words font-medium text-ink">{EVENT_LABEL[entry.action]} by {entry.reviewer}</div>
          <div className="text-faint"><time dateTime={entry.created_at}>{new Date(entry.created_at).toLocaleString()}</time> · <code>{entry.head_commit.slice(0, 12)}</code></div>
          <p className="whitespace-pre-wrap break-words text-muted">{entry.rationale}</p>
          {entry.due_date && <p className="break-words text-muted">{entry.owner} · Due {entry.due_date} UTC</p>}
        </li>)}
      </ol>}
    </section>
  );
}
