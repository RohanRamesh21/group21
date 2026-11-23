import { useCallback, useEffect, useRef, useState } from "react";
import type { FeedItem, Meta, RunState } from "./types";

export function useMeta() {
  const [meta, setMeta] = useState<Meta | null>(null);
  useEffect(() => {
    fetch("/api/meta").then((r) => r.json()).then(setMeta).catch(() => setMeta({ error: "backend offline" }));
  }, []);
  return meta;
}

export function useRun() {
  const [runId, setRunId] = useState<string | null>(null);
  const [state, setState] = useState<RunState | null>(null);
  const [feed, setFeed] = useState<FeedItem[]>([]);
  const [error, setError] = useState<string | null>(null);
  const src = useRef<EventSource | null>(null);
  const reviewToken = useRef<string | null>(null);

  const start = useCallback(async (mode: "replay" | "live", world: "canned" | "real") => {
    src.current?.close();
    reviewToken.current = null;
    setFeed([]); setState(null); setError(null);
    const r = await fetch("/api/runs", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ mode, world }),
    });
    const body = await r.json();
    if (!r.ok) { setError(body.detail ?? "could not start the run"); return; }
    reviewToken.current = body.review_token;
    setRunId(body.run_id);
    const es = new EventSource(`/api/runs/${body.run_id}/events`);
    src.current = es;
    es.addEventListener("feed", (e) => {
      const item = JSON.parse((e as MessageEvent).data) as FeedItem;
      setFeed((f) => (f.length && f[f.length - 1].seq >= item.seq ? f : [...f, item]));
    });
    es.addEventListener("state", (e) => setState(JSON.parse((e as MessageEvent).data)));
    es.addEventListener("end", () => es.close());
    es.onerror = () => es.close();
  }, []);

  const answer = useCallback(async (questionId: string, choice: number) => {
    if (!runId || !reviewToken.current) return false;
    const response = await fetch(`/api/runs/${runId}/human`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: reviewToken.current, question_id: questionId, choice }),
    });
    return response.ok;
  }, [runId]);

  useEffect(() => () => src.current?.close(), []);
  return { runId, state, feed, error, start, answer };
}
