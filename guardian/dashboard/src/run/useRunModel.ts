import { useCallback, useEffect, useState } from "react";
import { api, q, type RunModel } from "./shared";

/** Loads /api/run (the same model the Guardian report is built from) for the selected project. */
export function useRunModel(project: string | null) {
  const [model, setModel] = useState<RunModel | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const load = useCallback(async () => {
    try { setErr(null); setModel(await api(`/api/run${q(project)}`)); } catch (e) { setModel(null); setErr((e as Error).message); }
  }, [project]);
  useEffect(() => { load(); }, [load]);
  return { model, err, refresh: load };
}
