import { useCallback, useEffect, useState } from "react";

/** Hash routes, so a scan or an investigation can be reloaded or shared:
 *  #/                      home: pick a source and scan it
 *  #/scan/<id>/<view>      one scan (live progress, then results); id "main" = the CLI report
 *  #/investigate[/<id>]    agent investigation, optionally of a finished scan
 */
export type View = "overview" | "graph" | "scores" | "fix";
export type Route = { page: "home" } | { page: "scan"; id: string; view: View } | { page: "investigate"; id: string | null };

const VIEWS: View[] = ["overview", "graph", "scores", "fix"];

export function parse(hash: string): Route {
  const [page, id, view] = hash.replace(/^#\/?/, "").split("/").map(decodeURIComponent);
  if (page === "scan" && id) return { page: "scan", id, view: VIEWS.includes(view as View) ? (view as View) : "overview" };
  if (page === "investigate") return { page: "investigate", id: id || null };
  return { page: "home" };
}

export function href(r: Route): string {
  if (r.page === "scan") return `#/scan/${encodeURIComponent(r.id)}/${r.view}`;
  if (r.page === "investigate") return r.id ? `#/investigate/${encodeURIComponent(r.id)}` : "#/investigate";
  return "#/";
}

export function useRoute(): [Route, (r: Route) => void] {
  const [route, setRoute] = useState<Route>(() => parse(window.location.hash));
  useEffect(() => {
    const on = () => setRoute(parse(window.location.hash));
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  const go = useCallback((r: Route) => {
    const h = href(r);
    if (window.location.hash !== h) window.location.hash = h;
    else setRoute(parse(h));
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, []);
  return [route, go];
}
