"""Stretch goal 6: continuous monitoring. Re-check a scanned application for newly disclosed vulnerabilities.

No rescan of the code is needed: the saved inventory (exact name@version of every component) is queried against
OSV.dev again, the CISA KEV catalog and EPSS are refreshed, and the risk is re-scored. Each run appends to
<project out>/monitor.json:
  new_advisories    advisories that did not exist (or did not match) when the report was made
  newly_exploited   CVEs already in the report that have since entered CISA KEV
  verdict_before / verdict_after
Run once (`guardian watch --once`), on an interval (`guardian watch --interval 60`), or let the dashboard server do it
(GUARDIAN_MONITOR_INTERVAL=<minutes>). Nothing is changed in the repository.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _resolve(p: str) -> Path:
    q = Path(p)
    return q if q.is_absolute() else ROOT / q


def recheck(out: Path) -> dict:
    """One monitoring pass over the latest report in `out` (a check directory)."""
    from guardian.scoring import intel
    from guardian.scoring.score import score_report
    from guardian.universal import osv_api

    ptr = json.loads((out / "latest.json").read_text())
    report = json.loads(_resolve(ptr["path"]).read_text())
    old_scores = json.loads(_resolve(ptr["scores"]).read_text()) if ptr.get("scores") else {}
    entry = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "report": ptr["path"], "components": 0,
             "new_advisories": [], "newly_exploited": [], "verdict_before": report["headline"].get("verdict"),
             "verdict_after": None, "error": None}
    current = [v for v in report.get("vulnerabilities", []) if v.get("label") != "fixed"]
    known = {(v["name"], v["version"], i) for v in current for i in v.get("ids", [])}
    inv = [p for p in report.get("inventory", []) if p.get("version") and not p.get("first_party")]
    entry["components"] = len(inv)
    fresh, err = osv_api(inv)
    if err:
        entry["error"] = err
    new = []
    for a in fresh:
        if not any((a["name"], a["version"], i) in known for i in a["ids"]):
            new.append(a)
    # KEV / EPSS refresh: a known CVE that is now exploited in the wild changes its decision to Act
    kev_before = {f["evidence"].get("cve") for f in old_scores.get("findings", []) if (f.get("evidence") or {}).get("kev")}
    kev_now, kev_err = intel.kev(max_age=3600)
    if kev_err and not entry["error"]:
        entry["error"] = kev_err
    cves = {(f.get("evidence") or {}).get("cve"): f for f in old_scores.get("findings", []) if (f.get("evidence") or {}).get("cve")}
    entry["newly_exploited"] = sorted({f"{f['component']} {c}" for c, f in cves.items() if c in kev_now and c not in kev_before})
    # re-score with the new advisories added as present (not introduced: the code did not change)
    added = []
    for a in new:
        p = next((x for x in inv if x["name"] == a["name"] and x["version"] == a["version"]), {})
        added.append({**a, "id": next((i for i in a["ids"] if i.startswith(("MAL-", "GHSA-"))), a["ids"][0]),
                      "key": f"{a['name']}@{a['version']}#{a['ids'][0]}", "sources": ["osv"], "label": "pre_existing",
                      "newly_disclosed": True, "direct": bool(p.get("direct")), "runtime": bool(p.get("runtime")),
                      "component_key": p.get("key"), "source_file": p.get("source_file")})
    entry["new_advisories"] = sorted({f"{a['name']}@{a['version']} {a['id']} ({a['severity']})" for a in added})
    updated = {**report, "vulnerabilities": report.get("vulnerabilities", []) + added}
    rescored = score_report(updated)
    # the final verdict also includes policy-as-code; re-evaluate it with the new advisories (fall back to the stored result)
    from guardian import policy as pac
    pol = pac.evaluate(updated) if added else (report.get("policy") or {})
    if pol.get("error"):
        pol = report.get("policy") or {}
    entry["verdict_after"] = pac.combine(rescored["verdict"], pol)
    entry["levels_after"] = {lv: sum(n.values()) for lv, n in rescored["counts"].items()}
    entry["levels_before"] = {lv: sum(n.values()) for lv, n in old_scores.get("counts", {}).items()}
    hist_file = out / "monitor.json"
    hist = json.loads(hist_file.read_text()) if hist_file.exists() else {"history": []}
    hist["history"] = ([entry] + hist["history"])[:50]
    hist_file.write_text(json.dumps(hist, indent=1))
    return entry


def history(out: Path) -> dict:
    f = out / "monitor.json"
    return json.loads(f.read_text()) if f.exists() else {"history": []}


def targets(all_projects: bool, project: str | None) -> list[tuple[str, Path]]:
    from guardian import projects
    if project:
        return [(project, projects.out_dir(project))]
    out = [("main", projects.out_dir(None))]
    if all_projects:
        out += [(j["id"], projects.out_dir(j["id"])) for j in projects.list_jobs() if j.get("status") == "done"]
    return [(n, d) for n, d in out if (d / "latest.json").exists()]
