"""Contextual enrichment: adds fields to the existing score report; never changes level, decision, floor or verdict.

Order: reachability (before scoring, in check.py) -> confidence -> rank stability -> fix candidates -> human-check notes.
A runtime invariant checks that level/decision/floor/verdict are untouched by the enrichment.
"""
from __future__ import annotations

import json
from pathlib import Path

from guardian.scoring import intel
from guardian.scoring.contextual import confidence, fixrank, reachability, sensitivity

VERSION = "contextual-0.1"
ROOT = Path(__file__).resolve().parents[3]


def reach_for_report(report: dict) -> tuple[dict, str | None]:
    """(reachability by vulnerability key, error). An error never stops scoring: it is reported as not checked."""
    try:
        r = reachability.for_report(report)
        return r, None if r else "reachability not computed: no source tree or edges.json for the head run"
    except Exception as e:
        return {}, f"reachability failed ({type(e).__name__}: {e})"[:200]


def _edges(report: dict) -> list[dict]:
    head = (report.get("runs") or {}).get("head")
    if not head:
        return []
    p = (Path(head) if Path(head).is_absolute() else ROOT / head) / "edges.json"
    return json.loads(p.read_text()) if p.exists() else []


def _direct_parents(inventory: list[dict], edges: list[dict]):
    from collections import defaultdict, deque
    kids = defaultdict(list)
    for e in edges:
        kids[e["parent"]].append(e["child"])
    name = {p["key"]: f"{p['name']}@{p.get('version')}" for p in inventory}

    def parents(key: str) -> list[str]:
        out = []
        for top in kids.get("", []):
            q, seen = deque([top]), {top}
            while q:
                cur = q.popleft()
                if cur == key:
                    out.append(name.get(top, top))
                    break
                for c in kids.get(cur, []):
                    if c not in seen:
                        seen.add(c)
                        q.append(c)
        return sorted(set(out))
    return parents


def enrich(scores: dict, report: dict, reach_error: str | None = None, affected_lookup=None, fix_for: str = "relevant") -> dict:
    """Mutates and returns `scores`. `fix_for`: "relevant" = introduced or high/critical findings; "all" = every finding."""
    findings = scores["findings"]
    snapshot = ([(f["id"], f["level"], f["decision"], f["floor"]) for f in findings], scores["verdict"])
    errors = (scores.get("data") or {}).get("errors") or []
    not_checked = [e for e in [reach_error] if e]

    for f in findings:
        f["confidence"] = confidence.confidence(f, errors)

    rs = sensitivity.rank_stability(findings)
    for f in findings:
        f["rank_stability"] = rs["per_finding"][f["id"]]

    inv = report.get("inventory", [])
    ctx = fixrank.Ctx(findings, inv, affected_lookup or intel.osv_affected, _direct_parents(inv, _edges(report)))
    fixes = {}
    for f in findings:
        if f.get("label") == "fixed" or (fix_for == "relevant" and not (f["label"] == "introduced" or f["level"] in ("high", "critical"))):
            continue
        try:
            fixes[f["id"]] = fixrank.generate(f, ctx)
        except Exception as e:  # no silent failure: say which finding got no candidates
            not_checked.append(f"fix candidates for {f['id']} failed ({type(e).__name__}: {e})"[:200])

    checks = [f for f in findings if f["label"] == "introduced" and f["level"] in ("high", "critical") and f["confidence"]["band"] == "low"]
    notes = [f"{f['title']}: low confidence, needs a human check ({'; '.join(f['confidence']['missing'][:3])})" for f in checks]
    scores["reasons"] = list(scores["reasons"]) + notes
    scores["fix_candidates"] = fixes
    scores["rank_stability_summary"] = rs["summary"]
    scores["contextual"] = {"version": VERSION, "confidence_ahp": confidence.AHP, "fix_ahp": fixrank.AHP, "human_checks": [f["id"] for f in checks],
                      "reachability": {"computed": sum(1 for f in findings if f.get("reachability")), "note": "estimated by a static import scan"},
                      "not_checked": not_checked}
    after = ([(f["id"], f["level"], f["decision"], f["floor"]) for f in findings], scores["verdict"])
    if after != snapshot:  # the enrichment must be purely additive
        raise AssertionError("Contextual enrichment changed a level, decision, floor or verdict")
    return scores
