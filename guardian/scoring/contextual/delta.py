"""Feature E: before/after delta, "verified remediation". Set operations only; no AI.

Inputs: the scored report before the fix, the scored report from a sandbox rescan after the fix, the ids of the
findings the fix targeted, and the sandbox build/test result ("pass" | "fail" | None when it was not run).
A finding is matched across the two reports by identity (kind, package name, advisory / detector type), not by id,
because an upgrade changes the version inside the id.
"""
from __future__ import annotations

from guardian.scoring.score import ORDER


def _name(comp: str) -> str:
    comp = (comp or "").replace("pkg:npm/", "")
    return comp.rsplit("@", 1)[0] if "@" in comp[1:] else comp


def ident(f: dict) -> tuple:
    if f["kind"] == "vulnerability":
        return ("vuln", (f.get("package") or {}).get("name") or _name(f.get("component", "")), (f.get("evidence") or {}).get("advisory"))
    if f["kind"] == "supply_chain":
        return ("sc", f["id"].split(":", 1)[0], _name(f.get("component", "")))
    return ("ci", f["id"])


def _lv(f: dict) -> int:
    return ORDER.index(f["level"])


def _active(scores: dict) -> list[dict]:
    return [f for f in scores["findings"] if f.get("label") != "fixed"]


def _high(f: dict) -> bool:
    """High by Guardian level OR by advisory severity: a new Critical-CVSS advisory rated "Track" by SSVC is still
    a regression a human must see when a fix is verified."""
    impact = next((c["value"] for c in f.get("contributions", []) if c["factor"] == "impact"), 0)
    return f["level"] in ("high", "critical") or impact >= 0.8


def _index(findings: list[dict]) -> float:
    return round(sum(f["score"] for f in findings if f["level"] in ("high", "critical")), 1)


def _levels(findings: list[dict]) -> dict:
    return {lv: sum(1 for f in findings if f["level"] == lv) for lv in ORDER[::-1]}


def before_after(before: dict, after: dict, target_ids: list[str], build_tests: str | None) -> dict:
    b, a = _active(before), _active(after)
    bi, ai = {ident(f): f for f in b}, {ident(f): f for f in a}
    by_id = {f["id"]: f for f in b}
    missing = [t for t in target_ids if t not in by_id]
    targets = []
    for t in target_ids:
        if t not in by_id:
            continue
        i = ident(by_id[t])
        if i not in ai:
            status = "remediated"
        else:
            d = _lv(ai[i]) - _lv(by_id[t])
            status = "reduced" if d < 0 else ("regressed" if d > 0 else "unchanged")
        targets.append({"id": t, "status": status, "before": by_id[t]["level"], "after": ai[i]["level"] if i in ai else None})
    new = [f for i, f in ai.items() if i not in bi]
    new_high = [f for f in new if _high(f)]
    new_hard = [f for f in new if f.get("floor")]
    # no_new_high: no new finding at level high+ or with high+ advisory severity (see _high)
    cond = {"target_resolved": bool(targets) and not missing and all(t["status"] == "remediated" for t in targets),
            "no_new_high": not new_high, "no_hard_signal_recreated": not new_hard,
            "build_tests_pass": build_tests == "pass"}
    failed = [k for k, v in cond.items() if not v]
    if missing:
        failed.append(f"unknown target ids: {', '.join(missing)}")
    return {
        "verified": not failed, "failed_conditions": failed, "conditions": cond,
        "build_tests": build_tests or "not_run", "targets": targets,
        "levels_before": _levels(b), "levels_after": _levels(a),
        "risk_index": {"before": _index(b), "after": _index(a), "definition": "sum of priority scores of findings at level high or above",
                       "note": "relative before/after number under the same scoring version; not an absolute risk measure"},
        "new_findings": [{"id": f["id"], "level": f["level"], "score": f["score"]} for f in new],
        "remaining_risk": [{"id": f["id"], "level": f["level"], "score": f["score"], "decision": f["decision"], "owner": None}
                           for f in sorted(a, key=lambda f: (-_lv(f), -f["score"])) if f["level"] != "low" or _high(f)][:25],
    }
