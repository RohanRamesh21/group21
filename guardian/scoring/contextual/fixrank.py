"""Feature D: fix-candidate generation and scoring. The LLM never proposes a fix: candidates come from here.

Generator (deterministic) -> scoring (second AHP) -> human approval -> sandbox validation (other work stream).
The numbers are a FORECAST on the data we have; only the sandbox rescan proves a fix.

Criteria (each 0..1, higher is better after inversion): risk_reduction, compatibility (1 - compat_risk),
small footprint (1 - footprint), rollback ease, evidence confidence.
Not checked (reported on every candidate): peer-dependency conflicts and `engines` mismatches.
"""
from __future__ import annotations

import re
from typing import Callable

from guardian.scoring.contextual import semver
from guardian.scoring.score import ahp

CRITERIA = ["risk_reduction", "compatibility", "footprint", "rollback", "evidence"]
MATRIX = [
    [1,     2,     4,     3,     3],
    [1 / 2, 1,     3,     2,     2],
    [1 / 4, 1 / 3, 1,     1 / 2, 1 / 2],
    [1 / 3, 1 / 2, 2,     1,     1],
    [1 / 3, 1 / 2, 2,     1,     1],
]
AHP = ahp(MATRIX, CRITERIA)
W = AHP["weights"]
JUMP_RISK = {"patch": 0.1, "minor": 0.3, "major": 0.8, None: 0.5}
ROLLBACK = {"upgrade_to_fixed": (0.8, "git revert of the lockfile/manifest change"),
            "override_transitive": (0.6, "git revert of manifest override + lockfile"),
            "remove_package": (0.8, "git revert of the manifest/lockfile change"),
            "revert_change": (1.0, "the change is itself a revert"),
            "pin_action_sha": (0.9, "git revert of one workflow line"),
            "pin_image_digest": (0.9, "git revert of one Dockerfile line"),
            "escalate": (1.0, "no change is made")}
NOT_CHECKED = ["peer_dependencies", "engines"]
NAME_VER = re.compile(r"^(@?[^@\s]+)@([^@\s]+)$")
PACKAGE_TYPES = {"typosquat", "new_install_script", "lockfile_tamper", "untrusted_source", "suspicious_update", "new_dependency"}


def _comp(f: dict) -> str:
    return (f.get("component") or "").replace("pkg:npm/", "")


def _active(f: dict) -> bool:
    return f.get("label") != "fixed"


def _points(findings: list[dict]) -> float:
    return sum(f["score"] for f in findings)


class Ctx:
    """Everything the generator needs, injectable for tests (no network in tests)."""

    def __init__(self, findings: list[dict], inventory: list[dict], affected_lookup: Callable[[list[str]], dict],
                 direct_parents: Callable[[str], list[str]] | None = None):
        self.findings = [f for f in findings if _active(f)]
        self.inventory = inventory
        self.affected_lookup = affected_lookup
        self.direct_parents = direct_parents or (lambda key: [])
        self.index_total = sum(f["score"] for f in self.findings if f["level"] in ("medium", "high", "critical")) or 1.0

    def same_component(self, f: dict) -> list[dict]:
        c = _comp(f)
        return [g for g in self.findings if _comp(g) == c]

    def copies(self, name: str, version: str) -> int:
        return sum(1 for p in self.inventory if p["name"] == name and p.get("version") == version) or 1


def _advisory(f: dict) -> str | None:
    return (f.get("evidence") or {}).get("advisory")


def _resolves(target: str, sibs: list[dict], aff: dict) -> tuple[set[str], str]:
    """Which sibling advisory findings are cleared at `target`; method says which data decided it."""
    cleared, method = set(), "osv-affected-ranges"
    for s in sibs:
        entries = [e for e in (aff.get(_advisory(s)) or []) if e.get("name") == s["package"]["name"]]
        verdicts = [semver.affected(target, e) for e in entries]
        if verdicts and all(v is not None for v in verdicts):
            if not any(verdicts):
                cleared.add(s["id"])
            continue
        method = "advisory-fixed-list"  # ranges missing/undecidable: same-major fixed version at or below target
        tp = semver.parse(target)
        if tp and any((fp := semver.parse(fx)) and fp[0] == tp[0] and fp <= tp for fx in s.get("fixed") or []):
            cleared.add(s["id"])
    return cleared, method


def _candidate(f: dict, ctype: str, target: str | None, resolves: list[dict], ctx: Ctx, compat: float, method: str,
               extra: dict | None = None) -> dict:
    comp_pts = _points(ctx.same_component(f)) or f["score"] or 1.0
    in_comp = [g for g in resolves if _comp(g) == _comp(f)]
    rr_comp = min(1.0, _points(in_comp) / comp_pts) if comp_pts else 0.0
    share = _points([g for g in resolves if g["level"] in ("medium", "high", "critical")]) / ctx.index_total
    p = f.get("package") or {}
    copies = ctx.copies(p["name"], p["version"]) if p.get("name") else 1
    footprint = 0.0 if ctype == "escalate" else min(1.0, (copies if ctype in ("upgrade_to_fixed", "override_transitive", "remove_package") else 1) / 5)
    rb_val, rb_text = ROLLBACK[ctype]
    conf = (f.get("confidence") or {}).get("value", 0.5)
    vals = {"risk_reduction": rr_comp, "compatibility": 1 - compat, "footprint": 1 - footprint, "rollback": rb_val, "evidence": conf}
    c = {"id": f"{f['id']}::{ctype}::{target or ''}", "finding": f["id"], "type": ctype, "target": target,
         "resolves": [g["id"] for g in resolves], "method": method,
         "fix_score": round(100 * sum(W[k] * vals[k] for k in CRITERIA), 1),
         "criteria": {k: round(v, 3) for k, v in vals.items()},
         "expected_risk_reduction": {"component_share": round(rr_comp, 3), "share_of_total_index": round(share, 4),
                                     "findings_cleared": len(resolves), "note": "forecast from current data; the sandbox rescan verifies"},
         "compat": {"risk": round(compat, 2), **(extra or {})}, "rollback": rb_text,
         "checks_not_run": NOT_CHECKED, "forecast": True, "approval_required": True}
    return c


def generate(f: dict, ctx: Ctx) -> list[dict]:
    """Deterministic fix candidates for one scored finding (ranked best first)."""
    out: list[dict] = []
    comp = _comp(f)
    same = ctx.same_component(f)
    if f["kind"] == "vulnerability":
        p = f["package"]
        if f.get("floor") and "malicious" in f["floor"].lower():
            reach = (f.get("reachability") or {}).get("tier")
            out.append(_candidate(f, "remove_package", None, same, ctx, {"imported": 0.9, "dev_only": 0.2, "declared": 0.4}.get(reach, 0.5),
                                  "component match", {"semver": None}))
        elif p["ecosystem"] == "npm":
            sibs = [g for g in same if g["kind"] == "vulnerability" and not (g.get("floor"))]
            ids = sorted({_advisory(g) for g in sibs if _advisory(g)})
            aff = ctx.affected_lookup(ids) if ids else {}
            versions = {fx for g in sibs for fx in g.get("fixed") or []}
            for i in ids:
                for e in aff.get(i) or []:
                    for rg in e.get("ranges") or []:
                        versions |= {ev["fixed"] for ev in rg.get("events", []) if "fixed" in ev}
            newer = sorted((v for v in versions if semver.jump(p["version"], v) not in (None, "none")),
                           key=lambda v: semver.parse(v))
            same_major = [v for v in newer if semver.jump(p["version"], v) != "major"]
            chosen: dict[str, tuple[str, list[dict], str]] = {}
            for v in same_major + [x for x in newer if x not in same_major]:  # same major first, then the rest
                cleared, method = _resolves(v, sibs, aff)
                if f["id"] in cleared and "minimal" not in chosen:
                    chosen["minimal"] = (v, [g for g in sibs if g["id"] in cleared], method)
                if len(cleared) == len(sibs) and "all" not in chosen:
                    chosen["all"] = (v, [g for g in sibs if g["id"] in cleared], method)
            distinct = {t[0]: t for t in chosen.values()}
            via = [] if p["direct"] else ctx.direct_parents(p.get("key") or "")
            for v, (tv, cleared_f, method) in distinct.items():
                ctype = "upgrade_to_fixed" if p["direct"] else "override_transitive"
                j = semver.jump(p["version"], tv)
                compat = min(1.0, JUMP_RISK[j] + (0.0 if p["direct"] else 0.15))
                out.append(_candidate(f, ctype, tv, cleared_f, ctx, compat, method, {"semver": j, "via_direct_parents": via}))
    elif f["kind"] == "supply_chain":
        t = f["id"].split(":", 1)[0]
        m = NAME_VER.match(comp)
        if t in PACKAGE_TYPES and m:
            out.append(_candidate(f, "remove_package", None, same, ctx, 0.5, "component match", {"semver": None}))
        if t == "action_sha_to_tag":
            out.append(_candidate(f, "pin_action_sha", None, same, ctx, 0.1, "component match", {"semver": None}))
        if f.get("label") == "introduced":
            out.append(_candidate(f, "revert_change", None, same, ctx, 0.2, "component match", {"semver": None}))
    elif f["kind"] == "ci_image":
        t = (f["id"].split(":")[-1] if ":" in f["id"] else "")
        if t == "image_not_pinned":
            out.append(_candidate(f, "pin_image_digest", None, same, ctx, 0.1, "component match", {"semver": None}))
        elif t == "action_not_pinned":
            out.append(_candidate(f, "pin_action_sha", None, same, ctx, 0.1, "component match", {"semver": None}))
    if not out:
        out.append(_candidate(f, "escalate", None, [], ctx, 0.0, "no automatic fix",
                              {"semver": None, "reason": "no deterministic fix candidate for this finding"}))
    return sorted(out, key=lambda c: -c["fix_score"])


def validate_proposed(proposed: dict, generated: list[dict], known_versions: set[str] | None = None) -> tuple[bool, str]:
    """Referee for any fix an agent proposes: it must be exactly one of the generated candidates.

    Catches invented versions, invented fix types and fixes for findings that do not exist."""
    for c in generated:
        if c["finding"] == proposed.get("finding") and c["type"] == proposed.get("type") and c.get("target") == proposed.get("target"):
            return True, "matches a generated candidate"
    tv = proposed.get("target")
    if tv and known_versions is not None and tv not in known_versions:
        return False, f"version {tv} appears in no advisory data for this finding"
    return False, "not a generated candidate: agents may only choose among deterministic candidates"
