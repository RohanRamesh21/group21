"""Loads the scored report a remediation run works on, and exposes it read-only to the Fixer and the rule-based path.

Remediation works on the SCORED findings (ids like `foo@1.2.0#GHSA-1`), not on the investigation board (`F-xx` ids): they
are separate id spaces. Everything here is read-only: nothing is installed, executed or fetched except registry metadata.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from guardian.scoring import intel

ROOT = Path(__file__).resolve().parents[2]


def _abs(p: str | Path) -> Path:
    p = Path(p)
    return p if p.is_absolute() else ROOT / p


def tree_of(run_dir: str | None) -> Path | None:
    """The exported project tree of a scan run (src/ or trees/head), if it exists on disk."""
    if not run_dir:
        return None
    base = _abs(run_dir)
    for rel in ("src", "trees/head", "trees/base"):
        if (base / rel / "package.json").exists() or (base / rel).is_dir():
            return base / rel
    return None


class RemediationContext:
    def __init__(self, scores: dict, report: dict, src: Path | None = None, base_src: Path | None = None,
                 affected_lookup: Callable[[list[str]], dict] | None = None, project: str | None = None,
                 scores_path: str | None = None, report_path: str | None = None):
        self.scores, self.report = scores, report
        runs = report.get("runs") or {}
        self.src = src if src is not None else tree_of(runs.get("head"))
        self.base_src = base_src if base_src is not None else tree_of(runs.get("base"))
        self.affected_lookup = affected_lookup or intel.osv_affected
        self.project, self.scores_path, self.report_path = project, scores_path, report_path
        self.findings: dict[str, dict] = {f["id"]: f for f in scores["findings"]}
        self.candidates: dict[str, list[dict]] = scores.get("fix_candidates") or {}
        self.inventory: list[dict] = report.get("inventory", [])
        self.app_manifest: dict | None = None
        if self.src and (self.src / "package.json").is_file():
            try:
                self.app_manifest = json.loads((self.src / "package.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                self.app_manifest = None

    @classmethod
    def load(cls, project: str | None = None, affected_lookup=None) -> "RemediationContext":
        from guardian import projects
        d = projects.out_dir(project)
        latest = d / "latest.json"
        if not latest.exists():
            raise FileNotFoundError("no check report yet: run `guardian check <repo> --base <ref> --head <ref>` first")
        ptr = json.loads(latest.read_text())
        if not ptr.get("scores"):
            raise FileNotFoundError("the latest check has no scores file (scoring failed: see scores_error in latest.json)")
        report, scores = json.loads(_abs(ptr["path"]).read_text()), json.loads(_abs(ptr["scores"]).read_text())
        from guardian.scoring.advisor import with_active_matrix  # priorities follow the human-approved AHP matrix, like the dashboard
        scores = with_active_matrix(d, scores)
        return cls(scores, report, affected_lookup=affected_lookup, project=project, scores_path=ptr["scores"], report_path=ptr["path"])

    @classmethod
    def from_paths(cls, scores_path: str, report_path: str, project: str | None = None, affected_lookup=None) -> "RemediationContext":
        """Reload the exact scored report a stored run was built on (the 'latest' pointer may have moved on)."""
        return cls(json.loads(_abs(scores_path).read_text()), json.loads(_abs(report_path).read_text()), affected_lookup=affected_lookup,
                   project=project, scores_path=scores_path, report_path=report_path)

    # ---- read-only views -----------------------------------------------------
    def finding(self, fid: str) -> dict | None:
        return self.findings.get(fid)

    def cands(self, fid: str) -> list[dict]:
        return self.candidates.get(fid, [])

    def priority(self, n: int = 5, covered: set[str] | None = None) -> list[dict]:
        """Top-N scored findings that have fix candidates, best first. `covered` ids are skipped (already planned)."""
        out = []
        for f in self.scores["findings"]:  # already sorted: level, then AHP score
            if f.get("label") == "fixed" or f["id"] not in self.candidates or (covered and f["id"] in covered):
                continue
            out.append(self.card(f))
            if len(out) >= n:
                break
        return out

    def card(self, f: dict) -> dict:
        r, c = f.get("reachability") or {}, f.get("confidence") or {}
        return {"id": f["id"], "title": f["title"], "kind": f["kind"], "level": f["level"], "score": f["score"], "decision": f["decision"],
                "label": f["label"], "hard_signal": bool(f.get("floor")), "floor": f.get("floor"), "component": f.get("component"),
                "fixed_versions": f.get("fixed", []), "reachability": r.get("tier"), "confidence": c.get("band"),
                "confidence_value": c.get("value"), "confidence_missing": c.get("missing", []), "rank_stability": f.get("rank_stability"),
                "candidates": len(self.candidates.get(f["id"], []))}
