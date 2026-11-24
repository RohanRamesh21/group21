"""Runs the contextual scoring (guardian/scoring/contextual, from the contextual-scoring branch) inside our engine.

Order: reachability (static import scan of the head tree) -> score_report with the human-approved AHP weights (if any)
-> contextual enrichment (confidence, rank stability, fix candidates, human-check notes).

Two reconciliations with this codebase:
  * Confidence: the contextual AHP-weighted confidence (6 evidence signals) is the band shown everywhere. Our earlier
    5 data-quality checks (collection, applicability, freshness, contradictions, evidence) are kept under
    `confidence.dimensions`, so nothing that reads them breaks.
  * Human-check notes: the contextual pipeline writes them from its own band, so ours are dropped to avoid duplicates.
If the enrichment itself fails, the base scores stand and the failure is listed under contextual.not_checked.
"""
from __future__ import annotations

from pathlib import Path

from guardian.scoring.advisor import active_weights
from guardian.scoring.contextual import reachability
from guardian.scoring.contextual.pipeline import VERSION, enrich
from guardian.scoring.score import score_report


def _reach(report: dict, src: Path | None) -> tuple[dict, str | None]:
    """Reachability from the FULL first-party source tree. Our scan folder's src/ keeps only manifests, so the engine
    passes the exported head tree. With no source files at all the result is 'not computed', never 'declared'
    (which would wrongly lower CVE exposure for every runtime package)."""
    try:
        src = Path(src) if src else reachability._find_src(report)
        if src is None or reachability.scan_imports(src)["files"] == 0:
            return {}, "reachability not computed: no first-party source files found in the scanned tree"
        r = reachability.for_report(report, src=src)
        return r, None if r else "reachability not computed: no edges.json for the head run"
    except Exception as e:
        return {}, f"reachability failed ({type(e).__name__}: {e})"[:200]


def score_with_context(report: dict, out: Path, src: Path | None = None) -> dict:
    reach, reach_err = _reach(report, src)
    aw, ainfo = active_weights(Path(out))
    scores = score_report(report, reach=reach, weights=aw, matrix_info=ainfo)
    ours = {f["id"]: f.get("confidence") for f in scores["findings"]}
    own_checks = [r for r in scores["reasons"] if r.startswith("needs human check:")]
    scores["reasons"] = [r for r in scores["reasons"] if not r.startswith("needs human check:")]
    try:
        enrich(scores, report, reach_error=reach_err, weights=aw)
    except AssertionError:
        raise  # the enrichment changed a level/decision/floor/verdict: never hide that
    except Exception as e:
        for f in scores["findings"]:
            f["confidence"] = ours[f["id"]]
        scores["reasons"] += own_checks
        scores["contextual"] = {"version": VERSION, "not_checked": [f"contextual scoring failed ({type(e).__name__}: {e})"[:200]]}
        return scores
    for f in scores["findings"]:
        o = ours.get(f["id"]) or {}
        if o.get("dimensions"):
            f["confidence"]["dimensions"] = o["dimensions"]
            f["confidence"]["data_checks"] = {"band": o.get("band"), "missing": o.get("missing", [])}
    return scores
