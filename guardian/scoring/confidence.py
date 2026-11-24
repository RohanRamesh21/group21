"""Confidence: how complete and consistent the evidence behind a finding is (not how severe it is).

Five named dimensions, each ok / weak / missing / not_applicable, with a reason. No weights:
  high   = nothing weak or missing
  medium = something weak, nothing missing
  low    = something missing
Confidence never changes a level, decision or verdict. It is informational, and low confidence on an introduced
High/Critical finding asks for a human check.
"""
from __future__ import annotations

ORDER = ["low", "medium", "high"]
DIMENSIONS = ("collection", "applicability", "freshness", "contradictions", "evidence")


def _d(status: str, why: str) -> dict:
    return {"status": status, "why": why}


def _collection(f: dict, incomplete: list[str]) -> dict:
    area = "vulnerabilities/" if f["kind"] == "vulnerability" else "ci_image/" if f["kind"] == "ci_image" else "suspicious_changes"
    hits = [r for r in incomplete if r.startswith(area)]
    if f["kind"] == "vulnerability":
        scanners = {r.split("/", 1)[1].split(":", 1)[0] for r in hits}
        if {"osv", "osv_api", "osv_offline"} & scanners and "grype" in scanners:
            return _d("missing", "no vulnerability scanner completed")
        if hits:
            return _d("weak", f"a scanner did not complete: {'; '.join(hits)}")
        return _d("ok", "all vulnerability scanners completed")
    if hits:
        return _d("missing", f"the check that produces this finding did not complete: {'; '.join(hits)}")
    return _d("ok", "the producing check completed")


def _applicability(f: dict) -> dict:
    if f["kind"] != "vulnerability":
        return _d("not_applicable", "not an advisory match")
    ver = f.get("version")
    if ver is None:
        comp = f.get("component", "")
        ver = comp.rsplit("@", 1)[1] if "@" in comp[1:] else ""
    if not ver:
        return _d("missing", "exact installed version unknown, so the affected-range match can't be confirmed")
    return _d("ok", f"exact version {ver} matched against the advisory's affected ranges")


def _freshness(f: dict, intel_errors: list[str]) -> dict:
    if f["kind"] != "vulnerability":
        return _d("not_applicable", "no external threat data used")
    if intel_errors:
        return _d("weak", f"exploit data unavailable or stale: {'; '.join(intel_errors)}")
    return _d("ok", "EPSS and KEV loaded (cached at most one day)")


def _contradictions(f: dict) -> dict:
    if f["kind"] != "vulnerability":
        return _d("not_applicable", "single deterministic detector")
    by_src = (f.get("evidence") or {}).get("severity_by_source") or {}
    if len(set(by_src.values())) > 1:
        return _d("weak", "sources disagree on severity: " + ", ".join(f"{k} {v}" for k, v in sorted(by_src.items())))
    return _d("ok", "no disagreement between sources")


def _evidence(f: dict) -> dict:
    ev = f.get("evidence") or {}
    kind = f["kind"]
    if kind == "vulnerability":
        need = {"lockfile/manifest location": bool(ev.get("file") or ev.get("lockfile_line")),
                "advisory record": bool(ev.get("advisory"))}
    elif kind == "ci_image":
        need = {"file": bool(ev.get("file")), "line": ev.get("line") is not None}
    else:  # supply-chain: config redirects need the file; package signals need the lockfile entry
        need = {"file or lockfile entry": bool(ev.get("file") or ev.get("lockfile_line") or ev.get("resolved"))}
        if ev.get("detector") is None and f.get("type") is None:
            need["detector"] = False
    absent = [k for k, ok in need.items() if not ok]
    if not absent:
        return _d("ok", "all evidence required for this finding type is stored")
    if len(absent) < len(need):
        return _d("weak", f"missing: {', '.join(absent)}")
    return _d("missing", f"missing: {', '.join(absent)}")


def confidence(f: dict, ctx: dict) -> dict:
    dims = {"collection": _collection(f, ctx.get("incomplete", [])), "applicability": _applicability(f),
            "freshness": _freshness(f, ctx.get("intel_errors", [])), "contradictions": _contradictions(f),
            "evidence": _evidence(f)}
    states = {d["status"] for d in dims.values()}
    band = "low" if "missing" in states else "medium" if "weak" in states else "high"
    return {"band": band, "dimensions": dims,
            "missing": [f"{k}: {d['why']}" for k, d in dims.items() if d["status"] in ("missing", "weak")]}
