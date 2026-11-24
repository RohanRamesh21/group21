"""Per-stage run states (GUARDIAN_FINAL_PLAN.md §12.2), derived from what the engine actually recorded.

Status values: complete · partial · failed · unsupported · not_applicable · skipped (with a reason).
"""
from __future__ import annotations


def _s(sid: str, name: str, status: str, detail: str) -> dict:
    return {"id": sid, "name": name, "status": status, "detail": detail}


def stages(h: dict, compared: bool, scored: bool) -> list[dict]:
    inv = h.get("inventory") or {}
    vul = h.get("vulnerabilities") or {}
    ci = h.get("ci_image") or {}
    out = [_s("snapshot", "Snapshot", "complete", "files read from git objects; nothing executed")]
    n = inv.get("packages") or 0
    if h.get("syft_error"):
        out.append(_s("discover", "Discover components", "partial", f"Syft failed: {h['syft_error']}"))
    elif n:
        out.append(_s("discover", "Discover components", "complete", f"{n} components"))
    else:
        out.append(_s("discover", "Discover components", "not_applicable", "no third-party components found"))
    errs = vul.get("errors") or {}
    if not n:
        out.append(_s("vulnerabilities", "Known vulnerabilities", "not_applicable", "nothing to look up"))
    elif errs and len(errs) >= 2 and not any((vul.get("scanners") or {}).get(k) for k in ("osv", "grype")):
        out.append(_s("vulnerabilities", "Known vulnerabilities", "failed", "; ".join(f"{k}: {v}" for k, v in errs.items())))
    elif errs:
        out.append(_s("vulnerabilities", "Known vulnerabilities", "partial", "; ".join(f"{k}: {v}" for k, v in errs.items())))
    else:
        out.append(_s("vulnerabilities", "Known vulnerabilities", "complete", "OSV + Grype"))
    if h.get("suspicious_error"):
        out.append(_s("detectors", "Supply-chain detectors", "partial", h["suspicious_error"]))
    else:
        out.append(_s("detectors", "Supply-chain detectors", "complete", "look-alike, install scripts, sources, config, integrity"))
    total = ((ci.get("actions") or {}).get("total") or 0) + ((ci.get("images") or {}).get("total") or 0)
    cerr = ci.get("errors") or {}
    if cerr:
        out.append(_s("ci_image", "CI and images", "partial", "; ".join(f"{k}: {v}" for k, v in cerr.items())))
    elif total:
        out.append(_s("ci_image", "CI and images", "complete", f"{total} actions/images"))
    else:
        out.append(_s("ci_image", "CI and images", "not_applicable", "no workflows or images"))
    out.append(_s("compare", "Compare with base", "complete" if compared else "skipped",
                  "introduced / pre-existing / fixed" if compared else "no base revision: single scan"))
    out.append(_s("scoring", "Score and decide", "complete" if scored else "failed",
                  "floors → SSVC → priority → verdict" if scored else "scoring did not produce a result"))
    return out
