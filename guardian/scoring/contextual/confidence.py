"""Feature B: confidence level. "How sure are we about this finding?" (separate from how severe it is).

Six evidence-quality signals, each 0 / 0.5 / 1 or *not applicable*, combined with AHP weights (consistency ratio
is checked by a test). Not-applicable signals are dropped and the remaining weights renormalised, so malware or a
registry redirect is not penalised for having no CVSS vector.

Confidence is informational. It never changes a level, decision, floor or verdict (it may only add a
"needs human check" note for an introduced high/critical finding with low confidence).
"""
from __future__ import annotations

from guardian.scoring.score import ahp

SIGNALS = ["corroboration", "cvss_vector", "exploit_data", "reachability", "fix_evidence", "evidence_completeness"]
# Saaty judgements (row vs column). Corroboration (is it real?) matters most; completeness and CVSS next.
MATRIX = [
    [1,     2,     3,     3,     4,     2],
    [1 / 2, 1,     2,     2,     3,     1],
    [1 / 3, 1 / 2, 1,     1,     2,     1 / 2],
    [1 / 3, 1 / 2, 1,     1,     2,     1 / 2],
    [1 / 4, 1 / 3, 1 / 2, 1 / 2, 1,     1 / 3],
    [1 / 2, 1,     2,     2,     3,     1],
]
AHP = ahp(MATRIX, SIGNALS)
BANDS = [(0.80, "high"), (0.50, "medium"), (0.0, "low")]
MISSING_TEXT = {
    "corroboration": "only one scanner reports it" ,
    "cvss_vector": "no CVSS vector (severity word only)",
    "exploit_data": "EPSS/KEV unknown",
    "reachability": "reachability not determined",
    "fix_evidence": "fix version not corroborated",
    "evidence_completeness": "evidence incomplete (lockfile line / file / advisory link)",
}


def _fraction(vals: list) -> float:
    n = sum(1 for v in vals if v not in (None, "", [], 0))
    return 1.0 if n >= len(vals) else (0.5 if n == len(vals) - 1 and len(vals) > 1 else 0.0)


def signals_for(f: dict, data_errors: list[str] | None = None) -> dict[str, float | None]:
    """Signal values for one scored finding; None = not applicable."""
    ev, errs = f.get("evidence") or {}, " ".join(data_errors or [])
    sig: dict[str, float | None] = dict.fromkeys(SIGNALS)
    if f["kind"] == "vulnerability":
        malicious = f.get("floor") and "malicious" in (f["floor"] or "").lower()
        srcs = len(ev.get("sources") or [])
        sig["corroboration"] = 1.0 if (malicious or srcs >= 2) else (0.5 if srcs == 1 else 0.0)
        if not malicious:
            sig["cvss_vector"] = 1.0 if ev.get("cvss_vector") else 0.5
            known = bool(ev.get("kev") or ev.get("epss"))
            sig["exploit_data"] = (0.5 if "EPSS" in errs or "KEV" in errs else 1.0) if known else 0.0
            sig["fix_evidence"] = (1.0 if srcs >= 2 else 0.5) if f.get("fixed") else 0.0
            r = ev.get("reachability") or {}
            sig["reachability"] = 0.0 if r.get("status", "unknown") == "unknown" else (1.0 if r.get("evidence") else 0.5)
        sig["evidence_completeness"] = _fraction([ev.get("lockfile_line") or ev.get("file"), ev.get("url"), ev.get("advisory")])
    elif f["kind"] == "supply_chain":
        sig["corroboration"] = 1.0 if (ev.get("lockfile_line") or ev.get("file")) and ev.get("detector") else 0.5
        sig["evidence_completeness"] = _fraction([ev.get("lockfile_line") or ev.get("file"), ev.get("detector"), ev.get("resolved") or f.get("summary")])
    else:  # ci_image
        sig["corroboration"] = 1.0 if ev.get("file") and ev.get("line") else 0.5
        sig["evidence_completeness"] = _fraction([ev.get("file"), ev.get("line"), ev.get("url") or f.get("summary")])
    return sig


def confidence(f: dict, data_errors: list[str] | None = None) -> dict:
    sig = signals_for(f, data_errors)
    use = {k: v for k, v in sig.items() if v is not None}
    wsum = sum(AHP["weights"][k] for k in use)
    value = sum(AHP["weights"][k] * v for k, v in use.items()) / wsum
    band = next(b for t, b in BANDS if value >= t)
    return {"value": round(value, 3), "band": band, "signals": sig,
            "missing": [MISSING_TEXT[k] for k, v in use.items() if v < 1.0]}
