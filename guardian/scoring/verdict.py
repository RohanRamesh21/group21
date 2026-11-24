# READING GUIDE
# Shared normal-workflow merge gate: evaluate findings introduced by the change and report scan completeness separately.
# An ALLOW verdict does not mean the whole repository is vulnerability-free; pre-existing findings remain visible.
#
"""The one verdict function. Every path (CLI check, universal scan, dashboard, agents) uses this rule.

Only findings introduced by the change can block it. Completeness is reported next to the decision:
a run whose required scanners failed is never presented as a clean result.
"""
from __future__ import annotations

SEVERE = ("high", "critical")
RULE = ("block if the change introduces a critical finding or an SSVC 'Act' decision; "
        "review if it introduces a finding of high or critical severity (CVE, supply-chain or CI), "
        "even when exploitation data lowered its priority level; otherwise allow")


# Use introduced findings for the merge recommendation while retaining completeness as a separate result.
def decide(findings: list[dict], incomplete: list[str]) -> dict:
    intro = [f for f in findings if f.get("label") == "introduced"]
    block = [f for f in intro if f["level"] == "critical" or f["decision"] == "Act"]
    review = [f for f in intro if f not in block and (f["level"] == "high" or f.get("severity") in SEVERE)]
    verdict = "block" if block else ("review" if review else "allow")
    if block:
        reasons = [f"{f['title']} ({f.get('floor') or (f.get('ssvc') or {}).get('rule') or f['level']})" for f in block]
    elif review:
        reasons = [f"{f['title']} needs a human decision (severity {f.get('severity') or f['level']})" for f in review]
    else:
        reasons = ["no high or critical risk introduced by this change"]
    return {"verdict": verdict, "reasons": reasons, "complete": not incomplete, "incomplete_reasons": list(incomplete),
            "rule": RULE}


# Collect required-check failures that prevent presenting this scan as fully checked.
def incomplete_reasons(report: dict) -> list[str]:
    """Required checks that did not run. The offline OSV copy covers npm, so an OSV API outage
    only makes an npm-only run incomplete if no other ecosystem is present."""
    h = report.get("headline", {})
    ecos = {p.get("ecosystem") for p in report.get("inventory", []) if p.get("ecosystem")}
    out = []
    for k, v in sorted(((h.get("vulnerabilities") or {}).get("errors") or {}).items()):
        if k == "osv_api" and ecos <= {"npm"}:
            continue
        out.append(f"vulnerabilities/{k}: {v}")
    for k, v in sorted(((h.get("ci_image") or {}).get("errors") or {}).items()):
        out.append(f"ci_image/{k}: {v}")
    if h.get("suspicious_error"):
        out.append(f"suspicious_changes: {h['suspicious_error']}")
    if h.get("syft_error"):
        out.append(f"inventory/syft: {h['syft_error']}")
    return out
