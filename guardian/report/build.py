"""Guardian report (GUARDIAN_FINAL_PLAN.md §14.4): one run folder → report.json (machines) + report.html (people).

Everything comes from files the run produced (scan report, scores, fix plan, approvals, validation, audit log).
Parts that haven't happened are labelled ("not_started", "pending: needs the AI model"), never filled in.
"""
from __future__ import annotations

import hashlib
import html
import json
import time
from pathlib import Path

from guardian import approval as ap

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "1.0"
LEVEL_ORDER = ["critical", "high", "medium", "low", "info"]


def _load(p: Path) -> dict | None:
    return json.loads(p.read_text()) if p.exists() else None


def _sha_file(p: Path) -> str | None:
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None


def _tools() -> list[dict]:
    f = ROOT / "tools.lock"
    rows = []
    for ln in f.read_text().splitlines() if f.exists() else []:
        if ln.strip() and not ln.startswith("#") and "|" in ln:
            name, ver, sha = [x.strip() for x in ln.split("|")[:3]]
            rows.append({"tool": name, "version": ver, "sha256": sha})
    return rows



def _checks(stage: dict) -> str:
    """How many tests a stage ran, read from node --test's summary lines, or the integration steps."""
    import re
    out = stage.get("output") or ""
    n = {k: sum(int(x) for x in re.findall(rf"^# {k} (\d+)", out, re.M)) for k in ("tests", "pass", "fail")}
    if n["tests"]:
        return f"{n['pass']}/{n['tests']} passed" + (f", {n['fail']} failed" if n["fail"] else "")
    steps = (stage.get("integration") or {}).get("steps") or []
    if steps:
        return f"{sum(1 for x in steps if x.get('ok'))}/{len(steps)} steps: " + " → ".join(x["step"] for x in steps)
    if stage.get("hooks"):
        return "; ".join(f"{h['name']}: {'reused verified build' if h.get('cache') == 'hit' else h.get('reason')}" for h in stage["hooks"])
    return ""

def _capability(h: dict, plan: dict | None, validation: dict | None) -> str:
    if validation and validation.get("executed") and validation["gate"]["validation"] == "passed":
        return "L4"
    if plan:
        return "L3"
    return "L2" if h.get("base_sha") else "L1"


def build(out: Path) -> dict:
    out = Path(out)
    latest = json.loads((out / "latest.json").read_text())
    report = json.loads(Path(latest["path"]).read_text())
    scores = _load(Path(latest["scores"])) if latest.get("scores") else None
    if scores:  # a human-approved AHP matrix re-weights the stored factor values (levels, decisions, verdict untouched)
        from guardian.scoring.advisor import with_active_matrix
        scores = with_active_matrix(out, scores)
    h = report["headline"]
    plan, validation = _load(out / "fix-plan.json"), _load(out / "validation.json")
    approval = ap.latest_approval(out)
    findings = sorted((scores or {}).get("findings", []), key=lambda f: (f["label"] != "introduced", LEVEL_ORDER.index(f["level"]), -f["score"]))
    run_id = f"{h.get('app')}:{(h.get('base_sha') or '')[:12]}..{h['head_sha'][:12]}"
    head_dir = Path(report["runs"]["head"])
    sboms = {k: {"file": str(head_dir / v), "sha256": _sha_file(head_dir / v)}
             for k, v in {"cyclonedx": "sbom.syft.cdx.json", "spdx": "sbom.syft.spdx.json", "guardian": "sbom.guardian.cdx.json"}.items()}

    sections: dict[str, dict] = {}
    sections["run"] = {"app": h.get("app"), "repo": h.get("repo_path"), "base_sha": h.get("base_sha"), "head_sha": h["head_sha"],
                       "verdict": h.get("verdict"), "verdict_reasons": h.get("verdict_reasons", []), "complete": h.get("complete"),
                       "incomplete_reasons": h.get("incomplete_reasons", []), "stages": h.get("stages", []),
                       "capability_level": _capability(h, plan, validation), "tools": _tools(),
                       "scan_report": {"file": latest["path"], "sha256": _sha_file(Path(latest["path"]))}}
    inv = report.get("inventory", [])
    sections["inventory"] = {"summary": h.get("inventory"), "sboms": sboms,
                             "components": [{k: p.get(k) for k in ("name", "version", "ecosystem", "direct", "runtime", "exposure",
                                                                   "source_file", "path")} for p in inv]}
    sections["findings"] = {"counts": (scores or {}).get("counts"), "method": (scores or {}).get("method", {}).get("verdict_rule"),
                            "items": [{k: f.get(k) for k in ("id", "title", "kind", "label", "level", "severity", "decision", "score",
                                                             "floor", "confidence", "evidence", "contributions", "component", "summary",
                                                             "ssvc", "counterfactuals", "reachability", "rank_stability", "fixed", "package")}
                                      for f in findings],
                            # contextual scoring: how the priority was computed, which AHP matrix scored it, fix ranking
                            "scoring": {k: (scores or {}).get("method", {}).get(k) for k in ("ahp", "ahp_active", "criteria_text", "floors", "epss_poc_threshold")}
                                       | {"data": (scores or {}).get("data"), "fix_candidates": (scores or {}).get("fix_candidates") or {},
                                          "rank_stability_summary": (scores or {}).get("rank_stability_summary"),
                                          "contextual": (scores or {}).get("contextual")}}
    agents = _load(out / "agents" / "verdict.json")
    sections["investigation"] = ({"status": "done", **agents} if agents else
                                 {"status": "pending", "reason": "live agent investigation needs the AI model (API key not configured yet)"})
    if plan:
        sections["remediation"] = {"status": "approved" if approval and approval["decision"] == "approve" else
                                   ("rejected" if approval else "proposed"),
                                   "candidates": plan.get("candidates", []), "patch": plan.get("patch"), "approval": approval,
                                   "review": plan.get("review"),
                                   "pending": plan.get("pending", [])}
    else:
        sections["remediation"] = {"status": "not_started", "reason": "no fix plan has been requested for this run"}
    if validation:
        sections["validation"] = {"status": "executed" if validation.get("executed") else "refused", **{
            k: validation.get(k) for k in ("gate", "profile", "baseline", "candidate", "approval_id", "started", "finished", "timings")}}
        sections["before_after"] = {"rescan": validation.get("rescan"), "sbom_diff": (validation.get("gate") or {}).get("sbom_diff"),
                                    "delta": validation.get("delta"), "verdict_change": validation.get("verdict_change")}
    else:
        sections["validation"] = {"status": "not_started", "reason": "no validation has run for this run"}
        sections["before_after"] = {"status": "not_started"}
    targeted = {fid for c in (plan or {}).get("candidates", []) if c["type"] != "escalate" for fid in c.get("finding_ids", [])}
    accepted = ap.accepted_risks(out)
    acc_ids = {r["finding_id"] for r in accepted}
    sections["remaining_risk"] = {"accepted": accepted,
                                  "open": [{"id": f["id"], "title": f["title"], "level": f["level"], "label": f["label"]}
                                           for f in findings if f["id"] not in targeted and f["id"] not in acc_ids and f["level"] != "info"]}
    bands = [f["confidence"]["band"] for f in findings if f["label"] == "introduced" and f.get("confidence")]
    run_band = "low" if (not h.get("complete") or "low" in bands) else ("medium" if "medium" in bands else "high")
    if validation and validation.get("executed") and validation["gate"]["validation"] != "passed":
        run_band = "low"
    sections["confidence"] = {"band": run_band, "basis": "run completeness, confidence of introduced findings, validation outcome"}
    ok, n = ap.verify_audit(out)
    log = out / "audit.jsonl"
    sections["audit"] = {"chain_ok": ok, "entries": n,
                         "events": [json.loads(ln) for ln in log.read_text().splitlines() if ln.strip()] if log.exists() else []}
    return {"schema_version": SCHEMA_VERSION, "generated": time.time(), "run_id": run_id, "sections": sections}


# ---------------------------------------------------------------- HTML
def _e(x) -> str:
    return html.escape(str(x if x is not None else "—"))


TITLES = {"run": "1 · Run", "inventory": "2 · Components & SBOM", "findings": "3 · Findings (ranked, with evidence)",
          "investigation": "4 · Investigation", "remediation": "5 · Recommended & approved action", "validation": "6 · Validation",
          "before_after": "7 · Before / after", "remaining_risk": "8 · Remaining & accepted risk", "confidence": "9 · Confidence",
          "audit": "10 · Audit trail"}


def _section_html(key: str, s: dict) -> str:
    rows = []
    if key == "run":
        rows.append(f"<p><b>{_e(s['app'])}</b> · {_e((s['base_sha'] or '')[:12])} → {_e(s['head_sha'][:12])} · decision "
                    f"<span class='v-{_e(s['verdict'])}'>{_e((s['verdict'] or 'none').upper())}</span> · "
                    f"{'complete' if s['complete'] else 'INCOMPLETE'} · capability {_e(s['capability_level'])}</p>")
        rows.append("<ul>" + "".join(f"<li>{_e(r)}</li>" for r in s["verdict_reasons"] + s["incomplete_reasons"]) + "</ul>")
        rows.append("<table><tr><th>Stage</th><th>Status</th><th>Detail</th></tr>" + "".join(
            f"<tr><td>{_e(x['name'])}</td><td>{_e(x['status'])}</td><td>{_e(x['detail'])}</td></tr>" for x in s["stages"]) + "</table>")
    elif key == "inventory":
        rows.append(f"<p>{_e(s['summary'])}</p><ul>" + "".join(
            f"<li>{_e(k)}: {_e(v['file'])} <code>{_e((v['sha256'] or 'not produced')[:16])}</code></li>" for k, v in s["sboms"].items()) + "</ul>")
        rows.append(f"<p>{len(s['components'])} components (full list in report.json).</p>")
    elif key == "findings":
        rows.append("<table><tr><th>Level</th><th>Finding</th><th>Change</th><th>Confidence</th><th>Why</th></tr>" + "".join(
            f"<tr><td class='l-{_e(f['level'])}'>{_e(f['level'])}</td><td>{_e(f['title'])}</td><td>{_e(f['label'])}</td>"
            f"<td>{_e((f.get('confidence') or {}).get('band'))}</td><td>{_e(f.get('floor') or f.get('decision'))}</td></tr>"
            for f in s["items"][:200]) + "</table>")
    elif key == "remediation" and s.get("candidates"):
        rows.append(f"<p>Status: <b>{_e(s['status'])}</b> · patch <code>{_e(s['patch']['patch_sha256'][:16])}</code> · files "
                    f"{_e(', '.join(s['patch'].get('files', [])))}</p><ul>" + "".join(
                        f"<li><b>{_e(c['type'])}</b> {_e(c.get('package') or c.get('file') or '')} {_e(c.get('from', ''))}"
                        f"{' → ' + _e(c['to']) if c.get('to') else ''}: {_e(c.get('rationale', ''))}</li>" for c in s["candidates"]) + "</ul>")
        if s.get("approval"):
            a = s["approval"]
            rows.append(f"<p>👤 {_e(a['decision'])} by {_e(a['approver'])} at {_e(time.strftime('%Y-%m-%d %H:%M', time.localtime(a['created'])))}: {_e(a['reason'])}</p>")
    elif key == "validation" and s.get("gate"):
        g = s["gate"]
        rows.append(f"<p>Target: <b>{_e(g['target'])}</b> · validation: <b>{_e(g['validation'])}</b> · verified: <b>{_e(g['verified'])}</b></p>"
                    "<ul>" + "".join(f"<li>{_e(r)}</li>" for r in g["reasons"]) + "</ul>")
        names = {"baseline": "Baseline (target branch before this PR)", "candidate": "Fixed version (PR + approved patch)"}
        for side in ("baseline", "candidate"):
            if s.get(side):
                rows.append(f"<h4>{names[side]}</h4><table><tr><th>Stage</th><th>Status</th><th>Seconds</th><th>Tests / checks</th></tr>" + "".join(
                    f"<tr><td>{_e(x['id'])}</td><td>{_e(x['status'])}</td><td>{_e(x.get('seconds'))}</td><td>{_e(_checks(x))}</td></tr>"
                    for x in s[side]["stages"]) + "</table>")
        if s.get("timings"):
            t = s["timings"]
            rows.append(f"<p>Took {_e(t.get('total'))} s (baseline, fixed version and rescan in parallel; SBOMs {_e(t.get('sbom'))} s).</p>")
    elif key == "before_after" and (s.get("verdict_change") or {}).get("before"):
        b, a = s["verdict_change"]["before"], s["verdict_change"]["after"]
        groups = [("vulnerabilities", "Known vulnerabilities (CVE / GHSA)"), ("malware_suspicious", "Malware & suspicious packages"),
                  ("config_ci", "Config & CI changes"), ("other", "Dependency version changes (low, info)")]
        rows.append(f"<p>Decision: <b>{_e(str(b['verdict']).upper())}</b> as submitted → <b>{_e(str(a['verdict']).upper())}</b> with the approved fix (same engine, same advisory snapshot).</p>"
                    "<table><tr><th>Introduced by this PR</th><th>Before</th><th>After the fix</th></tr>" + "".join(
                        f"<tr><td>{_e(lbl)}</td><td>{_e(b['introduced'][k])}</td><td>{_e(a['introduced'][k])}</td></tr>" for k, lbl in groups)
                    + f"<tr><td>High / critical (level or advisory severity)</td><td>{_e(b['high_or_critical'])}</td><td>{_e(a['high_or_critical'])}</td></tr></table>"
                    f"<p>{_e(a['pre_existing'])} older findings were already in the project before this PR; they are unchanged and listed separately.</p>")
    elif key == "remaining_risk":
        rows.append("<h4>Accepted</h4><ul>" + "".join(f"<li>{_e(r['finding_id'])}: {_e(r['reason'])} (owner {_e(r['owner'])})</li>"
                                                       for r in s["accepted"]) + "</ul>")
        rows.append(f"<p>{len(s['open'])} open findings not covered by the fix (listed in report.json).</p>")
    elif key == "confidence":
        rows.append(f"<p>Overall confidence: <b>{_e(s['band'])}</b> ({_e(s['basis'])})</p>")
    elif key == "audit":
        rows.append(f"<p>Hash chain intact: <b>{_e(s['chain_ok'])}</b> · {s['entries']} entries</p>")
    else:
        rows.append(f"<p>{_e(s.get('status'))}{': ' + _e(s.get('reason')) if s.get('reason') else ''}</p>")
    return f'<section id="{key}">' + f"<h2>{_e(TITLES[key])}</h2>{''.join(rows)}</section>"


def to_html(rep: dict) -> str:
    css = ("body{font:14px/1.5 system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#111}"
           "h1{margin-bottom:.2rem}table{border-collapse:collapse;width:100%;margin:.5rem 0}td,th{border:1px solid #ddd;padding:4px 6px;text-align:left;vertical-align:top}"
           "section{border-top:2px solid #eee;margin-top:1.5rem}.v-block,.l-critical{color:#b00020;font-weight:600}.v-review,.l-high{color:#b35c00;font-weight:600}"
           ".v-allow{color:#11702a;font-weight:600}code{background:#f4f4f4;padding:0 3px}")
    body = "".join(_section_html(k, v) for k, v in rep["sections"].items())
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>Guardian report {_e(rep['run_id'])}</title><style>{css}</style></head>"
            f"<body><h1>Guardian report</h1><p>{_e(rep['run_id'])} · generated {_e(time.strftime('%Y-%m-%d %H:%M', time.localtime(rep['generated'])))}"
            f" · schema {_e(rep['schema_version'])} · machine-readable twin: report.json</p>{body}</body></html>")


def write(out: Path) -> dict:
    rep = build(out)
    j, h = Path(out) / "report.json", Path(out) / "report.html"
    j.write_text(json.dumps(rep, indent=1))
    h.write_text(to_html(rep))
    return {"json": str(j), "html": str(h), "sha256": hashlib.sha256(j.read_bytes()).hexdigest()}
