"""The remediation report (slide box 5): finding -> evidence -> approved action -> build/test -> before/after -> remaining risk -> audit.

Built only from stored records (plans, approvals, validations, audit log); it adds no new claims. Wording follows the
status machine: a plan is only called "verified" when delta.before_after said so (constitution C11).
"""
from __future__ import annotations

import html
import json

from guardian.remediation.context import RemediationContext
from guardian.remediation.models import FixPlan
from guardian.remediation.store import RemediationStore, now

STATUS_TEXT = {
    "proposed": "Recommended, waiting for a human decision",
    "approved": "Approved by a human, not applied yet",
    "rejected": "Rejected by a human",
    "escalated": "Escalated to a security reviewer",
    "applied": "Applied in a local sandbox copy (see the validation result for what was and was not proven)",
    "verified": "Verified (rescan clean, nothing new at High or above, build and tests passed)",
    "not_verified": "Applied but NOT verified (see failed conditions)",
    "failed": "Could not be applied or rescanned",
}


def _plan_entry(store: RemediationStore, p: FixPlan, ctx: RemediationContext) -> dict:
    v = store.validation(p.id)
    approvals = [a.model_dump() for a in store.approvals(p.id)]
    findings = []
    for fid in p.finding_ids:
        f = ctx.finding(fid)
        if f:
            findings.append({"id": fid, "title": f["title"], "level": f["level"], "score": f["score"], "label": f["label"], "decision": f["decision"],
                             "evidence_ids": [e for e in p.evidence_ids][:6], "advisory_url": (f.get("evidence") or {}).get("url")})
    return {
        "plan_id": p.id, "status": p.status, "status_text": STATUS_TEXT.get(p.status, p.status), "produced_by": p.produced_by,
        "findings": findings, "recommended_action": {"type": p.type, "target": p.target, "rationale": p.rationale, "claim_kind": p.claim_kind,
                                                      "forecast": p.forecast, "label": "FORECAST until a rescan proves it"},
        "upgrade_safety": p.upgrade_safety, "confidence": p.confidence, "patch_diff": p.patch.diff, "patch_notes": p.patch.notes,
        "skeptic_review": p.review.model_dump(), "plan_sha256": p.plan_sha256,
        "approval": approvals[-1] if approvals else None, "all_decisions": approvals,
        "validation": v.model_dump() if v else None,
        "before_after": (v.delta if v else None),
        "package_diff": (v.sbom_diff if v else None),
        "remaining_risk": ((v.delta or {}).get("remaining_risk") if v else None),
    }


def build(store: RemediationStore, ctx: RemediationContext) -> dict:
    plans = store.plans()
    entries = [_plan_entry(store, p, ctx) for p in plans]
    counts: dict[str, int] = {}
    for p in plans:
        counts[p.status] = counts.get(p.status, 0) + 1
    meta = store.meta()
    return {
        "run_id": store.run_id, "generated": now(), "mode": meta.get("mode"), "project": meta.get("project"),
        "summary": {"plans": len(plans), "by_status": counts, "verdict_before": ctx.scores.get("verdict"),
                    "honesty": "Recommendations are forecasts. Only a rescan after an approved, sandboxed fix proves a remediation, and only a passing "
                               "build and test run (Tier 2) allows the word 'verified'."},
        "plans": entries,
        "audit_trail": {"tool_versions": meta.get("tool_versions"), "data_timestamps": meta.get("data_timestamps"), "scores_path": meta.get("scores_path"),
                        "events": store.audit(), "approvals": [a.model_dump() for a in store.approvals()]},
        "not_checked": sorted({c for p in plans for c in (p.forecast.get("checks_not_run") or [])} | {c for p in plans if p.upgrade_safety for c in p.upgrade_safety.get("checks_not_run", [])}),
    }


def to_markdown(rep: dict) -> str:
    L = [f"# Remediation report {rep['run_id']}", "", f"Generated {rep['generated']} · mode: {rep.get('mode')} · project: {rep.get('project') or 'main scenario'}", "",
         f"> {rep['summary']['honesty']}", "", f"Plans: {rep['summary']['plans']} · by status: {json.dumps(rep['summary']['by_status'])}", ""]
    for e in rep["plans"]:
        a = e["recommended_action"]
        L += [f"## {e['plan_id']}: {a['type']} {a['target'] or ''}".rstrip(), "", f"**Status:** {e['status_text']}  ", f"**Produced by:** {e['produced_by']}  ",
              f"**Plan hash:** `{e['plan_sha256'][:16]}`", "", "### 1. Original finding(s)"]
        L += [f"- `{f['id']}` · {f['level']} · score {f['score']} · {f['label']} · {f['title']}" for f in e["findings"]]
        L += ["", "### 2. Recommended and approved action", f"- Recommended: {a['type']} {a['target'] or ''}: {a['rationale']}", f"- Basis: {a['label']}"]
        ap = e["approval"]
        L += [f"- Decision: **{ap['decision']}** by {ap['reviewer']} at {ap['at']} (plan hash `{ap['plan_sha256'][:16]}`)" + (f", note: {ap['note']}" if ap.get("note") else "")]\
            if ap else ["- Decision: none yet"]
        sk = e["skeptic_review"]
        L += ["", f"Skeptic review: **{sk['outcome']}**"] + [f"- [{c['status']}] {c['name']}: {c['detail']}" for c in sk["checks"]]
        if e["upgrade_safety"] and e["upgrade_safety"].get("applicable"):
            s = e["upgrade_safety"]
            L += ["", f"Upgrade safety: **{s['risk']}** ({s['coverage']} coverage)"] + [f"- {r}" for r in s["reasons"]]
        v = e["validation"]
        L += ["", "### 3. Build and test result"]
        L += ([f"- Tier: {v['tier']} · build/tests: **{v['build_tests']}** · outcome: **{v['outcome']}**", f"- {v['wording']}"] + [f"- {s['name']}: {s['status']}" for s in v["steps"]]) if v else ["- Not run yet"]
        L += ["", "### 4. Before and after"]
        d = e["before_after"]
        if d:
            L += [f"- Frame: {v['comparison_frame']}", f"- Levels before: {json.dumps(d['levels_before'])}", f"- Levels after: {json.dumps(d['levels_after'])}",
                  f"- Risk index (sum of High/Critical scores): {d['risk_index']['before']} -> {d['risk_index']['after']} ({d['risk_index']['note']})",
                  "- Targets: " + ", ".join(f"{t['id']} {t['status']}" for t in d["targets"]),
                  "- New findings: " + (", ".join(f"{n['id']} ({n['level']})" for n in d["new_findings"]) or "none")]
            pd = e["package_diff"] or {}
            L += [f"- Package diff: +{len(pd.get('added', []))} / -{len(pd.get('removed', []))} / changed {len(pd.get('updated', []))} ({pd.get('basis', '')})"]
        else:
            L += ["- Not available until the fix has been applied and rescanned"]
        L += ["", "### 5. Remaining or accepted risk"]
        L += [f"- `{r['id']}` · {r['level']} · {r['decision']} · owner: {r['owner'] or 'unassigned'}" for r in (e["remaining_risk"] or [])[:10]] or ["- Not available yet"]
        L += [""]
    at = rep["audit_trail"]
    L += ["## 6. Audit trail", f"- Tool versions: {json.dumps(at['tool_versions'])}", f"- Data timestamps: {json.dumps(at['data_timestamps'])}",
          f"- Not checked: {', '.join(rep['not_checked']) or 'nothing recorded'}", f"- Human decisions: {len(at['approvals'])} · events logged: {len(at['events'])}", ""]
    L += [f"  - {x['t']} {x['event']} " + json.dumps({k: v for k, v in x.items() if k not in ('t', 'event')}, default=str)[:160] for x in at["events"][-40:]]
    return "\n".join(L) + "\n"


def to_html(rep: dict) -> str:
    body = html.escape(to_markdown(rep))
    return ("<!doctype html><meta charset=utf-8><title>Remediation report</title><style>body{font:14px/1.5 system-ui;max-width:960px;margin:2rem auto;padding:0 1rem;"
            "background:#fff;color:#111}pre{white-space:pre-wrap}@media(prefers-color-scheme:dark){body{background:#111;color:#eee}}</style><pre>" + body + "</pre>")


def write(store: RemediationStore, ctx: RemediationContext) -> dict:
    rep = build(store, ctx)
    (store.root / "report.json").write_text(json.dumps(rep, indent=1, default=str))
    (store.root / "report.md").write_text(to_markdown(rep), encoding="utf-8")
    (store.root / "report.html").write_text(to_html(rep), encoding="utf-8")
    return rep
