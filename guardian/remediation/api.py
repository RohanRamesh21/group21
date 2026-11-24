"""HTTP API for the remediation chain (mounted by guardian/server.py).

The human decision endpoint is the ONLY writer of approvals; no agent tool maps to it. Apply refuses without a matching approval.
"""
from __future__ import annotations

import threading
import time

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from guardian.remediation import apply as applier
from guardian.remediation import report as reporter
from guardian.remediation import runner, service, validate
from guardian.remediation.context import RemediationContext
from guardian.remediation.store import BASE, RemediationStore

router = APIRouter(prefix="/api/remediation")
RUNS: dict[str, dict] = {}
JOBS: dict[tuple[str, str], dict] = {}
_LOCK = threading.Lock()


class StartReq(BaseModel):
    project: str | None = None
    top_n: int = 3
    mode: str = "rule_based"  # rule_based | agent | replay


class DecisionReq(BaseModel):
    decision: str
    reviewer: str
    note: str | None = None


class ApplyReq(BaseModel):
    tier: str = "tier1"  # tier1 | tier2


def _load(run_id: str) -> dict:
    with _LOCK:
        if run_id in RUNS:
            return RUNS[run_id]
    if not (BASE / run_id / "run.json").exists():
        raise HTTPException(404, "unknown remediation run")
    store = RemediationStore(run_id)
    meta = store.meta()
    try:
        ctx = RemediationContext.from_paths(meta["scores_path"], meta["report_path"], meta.get("project"))
    except Exception as e:
        raise HTTPException(500, f"cannot reload the scored report of this run: {e}")
    entry = {"rem": service.Remediator(ctx, store), "status": "done", "error": None}
    with _LOCK:
        RUNS[run_id] = entry
    return entry


@router.post("/runs")
def start(req: StartReq):
    if req.mode not in runner.MODES:
        raise HTTPException(400, f"mode must be one of {runner.MODES}")
    try:
        ctx = RemediationContext.load(req.project)
    except (FileNotFoundError, KeyError) as e:
        raise HTTPException(404, str(e))
    rem = service.open_run(ctx)
    store, run_id = rem.store, rem.store.run_id
    entry = {"rem": rem, "status": "running", "error": None, "started": time.time()}
    with _LOCK:
        RUNS[run_id] = entry
    store.save_meta(service.run_meta(ctx, req.mode))

    def work():
        try:
            runner.run_remediation(rem, req.mode, max(1, min(req.top_n, 10)))
            entry["status"] = "done"
        except BaseException as e:  # noqa: BLE001  surface any failure to the UI
            entry["status"], entry["error"] = "error", f"{type(e).__name__}: {e}"[:400]
    threading.Thread(target=work, daemon=True, name=run_id).start()
    return {"run_id": run_id}


@router.get("/runs")
def list_runs():
    out = []
    if BASE.exists():
        for d in sorted(BASE.iterdir(), key=lambda p: -p.stat().st_mtime):
            if (d / "run.json").exists():
                m = RemediationStore(d.name).meta()
                out.append({"run_id": d.name, "mode": m.get("mode_used") or m.get("mode"), "created": m.get("created"), "project": m.get("project")})
    return out


@router.get("/{run_id}")
def get_run(run_id: str):
    e = _load(run_id)
    status, error = e["status"], e.get("error")  # read BEFORE the plans: a 'done' status then always comes with the finished plans
    rem: service.Remediator = e["rem"]
    s = rem.store
    plans = [p.model_dump() for p in s.plans()]
    for p in plans:  # fixed-size text only: the diff and notes are shown, evidence content is fetched on demand
        v = s.validation(p["id"])
        p["validation"] = v.model_dump() if v else None
        p["decisions"] = [a.model_dump() for a in s.approvals(p["id"])]
        p["job"] = JOBS.get((run_id, p["id"]))
    msgs = [x for x in s.audit() if x["event"] in ("message", "rejected", "fallback", "prompt_injection", "tamper_detected", "apply_refused", "decision", "applied", "validated", "denied_tool")]
    return {"run_id": run_id, "status": status, "error": error, "meta": s.meta(), "plans": plans, "messages": msgs,
            "priority": rem.ctx.priority(10), "tier2": {"configured": "@sha256:" in validate.tier2_config()["image"]}}


@router.get("/{run_id}/evidence/{eid}")
def evidence(run_id: str, eid: str):
    s = _load(run_id)["rem"].store
    if not s.evidence.exists(eid):
        raise HTTPException(404, "unknown evidence id")
    ev = s.evidence.get(eid)
    return {"id": eid, "kind": ev.kind, "source": ev.source, "path": ev.path, "sha256": ev.sha256, "content": s.evidence.content(eid)[:20000]}


@router.post("/{run_id}/plans/{plan_id}/decision")
def decision(run_id: str, plan_id: str, req: DecisionReq):
    rem: service.Remediator = _load(run_id)["rem"]
    try:
        a = rem.decide(plan_id, req.decision, req.reviewer, req.note)
    except service.DecisionError as e:
        raise HTTPException(409, str(e))
    return a.model_dump()


@router.post("/{run_id}/plans/{plan_id}/apply")
def apply_and_validate(run_id: str, plan_id: str, req: ApplyReq):
    rem: service.Remediator = _load(run_id)["rem"]
    if req.tier not in ("tier1", "tier2"):
        raise HTTPException(400, "tier must be tier1 or tier2")
    try:
        applier.gate(rem.store, plan_id)  # fail fast and visibly, before any thread starts
    except applier.ApplyRefused as e:
        raise HTTPException(409, str(e))
    key = (run_id, plan_id)
    if JOBS.get(key, {}).get("status") == "running":
        raise HTTPException(409, "validation is already running for this plan")
    JOBS[key] = {"status": "running", "tier": req.tier, "started": time.time()}

    def work():
        try:
            res = validate.validate(rem.store, plan_id, rem.ctx, tier=req.tier)
            JOBS[key] = {"status": "done", "tier": req.tier, "outcome": res.outcome}
        except applier.ApplyRefused as e:
            JOBS[key] = {"status": "refused", "error": str(e)}
        except BaseException as e:  # noqa: BLE001
            JOBS[key] = {"status": "error", "error": f"{type(e).__name__}: {e}"[:400]}
    threading.Thread(target=work, daemon=True, name=f"{run_id}-{plan_id}").start()
    return {"started": True, "tier": req.tier}


@router.get("/{run_id}/plans/{plan_id}/validation")
def get_validation(run_id: str, plan_id: str):
    v = _load(run_id)["rem"].store.validation(plan_id)
    if v is None:
        raise HTTPException(404, "no validation yet for this plan")
    return v.model_dump()


@router.get("/{run_id}/report")
def get_report(run_id: str, fmt: str = "json"):
    rem: service.Remediator = _load(run_id)["rem"]
    rep = reporter.write(rem.store, rem.ctx)
    if fmt == "md":
        return PlainTextResponse(reporter.to_markdown(rep), media_type="text/markdown")
    if fmt == "html":
        return HTMLResponse(reporter.to_html(rep))
    return rep
