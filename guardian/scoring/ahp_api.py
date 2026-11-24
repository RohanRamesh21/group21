"""HTTP API for AI-advised AHP. The decision endpoints are the ONLY writers of approvals; no agent tool maps to them."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from guardian.scoring import advisor
from guardian.scoring.score import AHP, AHP_MATRIX, CRITERIA

router = APIRouter(prefix="/api/ahp")


class Tags(BaseModel):
    internet_facing: str | None = None
    data_sensitivity: str | None = None
    deployment: str | None = None
    notes: str | None = None


class ProposeReq(BaseModel):
    project: str | None = None
    mode: str = "agent"  # agent | replay
    tags: Tags = Tags()
    preset: str | None = None


class DecisionReq(BaseModel):
    project: str | None = None
    decision: str
    reviewer: str
    note: str | None = None


class ResetReq(BaseModel):
    project: str | None = None
    reviewer: str
    note: str | None = None


def _out(project: str | None):
    from guardian import projects
    try:
        return projects.out_dir(project)
    except KeyError:
        raise HTTPException(404, f"unknown project {project}")


@router.get("")
def overview(project: str | None = None):
    st = advisor.AhpStore(_out(project))
    act = st.active()
    return {"baseline": {"criteria": CRITERIA, "matrix": AHP_MATRIX, "weights": AHP["weights"], "consistency_ratio": AHP["consistency_ratio"]},
            "limits": {"max_drift": advisor.MAX_DRIFT, "consistency_limit": 0.10, "saaty": "1..9 and 1/2..1/9"},
            "active": act, "proposals": [m for m in st.matrices().values() if m["status"] == "proposed"],
            "history": [m for m in st.matrices().values() if m["status"] != "proposed"], "confirmed": st.confirmed(),
            "options": {"internet_facing": advisor.YES_NO, "data_sensitivity": advisor.SENSITIVITY, "deployment": advisor.DEPLOYMENTS,
                        "replay_presets": list(advisor.REPLAY_PRESETS)}}


@router.post("/propose")
def propose(req: ProposeReq):
    from guardian.remediation.context import RemediationContext
    try:
        ctx = RemediationContext.load(req.project)
    except (FileNotFoundError, KeyError) as e:
        raise HTTPException(404, str(e))
    st = advisor.AhpStore(_out(req.project))
    try:
        return advisor.propose(st, ctx.scores, ctx.src, req.tags.model_dump(), req.mode, preset=req.preset)
    except advisor.AdvisorError as e:
        raise HTTPException(409, str(e))
    except Exception as e:  # provider down / no key: say so, keep the baseline
        raise HTTPException(502, f"the advisor could not run ({type(e).__name__}: {e}); the baseline matrix stays in force"[:400])


@router.post("/{mid}/decision")
def decide(mid: str, req: DecisionReq):
    try:
        return advisor.AhpStore(_out(req.project)).decide(mid, req.decision, req.reviewer, req.note)
    except advisor.MatrixError as e:
        raise HTTPException(409, str(e))


@router.post("/reset")
def reset(req: ResetReq):
    try:
        advisor.AhpStore(_out(req.project)).reset(req.reviewer, req.note)
    except advisor.MatrixError as e:
        raise HTTPException(409, str(e))
    return {"ok": True}
