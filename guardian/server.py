"""Dashboard backend: starts agent runs in the background and streams the shared board over SSE.

Run:  .venv/bin/uvicorn guardian.server:app --port 8765
Serves the built dashboard (guardian/dashboard/dist) at / when it exists.
"""
from __future__ import annotations

import asyncio
import json
import threading
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from guardian import config
from guardian.agents.tools import UNTRUSTED_KINDS

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "guardian-out" / "dashboard"
DIST = ROOT / "guardian" / "dashboard" / "dist"
HUMAN_TIMEOUT = 120  # seconds; after that the policy answer is used and the audit says so

app = FastAPI(title="Supply Chain Guardian")

from guardian.scoring.ahp_api import router as ahp_router  # noqa: E402  AI-advised AHP: propose -> referee -> human approves

app.include_router(ahp_router)


class Run:
    def __init__(self, run_id: str, mode: str, world: str):
        self.id, self.mode, self.world = run_id, mode, world
        self.board = None
        self.store = None
        self.status = "starting"
        self.error: str | None = None
        self.started = time.time()
        self.pending_human: dict | None = None
        self._answer: str | None = None
        self._answered = threading.Event()

    def human(self, question: str, options: list[str], fallback) -> str:
        self.pending_human = {"question": question, "options": options, "timeout": HUMAN_TIMEOUT}
        self._answered.clear()
        got = self._answered.wait(HUMAN_TIMEOUT)
        self.pending_human = None
        if got and self._answer:
            return f"(human reviewer) {self._answer}"
        return f"(no reply in {HUMAN_TIMEOUT}s, policy answer used) {fallback(question, options)}"

    def answer(self, text: str) -> None:
        self._answer = text
        self._answered.set()


RUNS: dict[str, Run] = {}


def _meta() -> dict:
    """Headline numbers from the real scenario (git + lockfile only, no network)."""
    try:
        from guardian.adapters.npm import parse_lockfile
        from guardian.snapshot.snapshot import open_view
        repo = ROOT / "sandbox" / "uptime-kuma"
        head, _ = parse_lockfile(open_view(repo, "scenario/s3-s9").text("package-lock.json"))
        base, _ = parse_lockfile(open_view(repo, "scenario/base").text("package-lock.json"))
        hv = {(p.name, p.version) for p in head.values()}
        bv = {(p.name, p.version) for p in base.values()}
        return {"components": len({p.name for p in head.values()}), "lockfile_entries": len(head),
                "direct": sum(1 for p in head.values() if p.direct), "runtime": sum(1 for p in head.values() if p.runtime),
                "install_scripts": sum(1 for p in head.values() if p.has_install_script),
                "changed_packages": len(hv - bv), "repo": "louislam/uptime-kuma 2.5.12",
                "base": "scenario/base", "head": "scenario/s3-s9"}
    except Exception as e:  # sandbox missing: dashboard still works with the canned world
        return {"error": f"scenario not available: {e}"}


class StartReq(BaseModel):
    mode: str = "replay"  # replay | live
    world: str = "canned"  # canned | real
    pace: float = 0.55


@app.get("/api/health")
def health():
    return {"ok": True, "provider": config.provider()}


@app.get("/api/meta")
def meta():
    import os
    prov = config.provider()
    return {**_meta(), "provider": prov, "model": os.environ.get("GUARDIAN_MODEL", "anthropic/claude-sonnet-5.5") if prov == "openrouter" else prov,
            "effort": os.environ.get("GUARDIAN_EFFORT")}


@app.post("/api/runs")
def start(req: StartReq):
    from guardian.agents.run import run as run_agents

    if req.mode == "replay" and req.world != "canned":
        raise HTTPException(400, "replay runs on the canned world; use live for real facts")
    run_id = f"RUN-{uuid.uuid4().hex[:6].upper()}"
    r = Run(run_id, req.mode, req.world)
    RUNS[run_id] = r
    backend = "replay" if req.mode == "replay" else config.provider()
    if req.mode == "live" and backend == "replay":
        raise HTTPException(400, "no LLM key configured in guardian/.env")

    def attach(board, store):
        r.board, r.store, r.status = board, store, "running"

    def work():
        try:
            run_agents(OUT / run_id, backend=backend, run_id=run_id, world_kind=req.world,
                       pace=req.pace if req.mode == "replay" else 0.0, human_override=r.human, on_board=attach)
            r.status = "done"
        except BaseException as e:  # noqa: BLE001  surface any failure to the UI
            r.status, r.error = "error", f"{type(e).__name__}: {e}"[:400]

    threading.Thread(target=work, daemon=True, name=run_id).start()
    return {"run_id": run_id, "backend": backend}


def _state(r: Run) -> dict:
    b = r.board
    snap = b.snapshot() if b else {}
    if b:
        snap["coverage"] = {"required": sorted(b.coverage_required), "done": sorted(b.coverage_done & b.coverage_required)}
        snap["cases"] = {k: c.model_dump(include={"title", "finding_ids", "verdict", "risk", "resolved", "confidence", "rationale", "evidence_ids"})
                         for k, c in b.cases.items()}
    return {"run_id": r.id, "status": r.status, "error": r.error, "mode": r.mode, "world": r.world,
            "pending_human": r.pending_human, "elapsed": round(time.time() - r.started, 1), **snap}


@app.get("/api/runs/{run_id}/events")
async def events(run_id: str):
    r = RUNS.get(run_id) or _404()

    async def gen():
        sent, last_state = 0, None
        while True:
            feed = r.board.feed if r.board else []
            new = feed[sent:]
            for ev in new:
                yield f"event: feed\ndata: {json.dumps(ev, default=str)}\n\n"
            sent += len(new)
            state = json.dumps(_state(r), default=str)
            if state != last_state:
                yield f"event: state\ndata: {state}\n\n"
                last_state = state
            if r.status in ("done", "error") and sent == len(r.board.feed if r.board else []):
                yield "event: end\ndata: {}\n\n"
                return
            await asyncio.sleep(0.15)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})


class HumanReq(BaseModel):
    answer: str


@app.post("/api/runs/{run_id}/human")
def human(run_id: str, req: HumanReq):
    r = RUNS.get(run_id) or _404()
    if not r.pending_human:
        raise HTTPException(409, "no question is waiting")
    r.answer(req.answer[:500])
    return {"ok": True}


@app.get("/api/runs/{run_id}/evidence/{eid}")
def evidence(run_id: str, eid: str):
    r = RUNS.get(run_id) or _404()
    if not r.store or not r.store.exists(eid):
        raise HTTPException(404, "unknown evidence id")
    ev = r.store.get(eid)
    return {"id": eid, "kind": ev.kind, "source": ev.source, "path": ev.path,
            "untrusted": ev.kind in UNTRUSTED_KINDS, "content": r.store.content(eid)[:20000]}


_DEP_CACHE: dict = {}


def _gh_run(project: str | None) -> dict | None:
    """A PR run from the GitHub trigger ("gh-<run id>"), or None."""
    import re as _re
    if not project or not project.startswith("gh-") or not _re.fullmatch(r"gh-\d{8}-\d{6}-[0-9a-f]{6}", project):
        return None
    return _trigger_service().queue.get(project[3:])


def _profile_of(project: str | None, default: str = "uptime-kuma") -> str:
    """Validation profile bound into approvals and used by validation: per repository for PR runs."""
    from guardian.validation.runner import profile_for
    run = _gh_run(project)
    return profile_for(run["repo"]) if run else default


def _check_dir(project: str | None) -> Path:
    from guardian import projects
    if project and project.startswith("gh-"):
        if not _gh_run(project):
            raise HTTPException(404, f"unknown PR run {project}")
        return _trigger_service().root / "runs" / project[3:]
    try:
        return projects.out_dir(project)
    except KeyError:
        raise HTTPException(404, f"unknown project {project}")


_WARMED: set[str] = set()


def _auto_explain() -> bool:
    """Opening the scores page spends no tokens unless GUARDIAN_AUTO_EXPLAIN=1 (explanations are made on request)."""
    import os
    return os.environ.get("GUARDIAN_AUTO_EXPLAIN") == "1"


@app.get("/api/scores")
def scores(project: str | None = None):
    """Explainable risk scores (floors + SSVC + AHP-weighted priority) for the latest check of the main
    scenario, or of an uploaded project. Deterministic; no LLM involved in the numbers."""
    d = _check_dir(project)
    latest = d / "latest.json"
    if not latest.exists():
        raise HTTPException(404, "no check report yet")
    ptr = json.loads(latest.read_text())
    if not ptr.get("scores"):
        from guardian.scoring.score import score_report
        rp = Path(ptr["path"]) if Path(ptr["path"]).is_absolute() else ROOT / ptr["path"]
        data = score_report(json.loads(rp.read_text()))
        sp = rp.with_name(rp.name.replace("report-", "scores-"))
        sp.write_text(json.dumps(data, indent=1))
        ptr["scores"] = str(sp)
        latest.write_text(json.dumps(ptr))
    sp = Path(ptr["scores"]) if Path(ptr["scores"]).is_absolute() else ROOT / ptr["scores"]
    data = json.loads(sp.read_text())
    from guardian.scoring.advisor import with_active_matrix  # show the scores under the human-approved AHP matrix, if one exists
    data = with_active_matrix(d, data)
    if _auto_explain() and str(sp) not in _WARMED:  # opt-in: pre-write explanations (one batched, budgeted call)
        _WARMED.add(str(sp))
        from guardian.scoring.explain import warm
        threading.Thread(target=warm, args=(data["findings"],), kwargs={"limit": 10}, daemon=True).start()
    from guardian.scoring.explain import is_cached
    for f in data["findings"]:
        f["explained"] = is_cached(f)
    return data


class ExplainReq(BaseModel):
    id: str
    project: str | None = None
    force: bool = False


@app.post("/api/explain")
def explain_finding(req: ExplainReq):
    """Plain-English explanation of one scored finding (Gemini), checked against the score card."""
    data = scores(req.project)
    f = next((x for x in data["findings"] if x["id"] == req.id), None)
    if not f:
        raise HTTPException(404, "unknown finding")
    from guardian.scoring.explain import explain
    return explain(f, force=req.force)


class GitReq(BaseModel):
    url: str
    base: str | None = None
    head: str | None = None


@app.get("/api/projects")
def list_projects():
    from guardian import projects
    return projects.list_jobs()


@app.get("/api/projects/{pid}")
def get_project(pid: str):
    from guardian import projects
    j = projects.get(pid)
    if not j:
        raise HTTPException(404, "unknown project")
    return j


class LocalReq(BaseModel):
    name: str
    base: str
    head: str


@app.get("/api/sandbox")
def sandbox_repos():
    from guardian import projects
    return projects.list_sandbox()


@app.post("/api/projects/local")
def project_local(req: LocalReq):
    from guardian import projects
    try:
        return {"id": projects.start_local(req.name, req.base, req.head)}
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/projects/git")
def project_git(req: GitReq):
    from guardian import projects
    try:
        return {"id": projects.start_git(req.url, (req.base or "").strip() or None, (req.head or "").strip() or None)}
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/projects/zip")
async def project_zip(file: UploadFile = File(...)):
    from guardian import projects
    if not (file.filename or "").lower().endswith(".zip"):
        raise HTTPException(400, "please upload a .zip file")
    projects.BASE.mkdir(parents=True, exist_ok=True)
    tmp = projects.BASE / f"upload-{uuid.uuid4().hex}.zip"
    size = 0
    with open(tmp, "wb") as out:
        while chunk := await file.read(1 << 20):
            size += len(chunk)
            if size > projects.MAX_ZIP_BYTES:
                out.close()
                tmp.unlink(missing_ok=True)
                raise HTTPException(413, "zip is larger than 200 MB")
            out.write(chunk)
    return {"id": projects.start_zip(tmp, file.filename)}


def _latest(project: str | None) -> tuple[dict, dict | None]:
    latest = _check_dir(project) / "latest.json"
    if not latest.exists():
        raise HTTPException(404, "no report yet for this project")
    ptr = json.loads(latest.read_text())
    path = Path(ptr["path"]) if Path(ptr["path"]).is_absolute() else ROOT / ptr["path"]
    rep = json.loads(path.read_text())
    sp = ptr.get("scores")
    sc = json.loads((Path(sp) if Path(sp).is_absolute() else ROOT / sp).read_text()) if sp else None
    return rep, sc


class FixReq(BaseModel):
    project: str | None = None
    include: list[str] = []


@app.post("/api/fix-plan")
def fix_plan_create(req: FixReq):
    """Propose fixes for the latest run: deterministic candidates + one combined patch (nothing is applied)."""
    import guardian.remediation.plan as plan_mod
    out = _check_dir(req.project)
    latest = out / "latest.json"
    if not latest.exists():
        raise HTTPException(404, "no run yet")
    h = json.loads(Path(json.loads(latest.read_text())["path"]).read_text())["headline"]
    if not h.get("repo_path"):
        raise HTTPException(409, "this run predates fix support: rescan first")
    try:
        return plan_mod.propose(Path(h["repo_path"]), h.get("base_sha"), h["head_sha"], out, include=req.include)
    except plan_mod.StaleRun as e:
        raise HTTPException(409, str(e))


@app.post("/api/fix-plan/review")
def fix_plan_review(req: FixReq):
    """Fixer + Verifier review by the model (one call). Checked by code; never changes the plan."""
    from guardian.remediation.review import review
    out = _check_dir(req.project)
    f = out / "fix-plan.json"
    if not f.exists():
        raise HTTPException(404, "no fix plan yet")
    plan = json.loads(f.read_text())
    plan["review"] = review(plan)
    if plan["review"]["status"] == "done":
        plan["pending"] = [p for p in plan.get("pending", []) if "explanations" not in p]
    f.write_text(json.dumps(plan, indent=1))
    return plan["review"]


@app.get("/api/fix-plan")
def fix_plan_get(project: str | None = None):
    f = _check_dir(project) / "fix-plan.json"
    if not f.exists():
        raise HTTPException(404, "no fix plan yet")
    plan = json.loads(f.read_text())
    p = Path(plan["patch"]["patch_path"])
    plan["patch_text"] = p.read_text(errors="replace")[:200_000] if p.exists() else ""
    return plan


class ApprovalReq(BaseModel):
    project: str | None = None
    decision: str
    approver: str
    reason: str
    hours: float = 24
    reviewed: bool = False  # the approver confirms they looked at the exact patch (required to approve)


@app.post("/api/approval")
def approval_create(req: ApprovalReq):
    """A person approves or rejects the current fix plan. Bound to base, head, patch hash, policy hash, profile hash."""
    from guardian import approval as ap
    from guardian.validation.runner import load_profile
    from guardian.validation.validate import policy_sha256
    out = _check_dir(req.project)
    f = out / "fix-plan.json"
    if not f.exists():
        raise HTTPException(404, "no fix plan to approve")
    if req.decision == "approve" and not req.reviewed:
        raise HTTPException(400, "review the patch first, then confirm you reviewed it")
    if not 1 / 60 <= req.hours <= 24 * 7:
        raise HTTPException(400, "an approval lasts between 1 minute and 7 days")
    try:
        return ap.decide(out, json.loads(f.read_text()), req.decision, approver=req.approver, reason=req.reason, reviewed=req.reviewed,
                         ttl_seconds=int(req.hours * 3600), policy_sha256=policy_sha256(),
                         profile_sha256=load_profile(_profile_of(req.project))[1])
    except ValueError as e:
        raise HTTPException(400, str(e))
    finally:
        _gh_event(req.project, "decision_recorded", {"decision": req.decision, "approver": req.approver[:80]})


@app.get("/api/approval")
def approval_view(project: str | None = None):
    """What an approval binds (shown BEFORE anyone signs), the latest decision, and whether it still authorises the
    current plan: any change to commits, patch, policy or profile, or expiry, makes it invalid."""
    from guardian import approval as ap
    from guardian.validation.runner import load_profile
    from guardian.validation.validate import policy_sha256
    out = _check_dir(project)
    f = out / "fix-plan.json"
    if not f.exists():
        raise HTTPException(404, "no fix plan yet")
    plan = json.loads(f.read_text())
    profile = _profile_of(project)
    contract = {"base_sha": plan.get("base_sha"), "head_sha": plan["head_sha"], "patch_sha256": plan["patch"]["patch_sha256"],
                "policy_sha256": policy_sha256(), "profile": profile, "profile_sha256": load_profile(profile)[1]}
    rec = ap.latest_approval(out)
    valid, reason = False, "no decision yet: a named person must approve or reject"
    if rec:
        try:
            ap.check(rec, plan, policy_sha256=contract["policy_sha256"], profile_sha256=contract["profile_sha256"])
            valid, reason = True, None
        except ap.ApprovalInvalid as e:
            reason = str(e)
    audit_ok, entries = ap.verify_audit(out)
    return {"contract": contract, "approval": rec, "valid": valid, "reason": reason, "audit_ok": audit_ok, "audit_entries": entries}


@app.get("/api/risk-acceptance")
def risk_list(project: str | None = None):
    from guardian import approval as ap
    return ap.accepted_risks(_check_dir(project))


class RiskReq(BaseModel):
    project: str | None = None
    finding_id: str
    owner: str
    scope: str
    reason: str
    days: float = 30


@app.post("/api/risk-acceptance")
def risk_accept(req: RiskReq):
    from guardian import approval as ap
    try:
        return ap.accept_risk(_check_dir(req.project), req.finding_id, owner=req.owner, scope=req.scope, reason=req.reason,
                              ttl_seconds=int(req.days * 86400))
    except ValueError as e:
        raise HTTPException(400, str(e))


class ValidateReq(BaseModel):
    project: str | None = None
    profile: str = "uptime-kuma"


_VALIDATING: dict[str, str] = {}


@app.post("/api/validate")
def validate_start(req: ValidateReq):
    """Run validation in the background (it takes minutes). Refuses to execute anything without a matching approval."""
    import threading

    from guardian.validation.validate import validate
    out = _check_dir(req.project)
    key = str(out)
    if _VALIDATING.get(key) == "running":
        raise HTTPException(409, "validation already running")
    _VALIDATING[key] = "running"

    profile = _profile_of(req.project, req.profile)
    _gh_event(req.project, "validation_started", {"profile": profile})

    def work():
        try:
            res = validate(out, profile, log=lambda m: _VALIDATING.__setitem__(key + ":msg", m))
            _VALIDATING[key] = "done"
            _gh_validation_status(req.project, res if isinstance(res, dict) else json.loads((out / "validation.json").read_text()))
        except Exception as e:  # recorded, never hidden
            _VALIDATING[key] = f"error: {type(e).__name__}: {e}"[:300]
            _gh_event(req.project, "validation_finished", {"status": "error", "error": _VALIDATING[key]})
    threading.Thread(target=work, daemon=True).start()
    return {"status": "started"}


@app.get("/api/validation")
def validation_get(project: str | None = None):
    out = _check_dir(project)
    f = out / "validation.json"
    state = _VALIDATING.get(str(out))
    if not f.exists():
        if state:
            return {"status": state, "message": _VALIDATING.get(str(out) + ":msg")}
        raise HTTPException(404, "no validation yet")
    return {**json.loads(f.read_text()), "status": state or "done"}


_INVESTIGATING: dict[str, dict] = {}


class InvestigateReq(BaseModel):
    project: str | None = None
    explain: bool = False  # case summaries already explain; per-finding explanations are made on request
    fix_review: bool = True  # then the Fixer: rules propose the patch (if none yet), the model explains and questions it


@app.post("/api/investigate")
def investigate_start(req: InvestigateReq):
    """Budgeted AI investigation in the background: 1 call per case (parallel) + 1 Verifier call (+1 batched
    explanation call). Every call is budget-checked, recorded in the token ledger and cached."""
    from guardian.ai import workflow
    out = _check_dir(req.project)
    key = str(out)
    if (_INVESTIGATING.get(key) or {}).get("status") == "running":
        raise HTTPException(409, "investigation already running")
    if not (out / "latest.json").exists():
        raise HTTPException(404, "no run yet")
    _INVESTIGATING[key] = {"status": "running", "events": []}

    def work():
        st = _INVESTIGATING[key]
        try:
            workflow.investigate(out, on_event=lambda e: st["events"].append(e))
            if req.fix_review:
                _fixer(out, st["events"].append)
            if req.explain:
                from guardian.scoring.explain import warm
                ptr = json.loads((out / "latest.json").read_text())
                if ptr.get("scores"):
                    st["events"].append({"stage": "explain", "state": "running"})
                    warm([f for f in json.loads(Path(ptr["scores"]).read_text())["findings"] if f["label"] == "introduced"])
                    st["events"].append({"stage": "explain", "state": "done"})
            st["status"] = "finished"
        except Exception as e:  # recorded, never hidden
            st["status"] = f"error: {type(e).__name__}: {e}"[:300]
    threading.Thread(target=work, daemon=True).start()
    return {"status": "started"}


def _fixer(out: Path, emit) -> None:
    """Fixer step of the one-click run. Versions and the patch come from rules; the model only explains and questions."""
    import guardian.remediation.plan as plan_mod
    from guardian.remediation import review as rv
    emit({"agent": "fixer", "state": "running"})
    try:
        f = out / "fix-plan.json"
        if not f.exists():
            h = json.loads(Path(json.loads((out / "latest.json").read_text())["path"]).read_text())["headline"]
            plan_mod.propose(Path(h["repo_path"]), h.get("base_sha"), h["head_sha"], out, include=[])
        plan = json.loads(f.read_text())
        plan["review"] = rv.review(plan)
        if plan["review"]["status"] == "done":
            plan["pending"] = [p for p in plan.get("pending", []) if "explanations" not in p]
        f.write_text(json.dumps(plan, indent=1))
        emit({"agent": "fixer", "state": plan["review"]["status"], "candidates": len(plan.get("candidates", [])),
              "explanations": len(plan["review"].get("explanations", [])), "challenges": len(plan["review"].get("challenges", []))})
        emit({"agent": "human", "state": "waiting", "note": "approve or reject the patch"})
    except Exception as e:  # recorded, never hidden
        emit({"agent": "fixer", "state": "failed", "error": f"{type(e).__name__}: {e}"[:200]})


@app.get("/api/investigation/events")
def investigation_events(project: str | None = None):
    st = _INVESTIGATING.get(str(_check_dir(project)))
    return {"status": st["status"] if st else "idle", "events": st["events"] if st else []}


@app.get("/api/investigation")
def investigation_get(project: str | None = None):
    out = _check_dir(project)
    st = _INVESTIGATING.get(str(out))
    f = out / "agents" / "verdict.json"
    if st and st["status"] == "running":
        return {"status": "running", "events": st["events"]}
    if not f.exists():
        if st:
            return {"status": st["status"], "events": st["events"]}
        raise HTTPException(404, "no investigation yet")
    return json.loads(f.read_text())


@app.get("/api/ai/usage")
def ai_usage(run_id: str | None = None):
    """Token ledger summary (calls, tokens, budget). Never contains the key or prompts."""
    from guardian import llm_budget
    return llm_budget.summary(run_id)


@app.get("/api/run")
def run_view(project: str | None = None):
    """Everything the Run page shows, from the same builder as the Guardian report (one source of truth)."""
    from guardian.report.build import build
    from guardian import projects
    out = _check_dir(project)
    if not (out / "latest.json").exists():
        raise HTTPException(404, "no run yet")
    if projects.is_outdated(out):
        raise HTTPException(409, "outdated: this scan was made by an older Guardian version. Rescan it to use the current engine.")
    return build(out)


@app.post("/api/projects/{pid}/rescan")
def project_rescan(pid: str):
    """Re-run a saved scan with the current engine on the same commits (old results are kept)."""
    from guardian import projects
    if not projects.get(pid):
        raise HTTPException(404, "unknown project")
    try:
        projects.rescan(pid)
    except (RuntimeError, ValueError) as e:
        raise HTTPException(409, str(e))
    return {"status": "started", "project": pid}


@app.get("/api/report")
def report_get(project: str | None = None, fmt: str = "json"):
    from guardian.report.build import write
    paths = write(_check_dir(project))
    if fmt == "html":
        return FileResponse(paths["html"], media_type="text/html")
    return FileResponse(paths["json"], media_type="application/json", filename="guardian-report.json")


class GitHubEvent(BaseModel):
    repo: str
    pr: int
    action: str
    head_sha: str
    base_sha: str | None = None
    draft: bool = False
    title: str = ""
    wait: bool = True

    def model_post_init(self, _ctx) -> None:
        import re as _re
        if not _re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.repo) or not _re.fullmatch(r"[0-9a-f]{40}", self.head_sha) \
                or (self.base_sha and not _re.fullmatch(r"[0-9a-f]{40}", self.base_sha)) or len(self.title) > 200 \
                or (self.pr < 1 and not (self.action == "nightly" and self.pr == 0)):
            raise ValueError("malformed PR event")


_TRIGGER: dict = {}


def _trigger_service():
    """One service per server process (a single dispatcher). GitHub writes only if GUARDIAN_GITHUB_TOKEN is set."""
    if "svc" not in _TRIGGER:
        import os

        from guardian import universal
        from guardian.approval import file_sha256
        from guardian.trigger.github import GitHub
        from guardian.trigger.service import Service, git_fetch_pr
        from guardian.validation.runner import load_profile
        config.load_env()
        root = ROOT / "guardian-out" / "github"
        token = os.environ.get("GUARDIAN_GITHUB_TOKEN")

        def parts():
            import subprocess as sp
            db = sp.run(["grype", "db", "status"], capture_output=True, text=True).stdout.strip().splitlines()
            return {"policy_sha256": file_sha256(ROOT / "guardian.yaml"), "profile_sha256": load_profile("uptime-kuma")[1],
                    "intel": next((x for x in db if "Built" in x), "unknown").strip()}
        from guardian.trigger.github import GitHubRouter
        router = GitHubRouter(dict(os.environ))  # per-repository tokens, falling back to GUARDIAN_GITHUB_TOKEN
        svc = Service(root, fetch=git_fetch_pr(root), engine=universal.check_any,
                      github=router if router.configured else None, identity_parts=parts)
        if os.environ.get("GUARDIAN_AUTO_AGENTS", "1") != "0":
            svc.after_scan = lambda rid, out, h, e: _auto_agents(svc, rid, out, h, e)
        _TRIGGER["svc"] = svc
    return _TRIGGER["svc"]


def _auto_agents(svc, rid: str, out: Path, h: dict, e: dict, background: bool = True) -> None:
    """BLOCK/REVIEW PR runs: the 4 agents start by themselves (budgeted, cached). Their progress goes to the trigger
    event stream, so Buddy and the dashboard follow it live. ALLOW runs spend no tokens."""
    from guardian.ai import workflow
    st = _INVESTIGATING.setdefault(str(out), {"status": "running", "events": []})
    st.update(status="running", events=[])

    def emit(ev: dict) -> None:
        st["events"].append(ev)
        svc.events.append(rid, "agent", {**ev, "project": f"gh-{rid}", "pr": e.get("pr"), "repo": e.get("repo")})

    def work():
        svc.events.append(rid, "agents_started", {"project": f"gh-{rid}", "pr": e.get("pr"), "repo": e.get("repo"), "verdict": h.get("verdict")})
        try:
            res = workflow.investigate(out, on_event=emit)
            _fixer(out, emit)
            st["status"] = "finished"
            svc.events.append(rid, "agents_finished", {"project": f"gh-{rid}", "pr": e.get("pr"), "status": res.get("status"),
                                                       "tokens": (res.get("usage") or {}).get("run", {}).get("tokens")})
            svc.events.append(rid, "approval_needed", {"project": f"gh-{rid}", "pr": e.get("pr"), "repo": e.get("repo")})
        except Exception as ex:  # recorded, never hidden; the scan verdict stands on its own
            st["status"] = f"error: {type(ex).__name__}: {ex}"[:300]
            svc.events.append(rid, "agents_finished", {"project": f"gh-{rid}", "pr": e.get("pr"), "status": "error", "error": st["status"]})
    if background:
        threading.Thread(target=work, daemon=True, name=f"agents-{rid}").start()
    else:
        work()


def _gh_event(project: str | None, kind: str, data: dict) -> None:
    run = _gh_run(project)
    if run:
        _trigger_service().events.append(run["id"], kind, {**data, "project": project, "pr": run["pr"], "repo": run["repo"]})


def _gh_validation_status(project: str | None, res: dict) -> None:
    """Validation result of a PR run → the separate guardian/validation status on the PR's head commit + an event."""
    from guardian.trigger.github import validation_status
    run = _gh_run(project)
    if not run:
        return
    svc = _trigger_service()
    st = validation_status(res)
    posted = svc._post(lambda: svc.github.set_status(run["repo"], run["head_sha"], st, svc.run_url(run["id"])))
    _gh_event(project, "validation_finished", {"state": st["state"], "description": st["description"], "github": posted})


@app.get("/api/pr-runs")
def pr_runs():
    """PR runs from the GitHub trigger, newest first, for the run selector (titles are untrusted text, shown escaped)."""
    svc = _trigger_service()
    rows = [{"project": f"gh-{r['id']}", "repo": r["repo"], "pr": r["pr"], "title": r.get("title", ""), "status": r["status"],
             "verdict": (r.get("result") or {}).get("verdict"), "head_sha": r["head_sha"], "created": r["created"]}
            for r in svc.queue.runs.values()]
    return sorted(rows, key=lambda r: r["created"], reverse=True)


@app.post("/api/github/event")
def github_event(ev: GitHubEvent):
    """Called by guardian-submit (GitHub Actions on our runner) or the polling backup: same queue, same engine."""
    svc = _trigger_service()
    payload = ev.model_dump()
    if not ev.wait:
        threading.Thread(target=svc.handle, args=(payload,), daemon=True).start()
        return {"status": "accepted"}
    try:
        return svc.handle(payload)
    except Exception as e:
        raise HTTPException(502, f"{type(e).__name__}: {e}"[:300])


@app.get("/api/trigger/current")
def trigger_current():
    """Snapshot for dashboard/Buddy on (re)connect: current run per PR + the last event number."""
    svc = _trigger_service()
    runs = [r for r in svc.queue.runs.values() if r["status"] in ("queued", "running", "done")]
    latest: dict = {}
    for r in sorted(runs, key=lambda r: r["created"]):
        latest[(r["repo"], r["pr"])] = r
    evs = svc.events.since(0)
    return {"runs": list(latest.values()), "last_seq": evs[-1]["seq"] if evs else 0}


@app.get("/api/trigger/events")
def trigger_events(since: int = 0):
    return _trigger_service().events.since(since)


@app.get("/api/trigger/stream")
async def trigger_stream(since: int = 0, last_event_id: str | None = None):
    """Server-sent events with ids; a client resumes with Last-Event-ID (or ?since=)."""
    start = int(last_event_id) if last_event_id and last_event_id.isdigit() else since
    svc = _trigger_service()

    async def gen():
        seq = start
        while True:
            for e in svc.events.since(seq):
                seq = e["seq"]
                yield f"id: {e['seq']}\nevent: {e['kind']}\ndata: {json.dumps(e)}\n\n"
            yield ": keep-alive\n\n"
            await asyncio.sleep(1.5)
    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})


@app.get("/api/day1")
def day1(project: str | None = None):
    """The Day 1 checkpoint (5 steps of the brief) for a scanned project, from real scan data."""
    from guardian.day1 import build
    rep, sc = _latest(project)
    return build(rep, sc)


@app.get("/api/sbom")
def sbom(project: str | None = None, fmt: str = "cyclonedx"):
    files = {"guardian": "sbom.guardian.cdx.json", "cyclonedx": "sbom.syft.cdx.json", "spdx": "sbom.syft.spdx.json"}
    if fmt not in files:
        raise HTTPException(400, "fmt must be guardian, cyclonedx or spdx")
    rep, _ = _latest(project)
    head = Path(rep["runs"]["head"])
    f = (head if head.is_absolute() else ROOT / head) / files[fmt]
    if not f.exists():
        raise HTTPException(404, f"{files[fmt]} was not produced for this scan")
    return FileResponse(f, media_type="application/json", filename=f"{project or 'main'}-{files[fmt]}")


@app.get("/api/depgraph")
def depgraph(project: str | None = None):
    """Full dependency graph of the PR head from the latest `guardian check` report, with risk overlaid.
    Real scan data (lockfile + OSV + Grype + detectors); no LLM involved."""
    latest = _check_dir(project) / "latest.json"
    if not latest.exists():
        raise HTTPException(404, "no check report yet: run `guardian check sandbox/uptime-kuma --base scenario/base --head scenario/s3-s9`")
    path = Path(json.loads(latest.read_text())["path"])
    if not path.is_absolute():
        path = ROOT / path
    stamp = path.stat().st_mtime
    if _DEP_CACHE.get("stamp") == (str(path), stamp):
        return _DEP_CACHE["data"]
    rep = json.loads(path.read_text())
    head_dir = Path(rep["runs"]["head"])
    if not head_dir.is_absolute():
        head_dir = ROOT / head_dir
    edges = json.loads((head_dir / "edges.json").read_text())
    changes = rep.get("package_changes", {})
    added = {x.rsplit("@", 1)[0] for x in changes.get("added", [])}
    updated = {x.split(" ", 1)[0] for x in changes.get("updated", [])}
    vulns: dict[tuple, list] = {}
    for v in rep.get("vulnerabilities", []):
        if v.get("label") != "fixed":
            vulns.setdefault((v["name"], v["version"]), []).append(
                {"id": v["id"], "severity": v["severity"], "label": v.get("label"), "malicious": v.get("malicious", False),
                 "fixed": v.get("fixed", [])[:3], "summary": v.get("summary", "")[:140], "sources": v.get("sources", [])})
    sus: dict[str, list] = {}
    for x in rep.get("suspicious_changes", []):
        name = x["component"].replace("pkg:npm/", "").replace("%40", "@").rsplit("@", 1)[0] if x["component"].startswith("pkg:") or "@" in x["component"][1:] else x["component"]
        sus.setdefault(name, []).append({"type": x["type"], "severity": x["severity"], "summary": x["summary"], "hard": x.get("hard_signal", False)})
    order = ["info", "low", "medium", "high", "critical"]
    nodes = []
    for p in rep["inventory"]:
        vs = vulns.get((p["name"], p["version"]), [])
        ss = sus.get(p["name"], [])
        sev = max([v["severity"] for v in vs] + [s["severity"] for s in ss if s["severity"] != "info"], key=order.index, default=None)
        from urllib.parse import urlparse
        nodes.append({"id": p["key"], "name": p["name"], "version": p["version"], "direct": p["direct"], "runtime": p["runtime"],
                      "dev": p["dev"], "install": p["has_install_script"], "host": urlparse(p.get("resolved") or "").netloc,
                      "change": "added" if p["name"] in added else "updated" if p["name"] in updated else None,
                      "severity": sev, "vulns": vs, "signals": ss, "line": p.get("lockfile_line")})
    lab = {p["key"]: f"{p.get('alias') or p['name']}@{p['version']}" for p in rep["inventory"]}
    data = {"app": rep["headline"]["head"], "commit": rep["headline"]["head_commit"], "nodes": nodes,
            "edges": [{"s": e["parent"] or "root", "t": e["child"], "k": e["kind"]} for e in edges if e.get("child")],
            "headline": rep["headline"],
            # unique parent->child pairs labelled the way npm does (aliases keep their alias name): equals `npm ls --all`
            "unique_links": len({("root" if not e["parent"] else lab.get(e["parent"]), lab.get(e["child"])) for e in edges if e.get("child")}),
            "ci": [{k: c.get(k) for k in ("detector", "type", "severity", "component", "file", "line", "summary", "label", "url", "excerpt")}
                   for c in rep.get("ci_image", []) if c.get("label") != "fixed"],
            "ci_stats": {"actions": rep["headline"]["ci_image"]["actions"], "images": rep["headline"]["ci_image"]["images"]}}
    _DEP_CACHE.update(stamp=(str(path), stamp), data=data)
    return data


def _404():
    raise HTTPException(404, "unknown run")


if DIST.exists():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/{path:path}")
    def spa(path: str):
        root = DIST.resolve()
        f = (root / path).resolve()
        inside = f == root or root in f.parents
        return FileResponse(f if path and inside and f.is_file() else root / "index.html")
