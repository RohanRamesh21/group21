"""Dashboard backend: starts agent runs in the background and streams the shared board over SSE.

Run:  .venv/bin/uvicorn guardian.server:app --port 8765
Serves the built dashboard (guardian/dashboard/dist) at / when it exists.
"""
from __future__ import annotations

import asyncio
import json
import secrets
import threading
import time
import uuid
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from guardian import config, reviews
from guardian.agents.boundary import redact

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "guardian-out" / "dashboard"
REVIEW_DB = ROOT / "guardian-out" / "reviews.sqlite3"
DIST = ROOT / "guardian" / "dashboard" / "dist"
HUMAN_TIMEOUT = 120

app = FastAPI(title="Supply Chain Guardian")


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
        self._human_lock = threading.Lock()
        self._human_deadline = 0.0
        self.review_token = secrets.token_urlsafe(32)
        self.target: dict = {}

    def human(self, question: str, options: list[str], fallback) -> str:
        with self._human_lock:
            self._answer = None
            self._answered.clear()
            self._human_deadline = time.monotonic() + HUMAN_TIMEOUT
            self.pending_human = {"id": uuid.uuid4().hex, "question": question, "options": options, "timeout": HUMAN_TIMEOUT}
        self._answered.wait(HUMAN_TIMEOUT)
        with self._human_lock:
            self.pending_human = None
            if self._answer is not None:
                return f"(reviewer context) {self._answer}"
        return "No reviewer response. Registry intent is unknown."

    def answer(self, token: str, question_id: str, choice: int) -> None:
        """Accept one enumerated answer from the holder of the run's review token."""
        if not secrets.compare_digest(token.encode(), self.review_token.encode()):
            raise HTTPException(403, "invalid review token")
        with self._human_lock:
            pending = self.pending_human
            if (pending is None or pending["id"] != question_id or self._answered.is_set()
                    or time.monotonic() >= self._human_deadline):
                raise HTTPException(409, "question expired or already answered")
            if not 0 <= choice < len(pending["options"]):
                raise HTTPException(400, "unknown reviewer choice")
            self._answer = pending["options"][choice]
            self._answered.set()


RUNS: dict[str, Run] = {}


def _target(project: str | None, report: dict | None = None) -> dict:
    """What a live investigation looks at: the repository, base and head commits of a finished scan.
    The agents re-read the repository themselves (git + lockfile); the scan only tells them where to look."""
    rep = report if report is not None else _latest(project)[0]
    h = rep["headline"]
    repo = Path(rep.get("repo") or "")
    if not rep.get("repo") or not repo.is_dir():
        raise HTTPException(409, "this scan has no local repository copy to investigate: scan the project again")
    base, head = h.get("base_commit_full") or h.get("base_commit"), h.get("head_commit_full") or h.get("head_commit")
    return {"project": project, "app": h.get("app") or h.get("head"), "repo": str(repo), "base": base, "head": head,
            "base_ref": h.get("base"), "head_ref": h.get("head"), "compare": base != head, "verdict": h.get("verdict")}


class StartReq(BaseModel):
    mode: Literal["replay", "live"] = "replay"
    world: Literal["canned", "real"] = "canned"
    pace: float = Field(default=0.55, ge=0, le=2)
    project: str | None = Field(default=None, max_length=64)  # live only: the scanned project to investigate (None = CLI report)


@app.get("/api/health")
def health():
    return {"ok": True, "provider": config.provider()}


@app.get("/api/meta")
def meta():
    """Which agent backends this server can use. Says nothing about any particular project."""
    import os
    from guardian.agents.run import DEFAULT_REPLAY
    prov = config.provider()
    return {"provider": prov, "live_available": prov != "replay", "replay_available": DEFAULT_REPLAY.exists(),
            "model": os.environ.get("GUARDIAN_MODEL") or prov,
            "effort": os.environ.get("GUARDIAN_EFFORT")}


@app.post("/api/runs")
def start(req: StartReq):
    from guardian.agents.run import run as run_agents

    if req.mode == "replay" and req.world != "canned":
        raise HTTPException(400, "replay runs on the canned world; use live for real facts")
    backend = "replay" if req.mode == "replay" else config.provider()
    if req.mode == "live" and backend == "replay":
        raise HTTPException(400, "no LLM key configured in .env: live agents need one")
    # live agents always work on real facts from the chosen scan; the recorded replay is a fixed example
    world = "real" if req.mode == "live" else "canned"
    report = _latest(req.project)[0] if world == "real" else None
    target = _target(req.project, report) if world == "real" else {"project": None, "app": "recorded example", "recorded": True}
    run_id = f"RUN-{uuid.uuid4().hex[:16].upper()}"
    r = Run(run_id, req.mode, world)
    r.target = target
    RUNS[run_id] = r

    def attach(board, store):
        r.board, r.store, r.status = board, store, "running"

    def work():
        try:
            where = {"repo": Path(target["repo"]), "base": target["base"], "head": target["head"], "scan_report": report} if world == "real" else {}
            run_agents(OUT / run_id, backend=backend, run_id=run_id, world_kind=world,
                       pace=req.pace if req.mode == "replay" else 0.0, human_override=r.human, on_board=attach, **where)
            r.status = "done"
        except BaseException as e:  # noqa: BLE001  surface any failure to the UI
            # these carry our own messages (missing file, bad ref, unknown backend); others could echo untrusted data
            hint = f" ({redact(str(e))[:160]})" if isinstance(e, (FileNotFoundError, ValueError, SystemExit)) else ""
            r.status, r.error = "error", f"{type(e).__name__}: investigation could not start or save its result{hint}"

    threading.Thread(target=work, daemon=True, name=run_id).start()
    return {"run_id": run_id, "backend": backend, "review_token": r.review_token}


def _state(r: Run) -> dict:
    b = r.board
    snap = b.snapshot() if b else {}
    if b:
        snap["coverage"] = {"required": sorted(b.coverage_required), "done": sorted(b.coverage_done & b.coverage_required)}
        snap["cases"] = {k: c.model_dump(include={"title", "finding_ids", "verdict", "risk", "resolved", "confidence", "rationale", "evidence_ids"})
                         for k, c in b.cases.items()}
    return {"run_id": r.id, "status": r.status, "error": r.error, "mode": r.mode, "world": r.world,
            "target": {k: v for k, v in r.target.items() if k != "repo"}, "pending_human": r.pending_human, "elapsed": round(time.time() - r.started, 1), **snap}


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
    token: str = Field(max_length=128)
    question_id: str = Field(max_length=32)
    choice: int = Field(strict=True)


@app.post("/api/runs/{run_id}/human")
def human(run_id: str, req: HumanReq):
    r = RUNS.get(run_id) or _404()
    r.answer(req.token, req.question_id, req.choice)
    return {"ok": True}


@app.get("/api/runs/{run_id}/evidence/{eid}")
def evidence(run_id: str, eid: str):
    r = RUNS.get(run_id) or _404()
    if not r.store or not r.store.exists(eid):
        raise HTTPException(404, "unknown evidence id")
    ev = r.store.get(eid)
    try:
        content = redact(r.store.content(eid))[:20000]
    except (ValueError, OSError):
        raise HTTPException(409, "evidence failed its integrity check") from None
    return {"id": eid, "kind": ev.kind, "source": redact(ev.source), "path": redact(ev.path) if ev.path else None,
            "untrusted": True, "content": content}


_DEP_CACHE: dict = {}


def _check_dir(project: str | None) -> Path:
    from guardian import projects
    try:
        return projects.out_dir(project)
    except KeyError:
        raise HTTPException(404, f"unknown project {project}")


def _score_snapshot(project: str | None) -> tuple[dict, dict, Path]:
    d = _check_dir(project)
    latest = d / "latest.json"
    if not latest.exists():
        raise HTTPException(404, "no check report yet")
    ptr = json.loads(latest.read_text())
    rp = Path(ptr["path"]) if Path(ptr["path"]).is_absolute() else ROOT / ptr["path"]
    report = json.loads(rp.read_text())
    if not ptr.get("scores"):
        from guardian.scoring.score import score_report
        data = score_report(report)
        sp = rp.with_name(rp.name.replace("report-", "scores-"))
        sp.write_text(json.dumps(data, indent=1))
        ptr["scores"] = str(sp)
        latest.write_text(json.dumps(ptr))
    else:
        sp = Path(ptr["scores"]) if Path(ptr["scores"]).is_absolute() else ROOT / ptr["scores"]
        data = json.loads(sp.read_text())
    h = report["headline"]  # the final verdict also includes policy-as-code
    data["final_verdict"], data["final_reasons"] = h.get("verdict", data["verdict"]), h.get("verdict_reasons", data["reasons"])
    return data, report, d


def _review_targets(project: str | None, report: dict, directory: Path, data: dict):
    from guardian import projects

    scope = reviews.repository_scope(report, directory, projects.get(project) if project else None)
    return scope, reviews.targets(report, data["findings"], scope)


@app.get("/api/scores")
def scores(project: str | None = None):
    """Return deterministic scores and the current human disposition of each finding."""
    data, report, directory = _score_snapshot(project)
    scope, targets = _review_targets(project, report, directory, data)
    latest = reviews.ReviewStore(REVIEW_DB).latest(scope, {target.key for target in targets})
    if targets:
        data["findings"] = [{**target.finding, "review": reviews.disposition(target, latest.get(target.key))} for target in targets]
    return data


def _review_snapshot(project: str | None, key: str):
    data, report, directory = _score_snapshot(project)
    scope, targets = _review_targets(project, report, directory, data)
    target = next((target for target in targets if target.key == key), None)
    if target is None:
        raise HTTPException(404, "This finding is unavailable in the latest scan. Refresh Risk scores.")
    return data, report["headline"], scope, target


def _review_report(store: reviews.ReviewStore, scope: str, target: reviews.ReviewTarget, headline: dict, data: dict) -> dict:
    history = store.history(scope, target.key)
    return {"app": headline.get("app"), "base_commit": headline.get("base_commit_full"),
            "head_commit": headline["head_commit_full"], "verdict": data["final_verdict"], "finding": target.finding,
            "review": reviews.disposition(target, history[0] if history else None), "history": history}


@app.get("/api/reviews/{key}")
def finding_review(key: str, project: str | None = None, download: bool = False):
    """Read the review timeline and optionally download the finding review as JSON."""
    data, headline, scope, target = _review_snapshot(project, key)
    report = _review_report(reviews.ReviewStore(REVIEW_DB), scope, target, headline, data)
    if download:
        return JSONResponse(report, headers={"Content-Disposition": f'attachment; filename="guardian-review-{target.key[:12]}.json"'})
    return report


@app.post("/api/reviews/{key}", status_code=201)
def submit_finding_review(key: str, req: reviews.ReviewInput, project: str | None = None):
    """Append a disposition after checking the reviewed scan revision and timeline."""
    data, headline, scope, target = _review_snapshot(project, key)
    if req.revision != target.revision:
        raise HTTPException(409, "The scan changed. Refresh Risk scores before submitting another review.")
    store = reviews.ReviewStore(REVIEW_DB)
    try:
        store.append(scope, target, headline, req)
    except reviews.ReviewConflict:
        raise HTTPException(409, "The review history changed. Refresh Risk scores before submitting another review.") from None
    return _review_report(store, scope, target, headline, data)


class ExplainReq(BaseModel):
    id: str
    project: str | None = None
    force: bool = False


@app.post("/api/explain")
def explain_finding(req: ExplainReq):
    """Plain-English explanation of one scored finding (Gemini), checked against the score card."""
    data, _, _ = _score_snapshot(req.project)
    f = next((x for x in data["findings"] if x["id"] == req.id), None)
    if not f:
        raise HTTPException(404, "unknown finding")
    from guardian.scoring.explain import explain
    return explain(f, force=req.force)


class GitReq(BaseModel):
    url: str
    base: str | None = None
    head: str | None = None


class PathReq(BaseModel):
    path: str = Field(max_length=1024)
    base: str | None = Field(default=None, max_length=200)
    head: str | None = Field(default=None, max_length=200)


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


@app.post("/api/projects/git")
def project_git(req: GitReq):
    from guardian import projects
    try:
        return {"id": projects.start_git(req.url, (req.base or "").strip() or None, (req.head or "").strip() or None)}
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/projects/path")
def project_path(req: PathReq):
    """Scan a folder on this machine. A Git repository is cloned (never modified); any other folder is copied."""
    from guardian import projects
    try:
        return {"id": projects.start_path(req.path, (req.base or "").strip() or None, (req.head or "").strip() or None)}
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/sources")
def sources():
    """Hints for the source form: which folders a local-path scan may read."""
    from guardian import projects
    return {"path_roots": [str(r) for r in projects.path_roots()], "git_hosts": sorted(projects.GIT_HOSTS),
            "max_zip_mb": projects.MAX_ZIP_BYTES // (1024 * 1024)}


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
        raise HTTPException(404, "no check report yet: run `guardian check <repo> --base <ref> --head <ref>` or scan a project")
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
                 "fixed": v.get("fixed", [])[:3], "summary": v.get("summary", "")[:140], "sources": v.get("sources", []),
                 "reach": (v.get("reachability") or {}).get("status"), "reach_why": (v.get("reachability") or {}).get("why")})
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
    data = {"app": rep["headline"].get("app") or rep["headline"]["head"], "ref": rep["headline"]["head"],
            "commit": rep["headline"]["head_commit"], "nodes": nodes,
            "edges": [{"s": e["parent"] or "root", "t": e["child"], "k": e["kind"]} for e in edges if e.get("child")],
            "headline": rep["headline"],
            # unique parent->child pairs labelled the way npm does (aliases keep their alias name): equals `npm ls --all`
            "unique_links": len({("root" if not e["parent"] else lab.get(e["parent"]), lab.get(e["child"])) for e in edges if e.get("child")}),
            "ci": [{k: c.get(k) for k in ("detector", "type", "severity", "component", "file", "line", "summary", "label", "url", "excerpt")}
                   for c in rep.get("ci_image", []) if c.get("label") != "fixed"],
            "ci_stats": {"actions": rep["headline"]["ci_image"]["actions"], "images": rep["headline"]["ci_image"]["images"]}}
    _DEP_CACHE.update(stamp=(str(path), stamp), data=data)
    return data


# ------------------------------------------------------------------ policy, provenance, remediation, monitoring (stretch goals)
def _report_and_dir(project: str | None) -> tuple[dict, Path]:
    rep, _ = _latest(project)
    return rep, _check_dir(project)


@app.get("/api/context")
def context(project: str | None = None):
    """What the views are showing (app, refs, verdict) plus the headline numbers of the scan for the overview."""
    rep, d = _report_and_dir(project)
    h = rep["headline"]
    inv = h.get("inventory") or {}
    changes = h.get("changes") or {}
    sus = [s for s in rep.get("suspicious_changes", []) if s.get("type") != "tool_error"]
    order = ["critical", "high", "medium", "low", "info"]
    signals = sorted((s for s in sus if s.get("label") == "introduced" and s.get("severity") != "info"),
                     key=lambda s: (not s.get("hard_signal"), order.index(s.get("severity", "info"))))
    vul = h.get("vulnerabilities") or {}
    ci = h.get("ci_image") or {}
    sb = Path(rep.get("runs", {}).get("head") or "")
    sb = sb if sb.is_absolute() else ROOT / sb
    return {"project": project, "app": h.get("app") or h.get("head"), "base": h.get("base"), "head": h.get("head"),
            "base_commit": h.get("base_commit"), "head_commit": h.get("head_commit"),
            "compare": h.get("base_commit") != h.get("head_commit"), "verdict": h.get("verdict"),
            "reasons": (h.get("verdict_reasons") or [])[:6], "policy": h.get("policy_decision"),
            "packages": inv.get("packages"),
            "inventory": {k: inv.get(k) for k in ("packages", "unique_name_versions", "direct", "transitive", "runtime", "dev_only",
                                                  "install_scripts", "unpinned", "ecosystems", "manifests", "lockfiles", "workflows",
                                                  "actions", "base_images", "edges")},
            "changes": {"files": len(changes.get("files") or []), "added": changes.get("added", 0),
                        "updated": changes.get("updated", 0), "removed": changes.get("removed", 0)},
            "package_changes": {k: (rep.get("package_changes") or {}).get(k, [])[:12] for k in ("added", "updated", "removed")},
            "vulnerabilities": {k: vul.get(k) or {} for k in ("introduced", "pre_existing", "fixed")},
            "scanners": vul.get("scanners") or {}, "scanner_errors": vul.get("errors") or {},
            "ci": {"actions": ci.get("actions"), "images": ci.get("images"), "introduced": ci.get("introduced", 0),
                   "pre_existing": ci.get("pre_existing", 0)},
            "signals": [{k: s.get(k) for k in ("type", "severity", "component", "summary", "hard_signal", "file", "line")} for s in signals[:8]],
            "signal_counts": {"introduced": sum(1 for s in sus if s.get("label") == "introduced"),
                              "pre_existing": sum(1 for s in sus if s.get("label") == "pre_existing"),
                              "not_checked": sum(1 for s in rep.get("suspicious_changes", []) if s.get("label") == "not_checked")},
            "sandbox": {k: (h.get("sandbox") or {}).get(k) for k in ("mode", "engine", "all_isolated", "tools")},
            "provenance": h.get("provenance"), "sbom_agreement_pct": h.get("sbom_agreement_pct"),
            "sboms": [f for f, name in (("guardian", "sbom.guardian.cdx.json"), ("cyclonedx", "sbom.syft.cdx.json"),
                                        ("spdx", "sbom.syft.spdx.json")) if (sb / name).exists()],
            "scanned_at": int((d / "latest.json").stat().st_mtime)}


@app.get("/api/policy")
def policy_result(project: str | None = None):
    """Policy-as-code result (Conftest/OPA, policies/*.rego) and how it combined with the risk-score verdict."""
    rep, _ = _report_and_dir(project)
    h = rep["headline"]
    pol = rep.get("policy") or {"engine": None, "decision": None, "deny": [], "warn": [], "error": "report made before policy-as-code"}
    rules = sorted(p.name for p in (ROOT / "policies").glob("*.rego"))
    return {**pol, "score_verdict": h.get("score_verdict", h.get("verdict")), "verdict": h.get("verdict"), "rule_files": rules}


@app.get("/api/provenance")
def provenance(project: str | None = None):
    rep, _ = _report_and_dir(project)
    return rep.get("provenance") or {"checked": 0, "packages": [], "errors": ["report made before registry checks"]}


@app.get("/api/remediation")
def remediation_plan(project: str | None = None):
    from guardian import remediation
    rep, d = _report_and_dir(project)
    if "repo" not in rep:
        raise HTTPException(409, "this report was made before remediation support: re-run the check")
    return {"plan": remediation.plan(rep), "validations": remediation.validations(d),
            "compare": rep["headline"].get("base_commit") != rep["headline"].get("head_commit")}


FIX_JOBS: dict[str, dict] = {}


class ValidateReq(BaseModel):
    project: str | None = None
    ids: list[str] = Field(min_length=1, max_length=50)


@app.post("/api/remediation/validate")
def remediation_validate(req: ValidateReq):
    """Apply the chosen fixes to a copy of the code (sandbox) and rescan before vs after. Runs in the background."""
    from guardian import remediation
    rep, d = _report_and_dir(req.project)
    if "repo" not in rep:
        raise HTTPException(409, "this report was made before remediation support: re-run the check")
    job = {"id": f"JOB-{uuid.uuid4().hex[:8]}", "status": "running", "log": [], "result": None, "error": None, "started": time.time()}
    FIX_JOBS[job["id"]] = job

    def work():
        try:
            job["result"] = remediation.validate(rep, req.ids, d, log=lambda m: job["log"].append(m))
            job["status"] = "done"
        except Exception as e:  # noqa: BLE001 surface to the UI
            job["status"], job["error"] = "error", f"{type(e).__name__}: {e}"[:400]
    threading.Thread(target=work, daemon=True).start()
    return {"job": job["id"]}


@app.get("/api/remediation/jobs/{jid}")
def remediation_job(jid: str):
    job = FIX_JOBS.get(jid)
    if not job:
        raise HTTPException(404, "unknown job")
    return job


class ApproveReq(BaseModel):
    project: str | None = None
    validation: str
    approver: str = Field(min_length=1, max_length=80)
    confirm: bool


@app.post("/api/remediation/approve")
def remediation_approve(req: ApproveReq):
    """Human approval: create a local branch with the validated fix. Never pushes, never merges."""
    from guardian import remediation
    if not req.confirm:
        raise HTTPException(400, "approval must be confirmed")
    rep, d = _report_and_dir(req.project)
    val = next((v for v in remediation.validations(d) if v["id"] == req.validation), None)
    if not val:
        raise HTTPException(404, "unknown validation")
    if val.get("approved"):
        raise HTTPException(409, f"already approved: branch {val['approved']['branch']}")
    if not val.get("ok"):
        raise HTTPException(409, "this validation did not pass (a step failed or the fix introduced new problems)")
    try:
        return remediation.approve(rep, val, req.approver)
    except ValueError as e:
        raise HTTPException(409, str(e)) from e
    except Exception as e:  # noqa: BLE001
        raise HTTPException(500, f"could not create the branch: {type(e).__name__}: {e}"[:300])


@app.get("/api/monitor")
def monitor_history(project: str | None = None):
    from guardian import monitor
    d = _check_dir(project)
    return {**monitor.history(d), "interval_minutes": MONITOR_INTERVAL or None}


@app.post("/api/monitor/run")
def monitor_run(project: str | None = None):
    """Re-check the saved inventory for newly disclosed vulnerabilities (no rescan of the code)."""
    from guardian import monitor
    d = _check_dir(project)
    if not (d / "latest.json").exists():
        raise HTTPException(404, "no report yet for this project")
    return monitor.recheck(d)


MONITOR_INTERVAL = 0
try:
    import os as _os
    MONITOR_INTERVAL = int(_os.environ.get("GUARDIAN_MONITOR_INTERVAL", "0") or 0)
except ValueError:
    MONITOR_INTERVAL = 0


def _monitor_loop():
    from guardian import monitor
    while True:
        time.sleep(MONITOR_INTERVAL * 60)
        for _name, d in monitor.targets(True, None):
            try:
                monitor.recheck(d)
            except Exception:  # noqa: BLE001 keep monitoring the others
                pass


if MONITOR_INTERVAL > 0:
    threading.Thread(target=_monitor_loop, daemon=True, name="guardian-monitor").start()


def _404():
    raise HTTPException(404, "unknown run")


if DIST.exists():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/{path:path}")
    def spa(path: str):
        f = (DIST / path).resolve()
        if path and f.is_relative_to(DIST.resolve()) and f.is_file():
            return FileResponse(f)
        return FileResponse(DIST / "index.html")
