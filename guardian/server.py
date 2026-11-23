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
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from guardian import config
from guardian.agents.boundary import redact

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "guardian-out" / "dashboard"
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


def _meta() -> dict:
    """Headline numbers from the real scenario (git + lockfile only, no network)."""
    try:
        from guardian.adapters.npm import parse_lockfile
        from guardian.universal import git_show
        repo = ROOT / "sandbox" / "uptime-kuma"
        locks = {ref: git_show(repo, ref, "package-lock.json") for ref in ("scenario/base", "scenario/s3-s9")}
        if None in locks.values():
            raise FileNotFoundError("scenario/base or scenario/s3-s9 has no package-lock.json")
        base, _ = parse_lockfile(locks["scenario/base"])
        head, _ = parse_lockfile(locks["scenario/s3-s9"])
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
    mode: Literal["replay", "live"] = "replay"
    world: Literal["canned", "real"] = "canned"
    pace: float = Field(default=0.55, ge=0, le=2)


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
    backend = "replay" if req.mode == "replay" else config.provider()
    if req.mode == "live" and backend == "replay":
        raise HTTPException(400, "no LLM key configured in guardian/.env")
    run_id = f"RUN-{uuid.uuid4().hex[:16].upper()}"
    r = Run(run_id, req.mode, req.world)
    RUNS[run_id] = r

    def attach(board, store):
        r.board, r.store, r.status = board, store, "running"

    def work():
        try:
            run_agents(OUT / run_id, backend=backend, run_id=run_id, world_kind=req.world,
                       pace=req.pace if req.mode == "replay" else 0.0, human_override=r.human, on_board=attach)
            r.status = "done"
        except BaseException as e:  # noqa: BLE001  surface any failure to the UI
            r.status, r.error = "error", f"{type(e).__name__}: investigation could not start or save its result"

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
        f = (DIST / path).resolve()
        if path and f.is_relative_to(DIST.resolve()) and f.is_file():
            return FileResponse(f)
        return FileResponse(DIST / "index.html")
