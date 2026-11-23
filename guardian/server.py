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

from fastapi import FastAPI, HTTPException
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


@app.get("/api/depgraph")
def depgraph():
    """Full dependency graph of the PR head from the latest `guardian check` report, with risk overlaid.
    Real scan data (lockfile + OSV + Grype + detectors); no LLM involved."""
    latest = ROOT / "guardian-out" / "check" / "latest.json"
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
        f = DIST / path
        return FileResponse(f if path and f.is_file() else DIST / "index.html")
