"""Event handling: PR event → queue → fetch the exact commit (verified) → engine → events → GitHub statuses/comment.

Dependencies are injected (fetch, engine, github) so the same code runs in tests, with the polling backup and
with the GitHub Actions job. GitHub is only written to when a token is configured.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from guardian.trigger.events import EventStore
from guardian.trigger.github import GitHub, comment_body, status_for
from guardian.trigger.queue import RunQueue

SAFE_GIT = ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never", "-c", "core.symlinks=false"]
GIT_ENV = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo"}


def git_fetch_pr(root: Path):
    """Shallow, hook-free mirror per repository; returns (path, sha the PR ref actually points to)."""
    def fetch(repo: str, pr: int, head_sha: str, base_sha: str | None) -> tuple[Path, str]:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            raise ValueError("bad repository name")
        mirror = Path(root) / "mirrors" / repo.replace("/", "__")
        if not (mirror / ".git").exists():
            mirror.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(SAFE_GIT + ["clone", "-q", "--no-checkout", "--filter=blob:none", f"https://github.com/{repo}.git", str(mirror)],
                           check=True, capture_output=True, env=GIT_ENV, timeout=600)
        refs = [f"+refs/pull/{pr}/head:refs/guardian/pr-{pr}"] + ([base_sha] if base_sha else [])
        subprocess.run(SAFE_GIT + ["-C", str(mirror), "fetch", "-q", "origin", *refs], check=True, capture_output=True, env=GIT_ENV, timeout=600)
        sha = subprocess.run(["git", "-C", str(mirror), "rev-parse", f"refs/guardian/pr-{pr}"], capture_output=True, text=True, check=True).stdout.strip()
        return mirror, sha
    return fetch


class Service:
    def __init__(self, root: Path, *, fetch, engine, github: GitHub | None, identity_parts, run_url=None):
        self.root = Path(root)
        self.queue, self.events = RunQueue(self.root), EventStore(self.root)
        self.fetch, self.engine, self.github, self.identity_parts = fetch, engine, github, identity_parts
        self.run_url = run_url or (lambda rid: f"http://127.0.0.1:8765/#/runs/{rid}")

    def _post(self, fn, *a):
        if self.github is None:
            return "not posted: no GitHub token configured"
        try:
            fn(*a)
            return "posted"
        except Exception as e:  # GitHub outage must not change the analysis
            return f"post failed: {type(e).__name__}"

    def handle(self, e: dict) -> dict:
        run = self.queue.submit(e, rerun=e.get("action") == "rerun", **self.identity_parts())
        if run is None:
            self.events.append("-", "event_ignored", {"repo": e["repo"], "pr": e["pr"], "action": e.get("action")})
            return {"status": "ignored", "reason": "draft, closed or unsupported action"}
        rid = run["id"]
        if run["status"] == "done" and run.get("result"):
            return {"status": "reused", "run": run, "headline": run["result"]}
        self.events.append(rid, "run_queued", {k: run[k] for k in ("repo", "pr", "head_sha", "base_sha", "action")})
        self._post(lambda: self.github.set_status(e["repo"], e["head_sha"], {"state": "pending", "context": "guardian/scan",
                                                                            "description": "Guardian: scanning…"}, self.run_url(rid)))
        self.queue.start(rid)
        mirror, actual = self.fetch(e["repo"], e["pr"], e["head_sha"], e.get("base_sha"))
        if actual != e["head_sha"]:
            self.queue.finish(rid, {"stale": True})
            self.events.append(rid, "run_stale", {"expected": e["head_sha"], "found": actual})
            return {"status": "stale", "run": run, "reason": "the PR moved after the event; the newer event starts a new run"}
        self.events.append(rid, "scan_started", {"commit": actual})
        rep = self.engine(mirror, e.get("base_sha"), e["head_sha"], self.root / "runs" / rid, e["repo"].split("/")[-1])
        h = {**rep["headline"], "head_sha": e["head_sha"]}
        self.queue.finish(rid, {k: h.get(k) for k in ("verdict", "complete", "verdict_reasons", "incomplete_reasons")})
        self.events.append(rid, "scan_finished", {"verdict": h.get("verdict"), "complete": h.get("complete")})
        current = self.queue.current(e["repo"], e["pr"])
        posted = "superseded: not posted"
        if current and current["id"] == rid:
            posted = self._post(lambda: self.github.set_status(e["repo"], e["head_sha"], status_for(h), self.run_url(rid)))
            self._post(lambda: self.github.upsert_comment(e["repo"], e["pr"], comment_body(h, self.run_url(rid))))
        return {"status": "done", "run": self.queue.get(rid), "headline": h, "github": posted}
