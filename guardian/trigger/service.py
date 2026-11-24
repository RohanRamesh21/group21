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
        if pr == 0:  # nightly: the exact default-branch commit GitHub named
            subprocess.run(SAFE_GIT + ["-C", str(mirror), "fetch", "-q", "origin", f"+{head_sha}:refs/guardian/nightly"],
                           check=True, capture_output=True, env=GIT_ENV, timeout=600)
            ref = "refs/guardian/nightly"
        else:
            refs = [f"+refs/pull/{pr}/head:refs/guardian/pr-{pr}"] + ([base_sha] if base_sha else [])
            subprocess.run(SAFE_GIT + ["-C", str(mirror), "fetch", "-q", "origin", *refs], check=True, capture_output=True, env=GIT_ENV, timeout=600)
            ref = f"refs/guardian/pr-{pr}"
        sha = subprocess.run(["git", "-C", str(mirror), "rev-parse", ref], capture_output=True, text=True, check=True).stdout.strip()
        return mirror, sha
    return fetch


class Service:
    def __init__(self, root: Path, *, fetch, engine, github: GitHub | None, identity_parts, run_url=None):
        self.root = Path(root)
        self.queue, self.events = RunQueue(self.root), EventStore(self.root)
        self.fetch, self.engine, self.github, self.identity_parts = fetch, engine, github, identity_parts
        self.run_url = run_url or (lambda rid: f"http://127.0.0.1:8765/?run=gh-{rid}#summary")
        self.after_scan = None  # set by the server: starts the agents for BLOCK/REVIEW runs

    def _post(self, fn, *a):
        if self.github is None:
            return "not posted: no GitHub token configured"
        try:
            fn(*a)
            return "posted"
        except Exception as e:  # GitHub outage or missing token permission must not change the analysis
            return f"post failed: {type(e).__name__}: {str(e)[:120]}"

    def handle(self, e: dict) -> dict:
        if e.get("action") == "nightly":
            return self.nightly(e)
        run = self.queue.submit(e, rerun=e.get("action") == "rerun", **self.identity_parts())
        if run is not None and e.get("title") and run.get("title") != e["title"]:
            run["title"] = str(e["title"])[:200]  # untrusted text: stored and shown escaped, never interpreted
            self.queue._save()
        if run is None:
            self.events.append("-", "event_ignored", {"repo": e["repo"], "pr": e["pr"], "action": e.get("action")})
            return {"status": "ignored", "reason": "draft, closed or unsupported action"}
        rid = run["id"]
        if run["status"] == "done" and run.get("result"):
            h = {**run["result"], "head_sha": e["head_sha"]}
            if self.github is not None and h.get("verdict") is not None:  # re-post: an earlier post may have failed
                posted = self._post(lambda: self.github.set_status(e["repo"], e["head_sha"], status_for(h), self.run_url(rid)))
                commented = self._post(lambda: self.github.upsert_comment(e["repo"], e["pr"], comment_body(h, self.run_url(rid))))
                self.events.append(rid, "github_post", {"what": "status", "result": posted, "pr": e["pr"], "project": f"gh-{rid}", "reused": True})
                self.events.append(rid, "github_post", {"what": "comment", "result": commented, "pr": e["pr"], "project": f"gh-{rid}", "reused": True})
            return {"status": "reused", "run": run, "headline": run["result"]}
        self.events.append(rid, "run_queued", {**{k: run[k] for k in ("repo", "pr", "head_sha", "base_sha", "action")},
                                               "title": run.get("title", ""), "project": f"gh-{rid}"})
        self._post(lambda: self.github.set_status(e["repo"], e["head_sha"], {"state": "pending", "context": "guardian/scan",
                                                                            "description": "Guardian: scanning…"}, self.run_url(rid)))
        self.queue.start(rid)
        stopped = lambda: (self.queue.get(rid) or {}).get("status") == "cancelled"  # noqa: E731  (Buddy 'Stop')
        mirror, actual = self.fetch(e["repo"], e["pr"], e["head_sha"], e.get("base_sha"))
        if actual != e["head_sha"]:
            self.queue.finish(rid, {"stale": True})
            self.events.append(rid, "run_stale", {"expected": e["head_sha"], "found": actual})
            return {"status": "stale", "run": run, "reason": "the PR moved after the event; the newer event starts a new run"}
        if stopped():
            return {"status": "cancelled", "run": self.queue.get(rid)}
        self.events.append(rid, "scan_started", {"commit": actual})
        rep = self.engine(mirror, e.get("base_sha"), e["head_sha"], self.root / "runs" / rid, e["repo"].split("/")[-1])
        if stopped():  # stopped while the engine ran: its result is kept on disk, but no verdict is posted or acted on
            self.queue.finish(rid, {"stopped": True})
            return {"status": "cancelled", "run": self.queue.get(rid)}
        h = {**rep["headline"], "head_sha": e["head_sha"]}
        self.queue.finish(rid, {k: h.get(k) for k in ("verdict", "complete", "verdict_reasons", "incomplete_reasons")})
        self.events.append(rid, "scan_finished", {"verdict": h.get("verdict"), "complete": h.get("complete"), "repo": e["repo"],
                                                  "pr": e["pr"], "title": run.get("title", ""), "project": f"gh-{rid}",
                                                  "reasons": (h.get("verdict_reasons") or [])[:3]})
        current = self.queue.current(e["repo"], e["pr"])
        posted = "superseded: not posted"
        if current and current["id"] == rid:
            posted = self._post(lambda: self.github.set_status(e["repo"], e["head_sha"], status_for(h), self.run_url(rid)))
            commented = self._post(lambda: self.github.upsert_comment(e["repo"], e["pr"], comment_body(h, self.run_url(rid))))
            self.events.append(rid, "github_post", {"what": "status", "result": posted, "pr": e["pr"], "project": f"gh-{rid}"})
            self.events.append(rid, "github_post", {"what": "comment", "result": commented, "pr": e["pr"], "project": f"gh-{rid}"})
        if self.after_scan and current and current["id"] == rid and h.get("verdict") in ("block", "review") and h.get("complete"):
            self.after_scan(rid, self.root / "runs" / rid, h, e)
        return {"status": "done", "run": self.queue.get(rid), "headline": h, "github": posted}

    def nightly(self, e: dict) -> dict:
        """Re-check the default branch with fresh advisory data. Report only advisories not seen on earlier nights
        (newly disclosed), in one issue that is updated, never duplicated. The first night records the baseline."""
        import json as _json
        import time as _time
        repo = e["repo"]
        self.events.append("nightly", "nightly_started", {"repo": repo, "head_sha": e["head_sha"]})
        mirror, actual = self.fetch(repo, 0, e["head_sha"], None)
        out = self.root / "nightly" / repo.replace("/", "__") / _time.strftime("%Y%m%d-%H%M%S")
        rep = self.engine(mirror, None, actual, out, repo.split("/")[-1])
        keys = sorted({v["key"] for v in rep.get("vulnerabilities", []) if v.get("key")})
        state_file = self.root / "nightly" / f"{repo.replace('/', '__')}.json"
        state = _json.loads(state_file.read_text()) if state_file.exists() else None
        newly = [] if state is None else [k for k in keys if k not in set(state["seen"])]
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text(_json.dumps({"seen": sorted(set(keys) | set((state or {}).get("seen", []))), "last_run": _time.time(),
                                           "head_sha": actual}))
        posted = "nothing new"
        if newly:
            sev = {v["key"]: v.get("severity", "?") for v in rep.get("vulnerabilities", [])}
            body = (f"Guardian's nightly re-check of `{actual[:12]}` found **{len(newly)} newly disclosed** advisories in code that did not change.\n\n"
                    + "\n".join(f"- `{k}` ({sev.get(k)})" for k in newly)
                    + "\n\n_These were published after the code was merged; they are not attributed to any pull request._")
            posted = self._post(lambda: self.github.upsert_issue(repo, f"Guardian nightly: {len(newly)} newly disclosed advisories", body))
        self.events.append("nightly", "nightly_finished", {"repo": repo, "newly_disclosed": len(newly), "baseline": state is None})
        return {"status": "done", "nightly": True, "newly_disclosed": newly, "baseline": state is None, "github": posted,
                "headline": {"verdict": None, "complete": True}}
