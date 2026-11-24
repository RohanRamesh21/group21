"""Run queue for PR events: analysis identity, de-duplication, supersede, current run per PR (PR_TRIGGER_PLAN §4)."""
from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from pathlib import Path

START = {"opened", "synchronize", "reopened", "ready_for_review", "edited", "rerun"}


def identity(e: dict, *, policy_sha256: str, profile_sha256: str, intel: str) -> str:
    """Same identity = same analysis can be reused. The event name itself is not part of it."""
    parts = [e["repo"], str(e["pr"]), e.get("base_sha") or "", e["head_sha"], policy_sha256, profile_sha256, intel]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:20]


class RunQueue:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.file = self.root / "runs.json"
        self._lock = threading.Lock()
        self.runs: dict[str, dict] = json.loads(self.file.read_text()) if self.file.exists() else {}

    def _save(self) -> None:
        self.file.write_text(json.dumps(self.runs, indent=1))

    def get(self, rid: str) -> dict | None:
        return self.runs.get(rid)

    def current(self, repo: str, pr: int) -> dict | None:
        live = [r for r in self.runs.values() if r["repo"] == repo and r["pr"] == pr and r["status"] in ("queued", "running", "done")]
        return max(live, key=lambda r: r["created"]) if live else None

    def submit(self, e: dict, *, rerun: bool = False, **idn) -> dict | None:
        with self._lock:
            if e.get("action") == "closed":
                for r in self.runs.values():
                    if r["repo"] == e["repo"] and r["pr"] == e["pr"] and r["status"] in ("queued", "running", "done"):
                        r["status"] = "closed"
                self._save()
                return None
            if e.get("draft") or e.get("action") not in START:
                return None
            key = identity(e, **idn)
            cur = self.current(e["repo"], e["pr"])
            if cur and cur["identity"] == key and not rerun:
                return cur  # duplicate delivery or same state: reuse
            if cur:
                cur["status"] = "superseded"
                cur["superseded_by_head"] = e["head_sha"]
            rid = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
            run = {"id": rid, "identity": key, "repo": e["repo"], "pr": e["pr"], "base_sha": e.get("base_sha"),
                   "head_sha": e["head_sha"], "action": e.get("action"), "status": "queued", "created": time.time(), **idn}
            self.runs[rid] = run
            self._save()
            return run

    def start(self, rid: str) -> None:
        with self._lock:
            if self.runs[rid]["status"] == "queued":
                self.runs[rid]["status"] = "running"
                self._save()

    def finish(self, rid: str, result: dict) -> None:
        """Store the result; a superseded run keeps its status (its late result is kept for the audit trail only)."""
        with self._lock:
            r = self.runs[rid]
            r["result"] = result
            r["finished"] = time.time()
            if r["status"] in ("queued", "running"):
                r["status"] = "done"
            self._save()
