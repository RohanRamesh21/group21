"""Polling backup for the GitHub Actions trigger: same events, same queue (PR_TRIGGER_PLAN §3).

Detects: new PR, new commits, draft → ready, base change, closed/merged. GitHub's list is fully paginated by the client.
"""
from __future__ import annotations

import threading
import time


def poll_once(github, repo: str, state: dict, handle) -> None:
    pulls = {p["number"]: p for p in github.open_pulls(repo)}
    for n, p in pulls.items():
        cur = {"head": p["head"]["sha"], "base": p["base"]["sha"], "ref": p["base"].get("ref"), "draft": bool(p.get("draft"))}
        prev = state.get(n)
        state[n] = cur
        if cur["draft"]:
            continue
        if prev is None:
            action = "opened"
        elif prev["draft"]:
            action = "ready_for_review"
        elif prev["head"] != cur["head"]:
            action = "synchronize"
        elif prev["base"] != cur["base"] or prev["ref"] != cur["ref"]:
            action = "edited"
        else:
            continue
        handle({"repo": repo, "pr": n, "action": action, "head_sha": cur["head"], "base_sha": cur["base"], "draft": False})
    for n in [n for n in state if n not in pulls]:
        last = state.pop(n)
        handle({"repo": repo, "pr": n, "action": "closed", "head_sha": last["head"], "base_sha": last["base"], "draft": False})


def start(github, repos: list[str], handle, interval: float = 30.0) -> threading.Thread:
    """Background loop; errors are logged and retried after the interval (rate limits back off naturally)."""
    state: dict[str, dict] = {r: {} for r in repos}

    def loop():
        while True:
            for r in repos:
                try:
                    poll_once(github, r, state[r], handle)
                except Exception as e:  # keep polling; never crash the server
                    print(f"[watcher] {r}: {type(e).__name__}")
            time.sleep(interval)
    t = threading.Thread(target=loop, daemon=True, name="guardian-watcher")
    t.start()
    return t
