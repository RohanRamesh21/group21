"""guardian-submit: called by the GitHub Actions job on our self-hosted runner.

Reads the PR identity from environment variables (never from inlined `${{ }}` expressions), validates it strictly,
sends it to the local Guardian server, waits for the scan decision and exits with it:
0 allow · 1 review · 2 block · 3 incomplete · 64 bad input · 70 server unreachable.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.request

REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ACTIONS = {"opened", "synchronize", "reopened", "ready_for_review", "edited", "closed"}


def _post(url: str, payload: dict, timeout: int) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:  # local server only (127.0.0.1 by default)
        return json.loads(r.read())


def main(env: dict | None = None) -> int:
    env = os.environ if env is None else env
    repo, pr, action = env.get("REPO", ""), env.get("PR", ""), env.get("ACTION", "")
    base, head = env.get("BASE_SHA", ""), env.get("HEAD_SHA", "")
    if not (REPO_RE.match(repo) and pr.isdigit() and action in ACTIONS and SHA_RE.match(head) and (not base or SHA_RE.match(base))):
        print("guardian-submit: refusing malformed input", file=sys.stderr)
        return 64
    url = env.get("GUARDIAN_URL", "http://127.0.0.1:8765").rstrip("/") + "/api/github/event"
    try:
        res = _post(url, {"repo": repo, "pr": int(pr), "action": action, "base_sha": base or None, "head_sha": head,
                          "draft": env.get("DRAFT") == "true", "wait": True}, timeout=1500)
    except Exception as e:
        print(f"guardian-submit: Guardian server unreachable ({type(e).__name__})", file=sys.stderr)
        return 70
    h = res.get("headline") or {}
    print(json.dumps({"run": (res.get("run") or {}).get("id"), "verdict": h.get("verdict"), "complete": h.get("complete")}))
    if action == "closed":
        return 0
    if h.get("verdict") == "block":
        return 2
    if not h.get("complete") or h.get("verdict") not in ("allow", "review"):
        return 3
    return 0 if h["verdict"] == "allow" else 1


if __name__ == "__main__":
    sys.exit(main())
