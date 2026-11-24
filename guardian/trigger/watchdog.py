"""Missed-PR watchdog, run every 10 minutes by launchd (cron backup for the GitHub Actions trigger).

If the runner was offline when a PR was opened or pushed, no Guardian status exists on its head commit. The watchdog finds
those PRs and submits them to the same server endpoint the runner uses, so the same queue and engine handle them.
Usage: python -m guardian.trigger.watchdog --repo owner/name [--repo owner/other]
"""
from __future__ import annotations

import argparse
import json
import os
import urllib.request


def missed(github, repo: str, runs: list[dict]) -> list[dict]:
    have = {(r["repo"], r["pr"], r["head_sha"]) for r in runs if r.get("status") in ("queued", "running", "done")}
    out = []
    for p in github.open_pulls(repo):
        sha = p["head"]["sha"]
        if p.get("draft") or (repo, p["number"], sha) in have:
            continue
        if any(s.get("context") == "guardian/scan" for s in github.statuses(repo, sha)):
            continue
        out.append({"repo": repo, "pr": p["number"], "action": "opened", "head_sha": sha, "base_sha": p["base"]["sha"],
                    "draft": False, "title": (p.get("title") or "")[:200], "wait": False})
    return out


def main() -> int:
    from guardian import config
    from guardian.trigger.github import GitHub
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", action="append", required=True, help="repeat for several repositories")
    ap.add_argument("--server", default=os.environ.get("GUARDIAN_URL", "http://127.0.0.1:8765"))
    a = ap.parse_args()
    config.load_env()
    gh = GitHub(os.environ["GUARDIAN_GITHUB_TOKEN"])
    with urllib.request.urlopen(f"{a.server}/api/trigger/current", timeout=20) as r:
        runs = json.loads(r.read()).get("runs", [])
    events = [e for repo in a.repo for e in missed(gh, repo, runs)]
    for e in events:
        req = urllib.request.Request(f"{a.server}/api/github/event", data=json.dumps(e).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=30).read()
        print(f"watchdog: submitted {e['repo']}#{e['pr']} ({e['head_sha'][:8]})")
    print(f"watchdog: {len(events)} missed PR(s) across {', '.join(a.repo)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
