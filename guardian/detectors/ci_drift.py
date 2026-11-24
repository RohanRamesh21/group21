"""Base-vs-head CI drift detectors (hard signals from CLAUDE.md section 3.2).

D11 action_sha_to_tag
    Signal:   a GitHub Action that was pinned to a full commit SHA on base is referenced by a tag/branch on head.
    Why:      a SHA is immutable; a tag can be moved by whoever controls the action repo, so the same workflow
              file would run different code tomorrow.
    Incident: tj-actions/changed-files (March 2025): tags were repointed to a malicious commit.
    False positives: a legitimate switch to a tag of an action the team owns (first-party); we still flag it
              because the review is cheap and the floor is "high", not "critical".
    Not covered: "tag moved" needs live tag resolution on GitHub, which is outside the sandbox rules
              (CLAUDE.md 3.1), so only the SHA -> tag direction is detected.

D12 history_rewrite
    Signal:   the base commit is not an ancestor of the head commit.
    Why:      a force-push or rebase can silently drop or replace reviewed commits.
    Incident: general class of "rewritten history hides a malicious or removed commit".
    False positives: comparing two unrelated branches (e.g. two scenario branches) also triggers it; the
              check is skipped when `base` and `head` are the same commit.
"""
from __future__ import annotations

import subprocess
from pathlib import Path


def _action_id(uses: str) -> str:
    """'owner/repo/path@ref' -> 'owner/repo/path' (the action without its version)."""
    return uses.split("@", 1)[0]


def action_sha_to_tag(base_actions: list[dict], head_actions: list[dict]) -> list[dict]:
    """Pure function: actions that lost their SHA pin between base and head (same workflow file)."""
    pinned_before = {(a["workflow"], _action_id(a["uses"])) for a in base_actions if a.get("pinned_sha")}
    out = []
    for a in head_actions:
        if a["uses"].startswith(("./", "docker://")) or a.get("pinned_sha"):
            continue
        if (a["workflow"], _action_id(a["uses"])) in pinned_before:
            out.append({"detector": "D11", "type": "action_sha_to_tag", "component": a["uses"], "severity": "high",
                        "hard_signal": True, "label": "introduced", "file": a["workflow"], "line": a.get("line"),
                        "summary": f"{_action_id(a['uses'])} was pinned to a commit SHA on base and is now referenced by "
                                   f"'{a['uses'].split('@', 1)[-1]}'; a moved tag would run new code in CI"})
    return out


def history_rewrite(repo: Path, base: str, head: str) -> list[dict]:
    """Reads git only (never executes repository code). Empty list when base is an ancestor of head."""
    def rev(ref: str) -> str:
        return subprocess.run(["git", "-C", str(repo), "rev-parse", ref], capture_output=True, text=True, check=True).stdout.strip()

    b, h = rev(base), rev(head)
    if b == h:
        return []
    r = subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", b, h], capture_output=True, text=True)
    if r.returncode == 0:
        return []
    if r.returncode != 1:
        raise RuntimeError(f"git merge-base failed: {r.stderr.strip()[:200]}")
    return [{"detector": "D12", "type": "history_rewrite", "component": f"{base}..{head}", "severity": "high",
             "hard_signal": True, "label": "introduced",
             "summary": f"base commit {b[:8]} is not an ancestor of head {h[:8]}: history was rewritten or the refs are unrelated"}]
