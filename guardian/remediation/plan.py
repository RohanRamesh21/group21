# READING GUIDE
# Fix coordinator: load saved findings, verify requested commits match the scan, generate candidates and build one patch.
# The saved plan is a proposal. Generating it does not apply changes to the user's working repository.
#
"""Fix plan for a finished run: candidates for the change's findings + one combined patch, bound to full commits.

The plan is a proposal. Nothing is applied to the user's repository; approval (M5) binds to the patch hash.
"""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

from guardian.remediation.candidates import Sources, generate, live_sources
from guardian.remediation.patch import build_patch


class StaleRun(RuntimeError):
    """The stored run was made for other commits than the ones requested."""


def _sha(repo: Path, ref: str) -> str:
    r = subprocess.run(["git", "-C", str(repo), "rev-parse", f"{ref}^{{commit}}"], capture_output=True, text=True)
    if r.returncode != 0:
        raise ValueError(f"unknown revision {ref}")
    return r.stdout.strip()


def load_run(out_dir: Path) -> tuple[dict, dict]:
    latest = json.loads((out_dir / "latest.json").read_text())
    report = json.loads(Path(latest["path"]).read_text())
    if not latest.get("scores"):
        raise RuntimeError(f"run has no scores: {latest.get('scores_error')}")
    return report, json.loads(Path(latest["scores"]).read_text())


# Ensure findings belong to the requested commits before generating candidates and one reviewable patch.
def propose(repo: Path, base: str | None, head: str, out_dir: Path, include: list[str] | tuple = (),
            sources: Sources | None = None) -> dict:
    repo, out_dir = Path(repo), Path(out_dir)
    report, scores = load_run(out_dir)
    head_sha = _sha(repo, head)
    base_sha = _sha(repo, base) if base else None
    h = report["headline"]
    if not head_sha.startswith(h["head_commit"]) or (base_sha and not base_sha.startswith(h["base_commit"])):
        raise StaleRun(f"run is for {h['base_commit']}..{h['head_commit']}, not {(base_sha or '')[:12]}..{head_sha[:12]}: rescan first")
    wanted = set(include)
    picked = [f for f in scores["findings"] if f["label"] == "introduced" or f["id"] in wanted]
    cands = generate(picked, report, sources or live_sources())
    patch = build_patch(repo, base_sha or head_sha, head_sha, cands, out_dir)
    plan = {"created": time.time(), "repo": str(repo), "base_sha": base_sha, "head_sha": head_sha,
            "report": str(out_dir / "latest.json"), "findings_considered": [f["id"] for f in picked],
            "candidates": cands, "patch": patch,
            "pending": ["Fixer/Verifier explanations need the AI model (M3/M4 agent part)"]}
    (out_dir / "fix-plan.json").write_text(json.dumps(plan, indent=1))
    return plan
