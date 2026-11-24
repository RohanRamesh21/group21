"""What the AHP advisor needs from a run: its scores and the head source tree (read-only).

Replaces the RemediationContext the contextual-scoring branch used, so the advisor works on every run of this
dashboard (main scenario, scanned projects, GitHub PR runs) without that branch's remediation package.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AhpContext:
    scores: dict
    src: Path | None


def out_dir(project: str | None) -> Path:
    from guardian.server import _check_dir  # same project resolution as every other endpoint (incl. gh-<run> PR runs)
    return _check_dir(project)


def load(project: str | None) -> AhpContext:
    out = out_dir(project)
    latest = out / "latest.json"
    if not latest.exists():
        raise FileNotFoundError("no run yet")
    ptr = json.loads(latest.read_text())
    if not ptr.get("scores"):
        raise FileNotFoundError("this run has no scores yet")
    scores = json.loads(Path(ptr["scores"]).read_text())
    report = json.loads(Path(ptr["path"]).read_text())
    head = (report.get("runs") or {}).get("head")
    src = Path(head) / "src" if head and (Path(head) / "src").is_dir() else None
    return AhpContext(scores=scores, src=src)
