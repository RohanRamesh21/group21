"""Pre-merge check: what is in the app, what changed, what appears risky.

M1: there is one analysis engine, `guardian.universal.check_any`. This module stays as a stable entry point
for older callers; it adds nothing of its own, so every interface (CLI, dashboard, agents, CI) gets the same result.
"""
from __future__ import annotations

from pathlib import Path


def check(repo: Path, base: str, head: str, out: Path) -> dict:
    from guardian.universal import check_any
    return check_any(Path(repo), base, head, Path(out), Path(repo).name)
