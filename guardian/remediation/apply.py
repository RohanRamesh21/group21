"""The applier: the ONLY code in the remediation chain that writes files, and only behind the approval gate.

Safety (docs/DAY2_PROPOSAL.md section 4.2, CLAUDE.md section 3):
  * `gate()` refuses unless a human approval exists whose `plan_sha256` equals the plan's current hash (C7 extended)
    and the plan is intact. An agent has no tool that reaches this module.
  * Work happens in a throwaway COPY under guardian-out/remediation/<run>/work/<plan>/, never in the analysed project.
    The copy is a local git repo with a branch `guardian/fix/<plan_id>`. It is NEVER pushed (no remote is configured).
  * No analysed code runs. The only external command is `npm install --package-lock-only --ignore-scripts` (registry
    metadata fetch, allow-listed registry, project .npmrc moved aside so a PR cannot redirect it) and local `git`.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Callable

from guardian.remediation.models import FixPlan
from guardian.remediation.store import RemediationStore
from guardian.scoring.contextual import semver

REGISTRY = "https://registry.npmjs.org/"
SKIP = {"node_modules", ".git"}
GIT = ["git", "-c", "core.hooksPath=NUL" if os.name == "nt" else "core.hooksPath=/dev/null", "-c", "core.autocrlf=false",
       "-c", "user.name=guardian", "-c", "user.email=guardian@localhost", "-c", "commit.gpgsign=false", "-c", "protocol.file.allow=never"]
SAFE_ENV_KEYS = ("PATH", "PATHEXT", "SYSTEMROOT", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "ComSpec")


class ApplyRefused(Exception):
    """The gate said no. The message names the unmet condition."""


def safe_env() -> dict[str, str]:
    """A minimal environment for subprocesses: no API keys, tokens or proxies from the parent environment."""
    return {k: os.environ[k] for k in SAFE_ENV_KEYS if k in os.environ}


def gate(store: RemediationStore, plan_id: str) -> FixPlan:
    """Return the plan if (and only if) a matching human approval exists. Raises ApplyRefused otherwise."""
    plan = store.get_plan(plan_id)
    if plan is None:
        raise ApplyRefused(f"unknown plan {plan_id}")
    if not plan.intact():
        store.log("apply_refused", plan=plan_id, reason="plan hash mismatch")
        raise ApplyRefused("the plan changed after it was sealed: apply refused")
    mine = store.approvals(plan_id)
    if not mine:
        store.log("apply_refused", plan=plan_id, reason="no approval record")
        raise ApplyRefused("no human approval exists for this plan: apply refused (C7)")
    last = mine[-1]
    if last.decision != "approve":
        store.log("apply_refused", plan=plan_id, reason=f"last decision is {last.decision}")
        raise ApplyRefused(f"the last human decision for this plan is '{last.decision}', not approve")
    if last.plan_sha256 != plan.plan_sha256:
        store.log("apply_refused", plan=plan_id, reason="approval is for a different plan hash")
        raise ApplyRefused("the approval was given for a different version of the plan (hash mismatch): apply refused")
    if plan.status not in ("approved", "applied", "not_verified", "failed", "verified"):  # the approval stays valid for a re-run (e.g. Tier 2 after Tier 1)
        raise ApplyRefused(f"plan status is '{plan.status}': only an approved plan can be applied")
    if not plan.patch.supported:
        raise ApplyRefused("this plan is recommend-only in v1 (no automatic patch): " + "; ".join(plan.patch.notes))
    return plan


def _run(cmd: list[str], cwd: Path, timeout: int = 300, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env if env is not None else safe_env(), shell=False)


def _git(cwd: Path, *args: str) -> str:
    r = _run([*GIT, *args], cwd)
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:2])} failed: {(r.stderr or r.stdout).strip()[:300]}")
    return r.stdout.strip()


def _copy_tree(src: Path, dst: Path) -> None:
    for item in src.iterdir():
        if item.name in SKIP or item.is_symlink():
            continue
        target = dst / item.name
        if item.is_dir():
            shutil.copytree(item, target, ignore=shutil.ignore_patterns(*SKIP), symlinks=False)
        else:
            shutil.copy2(item, target)


def _clear(dst: Path) -> None:
    for item in dst.iterdir():
        if item.name == ".git":
            continue
        shutil.rmtree(item) if item.is_dir() else item.unlink()


def npm_lockfile(tree: Path) -> dict:
    """Default lockfile step: registry METADATA only (`--package-lock-only`), lifecycle scripts disabled."""
    npm = shutil.which("npm")
    if not npm:
        return {"status": "failed", "detail": "npm is not installed on this machine"}
    rc = tree / ".npmrc"
    moved = None
    if rc.exists():  # a PR can redirect the registry through .npmrc: never honour the project's file in the sandbox
        moved = tree / ".npmrc.guardian-aside"
        rc.rename(moved)
    try:
        # two DISTINCT empty config files (npm exits 0 without doing anything when both point at the same path)
        user_cfg, global_cfg = tree.parent / ".guardian-npmrc-user", tree.parent / ".guardian-npmrc-global"
        user_cfg.write_text("")
        global_cfg.write_text("")
        r = _run([npm, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", "--registry", REGISTRY,
                  "--userconfig", str(user_cfg), "--globalconfig", str(global_cfg)], tree, 600)  # no npm config from the machine or the project
        return {"status": "ok" if r.returncode == 0 else "failed", "detail": ((r.stderr if r.returncode else r.stdout) or "").strip()[-600:],
                "fetch_hosts": [REGISTRY], "project_npmrc_ignored": bool(moved)}
    except subprocess.TimeoutExpired:
        return {"status": "failed", "detail": "npm install --package-lock-only timed out after 600 s"}
    finally:
        if moved:
            moved.rename(rc)


def verify_lock(plan: FixPlan, repo: Path) -> tuple[bool, str]:
    """Post-condition of the lockfile step: the regenerated package-lock.json must really contain the planned change.

    A tool that exits 0 without doing the work (it has happened with npm) must never count as a successful fix."""
    if not plan.package or plan.type not in ("upgrade_to_fixed", "override_transitive", "remove_package"):
        return True, "no lockfile post-condition for this fix type"
    try:
        pk = json.loads((repo / "package-lock.json").read_text(encoding="utf-8")).get("packages") or {}
    except (OSError, ValueError) as e:
        return False, f"package-lock.json is missing or unreadable after the lockfile step ({type(e).__name__})"
    key = f"node_modules/{plan.package}"
    copies = {p: e.get("version") for p, e in pk.items() if p == key or p.endswith("/" + key)}
    top = pk.get(key, {}).get("version")
    if plan.type == "remove_package":
        return (not copies, f"{plan.package} is gone from the lockfile" if not copies else
                f"{plan.package} is still in the lockfile ({', '.join(sorted(copies))}): another dependency needs it")
    if plan.type == "override_transitive":
        bad = {p: v for p, v in copies.items() if v != plan.target}
        return (bool(copies) and not bad, f"every copy of {plan.package} resolves to {plan.target}" if copies and not bad else
                f"the override did not take effect: {plan.package} resolves to {', '.join(sorted(set(map(str, (bad or {'(none)': '?'}).values()))))}")
    ok = top is not None and (semver.cmp(top, plan.target or "") or 0) >= 0
    return ok, (f"{plan.package} resolves to {top} (>= {plan.target})" if ok else f"{plan.package} resolves to {top}, not {plan.target} or newer")


def _inside(root: Path, rel: str) -> Path:
    p = (root / rel).resolve()
    if root.resolve() not in p.parents and p != root.resolve():
        raise ApplyRefused(f"refusing to write outside the working copy: {rel}")
    return p


def apply_plan(store: RemediationStore, plan_id: str, src: Path, base_src: Path | None = None,
               lockfile: Callable[[Path], dict] = npm_lockfile) -> dict:
    """Apply an APPROVED plan in a throwaway local git copy. Returns the work-copy description. Never pushes."""
    plan = gate(store, plan_id)
    work = store.root / "work" / plan_id
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    repo = work / "repo"
    repo.mkdir(parents=True)
    steps: list[dict] = []
    try:
        _git(repo, "init", "-q")
        _git(repo, "checkout", "-q", "-b", "pr-base")
        if base_src is not None:  # same comparison frame as the original PR check
            _copy_tree(base_src, repo)
            _git(repo, "add", "-A")
            _git(repo, "commit", "-q", "--no-verify", "--allow-empty", "-m", "base (original base ref export)")
            _git(repo, "checkout", "-q", "-b", "pr-head")
            _clear(repo)
        else:
            _git(repo, "checkout", "-q", "-b", "pr-head")
        _copy_tree(src, repo)
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "--no-verify", "--allow-empty", "-m", "head (original PR head export)")
        branch = f"guardian/fix/{plan_id}"
        _git(repo, "checkout", "-q", "-b", branch)
        steps.append({"name": "copy", "status": "ok", "detail": f"throwaway copy with local branch {branch} (no remote, never pushed)"})
        for rel, text in plan.patch.files.items():
            _inside(repo, rel).parent.mkdir(parents=True, exist_ok=True)
            _inside(repo, rel).write_text(text, encoding="utf-8", newline="")
        for rel in plan.patch.delete_files:
            _inside(repo, rel).unlink(missing_ok=True)
        steps.append({"name": "patch", "status": "ok", "detail": f"wrote {len(plan.patch.files)} file(s), deleted {len(plan.patch.delete_files)}"})
        if plan.patch.lockfile == "regenerate":
            res = lockfile(repo)
            steps.append({"name": "lockfile", "status": res["status"], "detail": res.get("detail", ""), **{k: v for k, v in res.items() if k not in ("status", "detail")}})
            if res["status"] != "ok":
                raise RuntimeError("lockfile regeneration failed: " + res.get("detail", "")[:300])
            ok, why = verify_lock(plan, repo)
            steps.append({"name": "lockfile post-condition", "status": "ok" if ok else "failed", "detail": why})
            if not ok:
                raise RuntimeError("the lockfile does not contain the planned change: " + why)
        else:
            steps.append({"name": "lockfile", "status": "skipped", "detail": "this patch does not change the manifest"})
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "--no-verify", "--allow-empty", "-m", f"guardian fix {plan_id}: {plan.type} {plan.target or ''}".strip())
        stat = _git(repo, "diff", "--stat", "pr-head", branch)
        full = _git(repo, "diff", "pr-head", branch)
    except Exception as e:
        store.log("apply_failed", plan=plan_id, reason=f"{type(e).__name__}: {e}"[:300])
        store.set_status(plan_id, "failed")
        raise
    store.set_status(plan_id, "applied")
    store.log("applied", plan=plan_id, branch=branch, work=str(repo), pushed=False)
    (work / "fix.diff").write_text(full, encoding="utf-8")
    return {"branch": branch, "repo": str(repo), "base_ref": "pr-base" if base_src is not None else None, "head_ref": "pr-head", "fix_ref": branch,
            "steps": steps, "diff_stat": stat, "diff": full[:20000], "pushed": False}
