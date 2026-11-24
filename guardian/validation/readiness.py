"""Validation readiness: can this fix plan pass validation at all? Answered BEFORE anyone approves or runs it.

Static only: reads git objects, lockfiles, the plan and the profile; never installs, builds or runs project code. It
catches the failures we saw in real runs before they cost a human approval and a multi-minute sandbox run:
- the PR was compared with a base-branch tip far past its merge base (hundreds of unrelated "introduced" findings and
  a fix that removed packages the app needs);
- the patch removes or changes a package the validation profile must build (its allow-listed install hook);
- no profile names the repository (the default profile is someone else's app);
- an incomplete plan, a stale approval, or a missing sandbox image / registry.
(Prior work gates updates before they reach CI, e.g. Renovate's minimum release age; VulnBump's pass rule needs the
dependencies to resolve first.)
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

from guardian import approval as ap
from guardian.validation import runner as vr


def _git(repo: str | Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=60)


def _lock_at(repo: str, sha: str) -> dict | None:
    r = _git(repo, "show", f"{sha}:package-lock.json")
    try:
        return json.loads(r.stdout) if r.returncode == 0 else None
    except ValueError:
        return None


def _candidate_lock(repo: str, head: str, patch: Path) -> dict | None:
    """The head lockfile with the approved patch applied (lockfile and manifest only, in a scratch folder)."""
    with tempfile.TemporaryDirectory() as tmp:
        for f in ("package-lock.json", "package.json"):
            r = _git(repo, "show", f"{head}:{f}")
            if r.returncode == 0:
                (Path(tmp) / f).write_text(r.stdout)
        env = {**os.environ, "GIT_CEILING_DIRECTORIES": str(Path(tmp).parent)}
        r = subprocess.run(["git", "apply", "--include=package-lock.json", "--include=package.json", "--whitespace=nowarn", "-"],
                           input=patch.read_bytes(), cwd=tmp, capture_output=True, env=env, timeout=60)
        if r.returncode != 0:
            return None
        try:
            return json.loads((Path(tmp) / "package-lock.json").read_text())
        except (OSError, ValueError):
            return None


def _environment() -> list[dict]:
    """Sandbox prerequisites on this machine (warnings: they do not depend on the PR)."""
    out = []
    try:
        prof, _, _ = vr.load_profile("uptime-kuma")
        vr.image_digest(prof["image"])
        out.append({"id": "sandbox_image", "ok": True, "blocking": False, "title": "Sandbox image available", "detail": prof["image"]})
    except Exception as e:  # noqa: BLE001
        out.append({"id": "sandbox_image", "ok": False, "blocking": True, "title": "Sandbox image available",
                    "detail": str(e)[:160], "fix": "pull the image named in the profile (docker pull)"})
    r = subprocess.run(["docker", "ps", "-q", "--filter", f"name=^{vr.REGISTRY_CONTAINER}$"], capture_output=True, text=True, timeout=30)
    ok = r.returncode == 0 and bool(r.stdout.strip())
    out.append({"id": "registry", "ok": ok, "blocking": True, "title": "Local package registry running",
                "detail": "verdaccio container" + ("" if ok else " is not running"), **({} if ok else {"fix": "start the verdaccio container"})})
    return out


def check(out: Path, repo_name: str | None = None, profile: str | None = None, environment=_environment) -> dict:
    out = Path(out)
    checks: list[dict] = []

    def add(cid, ok, title, detail, fix=None, blocking=True):
        checks.append({"id": cid, "ok": bool(ok), "blocking": blocking, "title": title, "detail": detail, **({"fix": fix} if fix and not ok else {})})

    f = out / "fix-plan.json"
    if not f.exists():
        add("fix_plan", False, "A fix plan exists", "no fix plan has been computed for this run", "Fix & approve → Propose fixes")
        return {"ready": False, "checks": checks}
    plan = json.loads(f.read_text())
    patch = Path((plan.get("patch") or {}).get("patch_path") or "")
    actionable = [c for c in plan.get("candidates", []) if c.get("type") != "escalate"]
    complete = bool((plan.get("patch") or {}).get("complete", True))
    add("fix_plan", actionable and complete and patch.exists(), "The fix plan is complete",
        f"{len(actionable)} change(s) in one patch" + ("" if complete else "; some changes could not be applied"),
        "Recompute the fix")

    repo, base, head = plan.get("repo"), plan.get("base_sha"), plan.get("head_sha")
    if repo and base and head:
        mb = _git(repo, "merge-base", base, head).stdout.strip()
        ahead = _git(repo, "rev-list", "--count", f"{mb}..{base}").stdout.strip() if mb else ""
        same = bool(mb) and mb == base
        add("comparison_base", same, "Compared with the PR's merge base",
            "base is the merge base" if same else f"the run compared with a base-branch tip {ahead or '?'} commit(s) past the merge base: "
            "unrelated base-branch changes look introduced and the fix undoes them",
            "rescan this PR (Guardian now compares with the merge base)")

    name = profile or vr.profile_for(repo_name or "")
    prof, prof_sha, _ = vr.load_profile(name)
    listed = bool(repo_name) and repo_name in (prof.get("repos") or [])
    generic = name == "generic-npm"
    add("profile", listed or generic or not repo_name, "A validation profile covers this repository",
        f"profile '{name}'" + (" (automatic for npm repositories: install, build, own tests if any, AI tests for upgraded packages)"
                               if generic else "" if listed or not repo_name else f" does not list {repo_name}"),
        "add the repository to a profile's repos: list (or write a profile for it)", blocking=not generic)

    allow = [a for st in prof.get("stages", []) if st.get("id") == "hooks" for a in st.get("allow", [])]
    if allow and repo and base and head and patch.exists():
        base_lock, cand_lock = _lock_at(repo, base), _candidate_lock(repo, head, patch)
        for a in allow:
            key = f"node_modules/{a['name']}"
            want = f"{a['name']}@{a['version']}"
            in_base = ((base_lock or {}).get("packages") or {}).get(key) or {}
            in_cand = ((cand_lock or {}).get("packages") or {}).get(key) or {}
            ok_base = in_base.get("version") == a["version"] and in_base.get("integrity") == a["integrity"]
            ok_cand = in_cand.get("version") == a["version"] and in_cand.get("integrity") == a["integrity"]
            add(f"required:{a['name']}", ok_base and ok_cand, f"{want} kept (the profile builds it)",
                "present in baseline and fixed version" if ok_base and ok_cand else
                ("the fix removes or changes it" if ok_base else "the baseline does not contain it") +
                (" (patched lockfile could not be read)" if cand_lock is None else ""),
                "recompute the fix from a correct base; a fix must not remove packages the app needs")

    rec = ap.latest_approval(out)
    try:
        from guardian.validation.validate import policy_sha256
        if rec is None:
            raise ap.ApprovalInvalid("not approved yet")
        ap.check(rec, plan, policy_sha256=policy_sha256(), profile_sha256=prof_sha)
        add("approval", True, "Approved by a person", f"{rec.get('approver')}", blocking=False)
    except ap.ApprovalInvalid as e:
        add("approval", False, "Approved by a person", str(e)[:160], "Fix & approve → review the patch and approve", blocking=False)

    checks += environment()
    ready = all(c["ok"] for c in checks if c["blocking"])
    return {"ready": ready, "approved": next(c["ok"] for c in checks if c["id"] == "approval"), "checks": checks}
