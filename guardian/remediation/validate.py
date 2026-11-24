"""Sandbox validation of an approved fix: apply -> rescan -> before/after -> SBOM/package diff -> (optional) build and tests.

Only `delta.before_after(...)["verified"]` can make a plan "verified" (constitution C11); this module never sets it by hand.

Tier 1  (always): apply in the throwaway copy, regenerate the lockfile with scripts disabled, rescan, compare.
                  No analysed code runs, so build/tests are "not_run" and the outcome is "remediated_tests_not_run".
Tier 2  (opt-in): install from the Tier 1 lockfile with scripts disabled (network allowed for that step only), then run the
                  build/test commands in a container with NO network and NO secrets. Needs a digest-pinned image
                  (CLAUDE.md 3.3); without one Tier 2 is reported as not run, never faked.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Callable

from guardian.remediation import apply as applier
from guardian.remediation.context import RemediationContext
from guardian.remediation.models import ValidationResult
from guardian.remediation.store import RemediationStore, now
from guardian.scoring.contextual import delta

CHECKS_NOT_RUN = ["peer_dependencies (only when the target manifest was readable)", "engines"]

Rescan = Callable[[Path, str, str, Path], tuple[dict, dict]]  # (repo, base_ref, head_ref, out) -> (scores_after, report_after)
Tier2 = Callable[[Path], dict]  # (repo) -> {"status": "pass"|"fail"|"not_run", "steps": [...]}


def default_rescan(repo: Path, base_ref: str, head_ref: str, out: Path) -> tuple[dict, dict]:
    """The real check pipeline on the fixed copy (needs osv-scanner, syft, grype installed: see docs/SETUP.md)."""
    from guardian.check import check
    rep = check(repo, base_ref, head_ref, out)
    ptr = json.loads((out / "latest.json").read_text())
    if not ptr.get("scores"):
        raise RuntimeError("the rescan produced no scores: " + str(ptr.get("scores_error")))
    return json.loads(Path(ptr["scores"]).read_text()), rep


def package_diff(before: list[dict], after: list[dict]) -> dict:
    """Package-set diff of the lockfile inventories (the 'before/after SBOM' comparison). New packages are new risk."""
    def idx(inv):
        out: dict[str, set] = {}
        for p in inv:
            out.setdefault(p["name"], set()).add(p["version"])
        return out
    b, a = idx(before), idx(after)
    return {"added": sorted(f"{n}@{v}" for n in a.keys() - b.keys() for v in a[n]),
            "removed": sorted(f"{n}@{v}" for n in b.keys() - a.keys() for v in b[n]),
            "updated": sorted(f"{n}: {','.join(sorted(b[n]))} -> {','.join(sorted(a[n]))}" for n in a.keys() & b.keys() if a[n] != b[n]),
            "basis": "package set of the lockfile inventory before and after (the Syft SBOM comparison runs inside the rescan when Syft is installed)"}


# ----------------------------------------------------------------------------- Tier 2 (Docker, opt-in)
def tier2_config() -> dict:
    cfg = {"image": os.environ.get("GUARDIAN_TIER2_IMAGE", ""), "commands": ["npm run build --if-present"], "timeout": 900}
    try:
        import yaml
        y = yaml.safe_load((Path(__file__).resolve().parents[2] / "guardian.yaml").read_text()) or {}
        t2 = ((y.get("remediation") or {}).get("tier2")) or {}
        cfg["image"] = cfg["image"] or t2.get("image", "")
        cfg["commands"] = t2.get("commands", cfg["commands"])
        cfg["timeout"] = t2.get("timeout", cfg["timeout"])
    except Exception:
        pass
    return cfg


def docker_tier2(repo: Path) -> dict:
    cfg = tier2_config()
    if not shutil.which("docker"):
        return {"status": "not_run", "steps": [{"name": "tier2", "status": "skipped", "detail": "docker is not installed"}]}
    if "@sha256:" not in cfg["image"]:
        return {"status": "not_run", "steps": [{"name": "tier2", "status": "skipped",
                "detail": "no digest-pinned image configured (set GUARDIAN_TIER2_IMAGE or remediation.tier2.image in guardian.yaml to an image@sha256:...)"}]}
    mount = f"{repo}:/work"
    hard = ["--rm", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "-v", mount, "-w", "/work"]
    steps: list[dict] = []

    def run(name: str, args: list[str]) -> bool:
        try:
            r = subprocess.run(["docker", "run", *args], capture_output=True, text=True, timeout=cfg["timeout"], env=applier.safe_env())
        except subprocess.TimeoutExpired:
            steps.append({"name": name, "status": "failed", "detail": f"timed out after {cfg['timeout']} s"})
            return False
        steps.append({"name": name, "status": "ok" if r.returncode == 0 else "failed", "detail": ((r.stdout + r.stderr).strip())[-800:]})
        return r.returncode == 0

    # install: network on, lifecycle scripts OFF (nothing from the packages runs)
    if not run("install (scripts disabled, network on)", [*hard, cfg["image"], "npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"]):
        return {"status": "fail", "steps": steps}
    for cmd in cfg["commands"]:  # build/tests: NO network, no secrets (docker passes no host env by default)
        if not run(f"{cmd} (no network)", ["--network", "none", *hard, cfg["image"], "sh", "-c", cmd]):
            return {"status": "fail", "steps": steps}
    return {"status": "pass", "steps": steps}


# ----------------------------------------------------------------------------- orchestration
def validate(store: RemediationStore, plan_id: str, ctx: RemediationContext, *, tier: str = "tier1",
             lockfile: Callable[[Path], dict] = applier.npm_lockfile, rescan: Rescan = default_rescan, tier2: Tier2 = docker_tier2) -> ValidationResult:
    plan = store.get_plan(plan_id)
    started = now()
    if ctx.src is None:
        raise applier.ApplyRefused("the project source tree is not on disk for this report: nothing to apply the fix to")
    res = ValidationResult(plan_id=plan_id, plan_sha256=plan.plan_sha256 if plan else "", tier=tier, started=started,  # type: ignore[arg-type]
                           checks_not_run=list(CHECKS_NOT_RUN))
    try:
        ap = applier.apply_plan(store, plan_id, ctx.src, ctx.base_src, lockfile)
    except applier.ApplyRefused:
        raise  # a refusal is not a validation result: nothing was changed
    except Exception as e:
        res.steps.append({"name": "apply", "status": "failed", "detail": f"{type(e).__name__}: {e}"[:400]})
        res.outcome, res.wording = "failed", "The fix could not be applied in the sandbox. Nothing was verified."
        store.save_validation(res)
        return res
    plan = store.get_plan(plan_id)
    assert plan is not None
    res.branch, res.work_dir, res.steps = ap["branch"], ap["repo"], list(ap["steps"])
    repo = Path(ap["repo"])
    base_ref = ap["base_ref"] or ap["head_ref"]
    res.comparison_frame = ("original base ref -> fixed branch (same frame as the PR check: risk index comparable)" if ap["base_ref"]
                            else "original PR head -> fixed branch (no base export on disk: remaining findings are relabelled pre-existing, so the risk index is NOT comparable; resolved targets and new findings are)")
    try:
        after, after_report = rescan(repo, base_ref, ap["fix_ref"], repo.parent / "rescan")
        res.steps.append({"name": "rescan", "status": "ok", "detail": f"re-ran the check pipeline on {ap['fix_ref']}"})
    except Exception as e:
        res.steps.append({"name": "rescan", "status": "failed", "detail": f"{type(e).__name__}: {e}"[:400]})
        res.outcome, res.wording = "failed", "The rescan failed, so the fix cannot be verified (the fix is applied on a local branch only)."
        store.set_status(plan_id, "failed")
        store.save_validation(res)
        return res
    res.sbom_diff = package_diff(ctx.inventory, after_report.get("inventory", []))

    build = "not_run"
    if tier == "tier2":
        t2 = tier2(repo)
        res.steps += t2["steps"]
        build = {"pass": "pass", "fail": "fail"}.get(t2["status"], "not_run")
    res.build_tests = build  # type: ignore[assignment]
    res.delta = delta.before_after(ctx.scores, after, plan.finding_ids, build if build != "not_run" else None)
    failed = res.delta["failed_conditions"]
    if res.delta["verified"]:
        res.outcome = "verified"
        res.wording = "Verified: targets remediated by rescan, nothing new at High or above, no hard signal recreated, build and tests passed."
        store.set_status(plan_id, "verified")  # the only place a plan becomes verified, and only from delta's verdict (C11)
    elif failed == ["build_tests_pass"] and build == "not_run":
        res.outcome = "remediated_tests_not_run"
        res.wording = "Remediated by rescan; build and tests not run. Not verified."
        store.set_status(plan_id, "applied")
    else:
        res.outcome = "not_verified"
        res.wording = "Not verified. Failed condition(s): " + ", ".join(failed)
        store.set_status(plan_id, "not_verified")
    store.save_validation(res)
    store.log("validated", plan=plan_id, tier=tier, outcome=res.outcome, failed=failed)
    return res
