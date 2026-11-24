"""M5 validation: profile binding, lifecycle-hook exceptions, docker isolation flags and the verified-fix gate."""
import json

import pytest

from guardian.validation import runner as vr


def test_profile_loads_and_has_a_stable_hash():
    prof, sha, folder = vr.load_profile("uptime-kuma")
    assert prof["name"] == "uptime-kuma" and len(sha) == 64 and (folder / "integration.cjs").exists()
    assert vr.load_profile("uptime-kuma")[1] == sha


def test_unknown_profile_is_rejected():
    with pytest.raises(FileNotFoundError):
        vr.load_profile("../../etc")


ALLOW = [{"name": "@louislam/sqlite3", "version": "15.1.6", "integrity": "sha512-GOOD", "cmd": "npm rebuild @louislam/sqlite3"}]


def _lock(integrity="sha512-GOOD", version="15.1.6"):
    return {"packages": {"node_modules/@louislam/sqlite3": {"version": version, "integrity": integrity, "hasInstallScript": True}}}


def test_hook_runs_only_when_name_version_and_integrity_match():
    plan = vr.hook_plan(ALLOW, _lock())
    assert plan == [{"name": "@louislam/sqlite3", "run": True, "cmd": "npm rebuild @louislam/sqlite3", "reason": "matches profile exception"}]


@pytest.mark.parametrize("lock,why", [(_lock(integrity="sha512-SWAPPED"), "integrity"), (_lock(version="15.1.7"), "version"),
                                      ({"packages": {}}, "not in the lockfile")])
def test_hook_is_refused_on_any_mismatch(lock, why):
    p = vr.hook_plan(ALLOW, lock)[0]
    assert p["run"] is False and why in p["reason"]


def test_docker_run_is_isolated():
    prof, _, _ = vr.load_profile("uptime-kuma")
    args = vr.docker_run_args(prof, "guardian-val-x", "/tmp/tree", "node@sha256:abc")
    joined = " ".join(args)
    for flag in ("--cap-drop ALL", "--security-opt no-new-privileges", "--network guardian-validate", "--pids-limit",
                 "--memory 4g", "--user 1000:1000"):
        assert flag in joined
    assert "docker.sock" not in joined and "-v /tmp/tree:/work" in joined
    import os
    host_home = os.path.expanduser("~")
    assert not any(host_home in a or "TOKEN" in a or "KEY" in a or "SECRET" in a for a in args)
    assert "HOME=/tmp/home" in args  # throwaway home inside the container


# ---------- verified gate ----------

def _stage(i, status, security=False, required=True):
    return {"id": i, "status": status, "required": required, "security": security}


GOOD_STAGES = [_stage("install", "passed"), _stage("hooks", "passed"), _stage("build", "passed"),
               _stage("target_test", "passed", security=True), _stage("unit", "passed"), _stage("integration", "passed")]


def _gate(**kw):
    args = dict(approval_ok=True, approval_error=None, baseline=GOOD_STAGES, candidate=GOOD_STAGES, targets_resolved=["F1"],
                targets_remaining=[], new_high=[], rescans_complete=True, sbom_diff={"added": [], "removed": ["axois@1.0.0"], "changed": []},
                same_snapshot=True, evidence_ok=True)
    args.update(kw)
    return vr.gate(**args)


def test_everything_green_is_verified():
    g = _gate()
    assert g["verified"] is True and g["validation"] == "passed" and g["target"] == "corrected"


@pytest.mark.parametrize("kw,validation,reason", [
    (dict(approval_ok=False, approval_error="patch changed"), "failed", "approval"),
    (dict(candidate=GOOD_STAGES[:-1] + [_stage("integration", "failed")]), "failed", "integration"),
    (dict(candidate=GOOD_STAGES[:-1] + [_stage("integration", "not_run")]), "incomplete", "integration"),
    (dict(rescans_complete=False), "incomplete", "rescan"),
    (dict(same_snapshot=False), "incomplete", "snapshot"),
    (dict(evidence_ok=False), "failed", "evidence"),
])
def test_any_gap_is_not_verified(kw, validation, reason):
    g = _gate(**kw)
    assert g["verified"] is False and g["validation"] == validation and any(reason in r for r in g["reasons"])


def test_security_test_must_pass_even_if_it_failed_on_baseline():
    base = GOOD_STAGES[:3] + [_stage("target_test", "failed", security=True)] + GOOD_STAGES[4:]
    cand = list(base)
    g = _gate(baseline=base, candidate=cand)
    assert g["verified"] is False and any("security" in r for r in g["reasons"])


def test_ordinary_test_failing_on_baseline_too_is_pre_existing_not_blamed():
    base = GOOD_STAGES[:4] + [_stage("unit", "failed")] + GOOD_STAGES[5:]
    g = _gate(baseline=base, candidate=base)
    assert g["verified"] is True and g["pre_existing_failures"] == ["unit"]


def test_target_fixed_but_new_high_or_remaining_target_is_reported_separately():
    g = _gate(new_high=["x@1: GHSA-new"])
    assert g["verified"] is False and g["target"] == "corrected"
    g = _gate(targets_resolved=[], targets_remaining=["F1"])
    assert g["verified"] is False and g["target"] == "not corrected"


def test_gate_result_is_serialisable():
    json.dumps(_gate())


# ---------- orchestration: nothing runs without a matching approval ----------

def _plan_dir(tmp_path):
    out = tmp_path / "run"
    out.mkdir()
    patch = out / "fix.patch"
    patch.write_text("")
    import hashlib
    plan = {"repo": str(tmp_path), "base_sha": "a" * 40, "head_sha": "b" * 40, "candidates": [],
            "patch": {"patch_sha256": hashlib.sha256(b"").hexdigest(), "patch_path": str(patch)}}
    (out / "fix-plan.json").write_text(json.dumps(plan))
    return out, plan


def test_validate_without_approval_runs_nothing(tmp_path, monkeypatch):
    from guardian.validation import validate as vv
    out, _ = _plan_dir(tmp_path)
    monkeypatch.setattr(vr, "run_profile", lambda *a, **k: pytest.fail("must not execute anything"))
    res = vv.validate(out)
    assert res["gate"]["verified"] is False and res["gate"]["validation"] == "failed"
    assert any("approval" in r for r in res["gate"]["reasons"])
    assert json.loads((out / "validation.json").read_text())["gate"]["verified"] is False


def test_validate_with_stale_approval_runs_nothing(tmp_path, monkeypatch):
    from guardian import approval as ap
    from guardian.validation import validate as vv
    out, plan = _plan_dir(tmp_path)
    _, prof_sha, _ = vr.load_profile("uptime-kuma")
    ap.decide(out, {**plan, "patch": {"patch_sha256": "0" * 64}}, "approve", approver="k", reason="ok", ttl_seconds=3600,
              policy_sha256=vv.policy_sha256(), profile_sha256=prof_sha)
    monkeypatch.setattr(vr, "run_profile", lambda *a, **k: pytest.fail("must not execute anything"))
    res = vv.validate(out)
    assert res["gate"]["verified"] is False and any("patch changed" in r for r in res["gate"]["reasons"])


def test_patch_is_really_applied_even_when_the_tree_sits_inside_another_git_repo(tmp_path):
    """Found live: validation trees live under guardian-out/, inside Guardian's own git repo. `git apply` run there
    silently skipped every path and returned 0, so the 'candidate' was the unpatched PR. Applying must ignore any
    surrounding repo and prove the patch is in the tree."""
    import hashlib
    import subprocess
    from guardian.validation.runner import prepare_tree
    src = tmp_path / "src"
    src.mkdir()
    subprocess.run(["git", "init", "-q", str(src)], check=True)
    (src / ".npmrc").write_text("legacy-peer-deps=true\nregistry=http://127.0.0.1:4873/\n")
    g = ["git", "-C", str(src), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(g + ["add", "-A"], check=True)
    subprocess.run(g + ["commit", "-qm", "head"], check=True)
    sha = subprocess.run(g + ["rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    patch = tmp_path / "fix.patch"
    patch.write_text("diff --git a/.npmrc b/.npmrc\n--- a/.npmrc\n+++ b/.npmrc\n@@ -1,2 +1 @@\n legacy-peer-deps=true\n"
                     "-registry=http://127.0.0.1:4873/\n")
    outer = tmp_path / "outer"  # an unrelated repo around the destination, like guardian-out/ inside guardian/
    outer.mkdir()
    subprocess.run(["git", "init", "-q", str(outer)], check=True)
    dest = prepare_tree(src, sha, outer / "out" / "validation" / "candidate", patch, hashlib.sha256(patch.read_bytes()).hexdigest())
    assert (dest / ".npmrc").read_text() == "legacy-peer-deps=true\n"


def test_a_patch_that_does_not_change_the_tree_is_refused(tmp_path, monkeypatch):
    import hashlib
    import subprocess

    import pytest

    from guardian.validation import runner
    src = tmp_path / "src"
    src.mkdir()
    subprocess.run(["git", "init", "-q", str(src)], check=True)
    (src / "a.txt").write_text("one\n")
    g = ["git", "-C", str(src), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(g + ["add", "-A"], check=True)
    subprocess.run(g + ["commit", "-qm", "head"], check=True)
    sha = subprocess.run(g + ["rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    patch = tmp_path / "p.patch"
    patch.write_text("diff --git a/a.txt b/a.txt\n--- a/a.txt\n+++ b/a.txt\n@@ -1 +1 @@\n-one\n+two\n")
    real = subprocess.run

    def silent_apply(cmd, *a, **k):  # simulate git apply that "succeeds" without touching anything
        if cmd[:2] == ["git", "apply"] and "--check" not in cmd:
            return subprocess.CompletedProcess(cmd, 0, b"", b"")
        return real(cmd, *a, **k)
    monkeypatch.setattr(runner.subprocess, "run", silent_apply)
    with pytest.raises(RuntimeError, match="not applied"):
        runner.prepare_tree(src, sha, tmp_path / "dest", patch, hashlib.sha256(patch.read_bytes()).hexdigest())


def test_rescan_compares_base_with_the_fixed_version_not_the_pr_head(tmp_path, monkeypatch):
    """Found live: comparing PR head → fixed version flagged the revert of .npmrc itself as a 'sensitive file change'
    still present. The question is the original one: after the fix, what does this PR still introduce versus base?"""
    import hashlib
    import json
    import subprocess

    from guardian.validation import validate as v
    src = tmp_path / "src"
    src.mkdir()
    g = ["git", "-C", str(src), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(["git", "init", "-q", str(src)], check=True)
    (src / ".npmrc").write_text("legacy-peer-deps=true\n")
    subprocess.run(g + ["add", "-A"], check=True)
    subprocess.run(g + ["commit", "-qm", "base"], check=True)
    base = subprocess.run(g + ["rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    (src / ".npmrc").write_text("legacy-peer-deps=true\nregistry=http://127.0.0.1:4873/\n")
    subprocess.run(g + ["commit", "-qam", "head"], check=True)
    head = subprocess.run(g + ["rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    patch = tmp_path / "fix.patch"
    patch.write_text("diff --git a/.npmrc b/.npmrc\n--- a/.npmrc\n+++ b/.npmrc\n@@ -1,2 +1 @@\n legacy-peer-deps=true\n"
                     "-registry=http://127.0.0.1:4873/\n")
    seen = {}

    def fake_check_any(work, b, h, out, app):
        show = lambda ref: subprocess.run(["git", "-C", str(work), "show", f"{ref}:.npmrc"], capture_output=True, text=True).stdout  # noqa: E731
        seen.update(before=show(b), after=show(h))
        (out).mkdir(parents=True, exist_ok=True)
        (out / "latest.json").write_text(json.dumps({"path": "x"}))
        return {"headline": {"complete": True}}
    monkeypatch.setattr("guardian.universal.check_any", fake_check_any)
    v._source_rescan(src, base, head, patch, tmp_path / "work", "app")
    assert seen["before"] == "legacy-peer-deps=true\n"   # base, not the PR head
    assert seen["after"] == "legacy-peer-deps=true\n"    # PR head + approved patch
