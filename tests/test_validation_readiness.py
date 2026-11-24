"""Validation readiness predicts, before approval and without running code, the failures seen in real runs."""
import hashlib
import json
import subprocess

from guardian.validation import readiness as rd
from guardian.validation import runner as vr

prof, _, _ = vr.load_profile("uptime-kuma")
HOOK = next(a for st in prof["stages"] if st["id"] == "hooks" for a in st["allow"])
REPO = prof["repos"][0]
OK_ENV = lambda: []  # noqa: E731


def _lock(extra=None, sqlite=True):
    pk = {"": {"name": "app"}, "node_modules/lodash": {"version": "4.17.20", "integrity": "sha512-L"}}
    if sqlite:
        pk[f"node_modules/{HOOK['name']}"] = {"version": HOOK["version"], "integrity": HOOK["integrity"]}
    pk.update(extra or {})
    return {"name": "app", "lockfileVersion": 3, "packages": pk}


def _setup(tmp_path, fixed_lock, base_moves=False):
    repo = tmp_path / "repo"
    repo.mkdir()
    g = lambda *a: subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *a],  # noqa: E731
                                  check=True, capture_output=True, text=True).stdout.strip()
    g("init", "-q", "-b", "main")
    (repo / "package.json").write_text('{"name": "app"}\n')
    (repo / "package-lock.json").write_text(json.dumps(_lock(), indent=2) + "\n")
    g("add", "-A"); g("commit", "-qm", "base")
    base = g("rev-parse", "HEAD")
    g("checkout", "-qb", "pr")
    (repo / "package-lock.json").write_text(json.dumps(_lock({"node_modules/lodash": {"version": "4.17.19", "integrity": "sha512-O"}}), indent=2) + "\n")
    g("add", "-A"); g("commit", "-qm", "pr")
    head = g("rev-parse", "HEAD")
    (repo / "package-lock.json").write_text(json.dumps(fixed_lock, indent=2) + "\n")
    patch = g("diff") + "\n"
    g("checkout", "-q", "--", ".")
    if base_moves:
        g("checkout", "-q", "main")
        (repo / "later.txt").write_text("x")
        g("add", "-A"); g("commit", "-qm", "base branch moves on")
        base = g("rev-parse", "HEAD")
    out = tmp_path / "run"
    out.mkdir()
    pp = out / "fix.patch"
    pp.write_text(patch)
    plan = {"repo": str(repo), "base_sha": base, "head_sha": head,
            "candidates": [{"id": "c1", "type": "upgrade_to_fixed", "package": "lodash", "finding_ids": ["f1"]}],
            "patch": {"patch_path": str(pp), "patch_sha256": hashlib.sha256(pp.read_bytes()).hexdigest(), "complete": True}}
    (out / "fix-plan.json").write_text(json.dumps(plan))
    return out


def _by(res):
    return {c["id"]: c for c in res["checks"]}


def test_a_sound_plan_is_ready_and_only_waits_for_approval(tmp_path):
    out = _setup(tmp_path, _lock())
    res = rd.check(out, REPO, environment=OK_ENV)
    assert res["ready"] is True and res["approved"] is False
    assert _by(res)[f"required:{HOOK['name']}"]["ok"] is True


def test_a_fix_that_removes_a_package_the_app_needs_is_not_ready(tmp_path):
    out = _setup(tmp_path, _lock(sqlite=False))
    res = rd.check(out, REPO, environment=OK_ENV)
    c = _by(res)[f"required:{HOOK['name']}"]
    assert res["ready"] is False and c["ok"] is False and "removes" in c["detail"] and c["fix"]


def test_a_run_compared_with_a_moved_base_tip_is_not_ready(tmp_path):
    out = _setup(tmp_path, _lock(), base_moves=True)
    res = rd.check(out, REPO, environment=OK_ENV)
    c = _by(res)["comparison_base"]
    assert res["ready"] is False and c["ok"] is False and "merge base" in c["detail"] and "rescan" in c["fix"]


def test_no_plan_is_not_ready(tmp_path):
    res = rd.check(tmp_path, REPO, environment=OK_ENV)
    assert res["ready"] is False and res["checks"][0]["id"] == "fix_plan"


def test_a_repository_no_profile_names_gets_the_automatic_npm_profile(tmp_path):
    out = _setup(tmp_path, _lock())
    res = rd.check(out, "someone/else", environment=OK_ENV)
    assert _by(res)["profile"]["ok"] is True and "automatic" in _by(res)["profile"]["detail"] and res["ready"] is True


def test_an_explicitly_named_profile_that_does_not_list_the_repo_is_flagged(tmp_path):
    out = _setup(tmp_path, _lock())
    res = rd.check(out, "someone/else", profile="uptime-kuma", environment=OK_ENV)
    assert _by(res)["profile"]["ok"] is False and res["ready"] is False


def test_environment_problems_block(tmp_path):
    out = _setup(tmp_path, _lock())
    env = lambda: [{"id": "registry", "ok": False, "blocking": True, "title": "Local package registry running", "detail": "down"}]  # noqa: E731
    assert rd.check(out, REPO, environment=env)["ready"] is False


def test_exposure_says_which_changed_packages_tests_reach(tmp_path):
    from guardian.validation.validate import test_exposure
    (tmp_path / "server").mkdir(); (tmp_path / "test").mkdir(); (tmp_path / "node_modules" / "lodash").mkdir(parents=True)
    (tmp_path / "server" / "a.js").write_text("const f = require('node-fetch');\nconst _ = require('lodash/fp');")
    (tmp_path / "test" / "a.test.js").write_text("import _ from 'lodash';")
    (tmp_path / "node_modules" / "lodash" / "x.js").write_text("require('minimist')")  # vendored code is not ours
    e = test_exposure(tmp_path, ["lodash", "node-fetch", "minimist"])
    assert e["lodash"]["test_files"] == 1 and e["lodash"]["verdict"] == "imported by tests"
    assert e["node-fetch"]["verdict"] == "used by the app, not imported by any test"
    assert e["minimist"]["app_files"] == 0 and "tests do not exercise it" in e["minimist"]["verdict"]
