"""Approval gate, sandbox apply and validation. The lockfile step and the rescan are injected: no network, no scanners."""
import json
import subprocess
from pathlib import Path

import pytest

from guardian.remediation import apply as applier
from guardian.remediation import validate as validator
from guardian.remediation.models import Approval
from guardian.remediation.store import now
from guardian.scoring.score import score_report
from tests.remediation.conftest import have_git

pytestmark = pytest.mark.skipif(not have_git(), reason="git is required")


def fid(ctx, needle):
    return next(f["id"] for f in ctx.scores["findings"] if needle in f["id"])


def plan_for(rem, ctx, needle, ctype, target):
    f = fid(ctx, needle)
    return rem.propose(f, ctype, target, f"Rule-based pick for {ctx.finding(f)['component']}.", [rem.evidence_finding(f), rem.evidence_candidates(f)], "rule_based")


def fake_lock(tree):  # stands in for `npm install --package-lock-only --ignore-scripts`: a lock derived from the patched package.json
    import re
    m = json.loads((Path(tree) / "package.json").read_text())
    pk = {"": {"name": m["name"]}}
    for sec in ("dependencies", "devDependencies"):
        for n, spec in (m.get(sec) or {}).items():
            pk[f"node_modules/{n}"] = {"version": re.sub(r"^[\^~]", "", spec)}
    for n, v in (m.get("overrides") or {}).items():
        pk[f"node_modules/{n}"] = {"version": v}
    (Path(tree) / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "regenerated": True, "packages": pk}) + "\n")
    return {"status": "ok", "detail": "fake lockfile step"}


def rescan_without(ctx, drop_ids, extra=None, after_inventory=None):
    """A fake rescan: the scored report minus the dropped findings (they are `fixed` after the change)."""
    def rescan(repo, base_ref, head_ref, out):
        rep = json.loads(json.dumps(ctx.report))
        for v in rep["vulnerabilities"]:
            if f"{v['name']}@{v['version']}#{v['id']}" in drop_ids:
                v["label"] = "fixed"
        rep["suspicious_changes"] = [s for s in rep["suspicious_changes"] if f"{s['type']}:{s['component'].replace('pkg:npm/', '')}" not in drop_ids]
        rep["vulnerabilities"] += extra or []
        if after_inventory is not None:
            rep["inventory"] = after_inventory
        return score_report(rep), rep
    return rescan


# ------------------------------------------------------------------------------------------------ the gate (C7 extended)
def test_apply_refused_without_approval(rem, ctx, store):
    p = plan_for(rem, ctx, "GHSA-1", "upgrade_to_fixed", "1.2.4")
    with pytest.raises(applier.ApplyRefused, match="no human approval"):
        applier.apply_plan(store, p.id, ctx.src, ctx.base_src, fake_lock)
    assert not (store.root / "work").exists()  # nothing was written
    assert any(e["event"] == "apply_refused" for e in store.audit())


def test_apply_refused_after_reject_or_escalate(rem, ctx, store):
    p = plan_for(rem, ctx, "GHSA-1", "upgrade_to_fixed", "1.2.4")
    rem.decide(p.id, "reject", "Dana", "too risky")
    with pytest.raises(applier.ApplyRefused):
        applier.apply_plan(store, p.id, ctx.src, ctx.base_src, fake_lock)


def test_apply_refused_when_plan_changes_after_approval(rem, ctx, store):
    p = plan_for(rem, ctx, "GHSA-1", "upgrade_to_fixed", "1.2.4")
    rem.decide(p.id, "approve", "Dana")
    stored = store.get_plan(p.id)
    stored.patch.files["package.json"] = stored.patch.files["package.json"].replace("^1.2.4", "^9.9.9")
    store.save_plan(stored)
    with pytest.raises(applier.ApplyRefused, match="changed after it was sealed"):
        applier.apply_plan(store, p.id, ctx.src, ctx.base_src, fake_lock)


def test_approval_for_another_plans_hash_is_not_accepted(rem, ctx, store):
    a = plan_for(rem, ctx, "GHSA-1", "upgrade_to_fixed", "1.2.4")
    b = plan_for(rem, ctx, "MAL-1", "remove_package", None)
    store.append_approval(Approval(plan_id=b.id, plan_sha256=a.plan_sha256, decision="approve", reviewer="Eve", at=now()))  # forged hash
    store.set_status(b.id, "approved")
    with pytest.raises(applier.ApplyRefused, match="different version of the plan"):
        applier.apply_plan(store, b.id, ctx.src, ctx.base_src, fake_lock)


def test_recommend_only_plans_cannot_be_applied(rem, ctx, store):
    f = fid(ctx, "typosquat")
    p = rem.propose(f, "revert_change", None, "Revert the introduced axois@1.0.0 change.", [rem.evidence_finding(f), rem.evidence_candidates(f)], "rule_based")
    ctx.base_src = None
    p2 = rem.store.get_plan(p.id)
    assert p2.patch.supported  # (with a base tree the revert is expressible)
    esc = rem.propose(fid(ctx, "GHSA-3"), "override_transitive", "3.0.1", "Override bar@3.0.0 to bar@3.0.1.",
                      [rem.evidence_finding(fid(ctx, "GHSA-3")), rem.evidence_candidates(fid(ctx, "GHSA-3"))], "rule_based")
    rem.decide(esc.id, "approve", "Dana")
    if not esc.patch.supported:
        with pytest.raises(applier.ApplyRefused, match="recommend-only"):
            applier.apply_plan(store, esc.id, ctx.src, None, fake_lock)


# ------------------------------------------------------------------------------------------------ apply (sandbox copy)
def test_apply_writes_only_a_local_branch_copy_and_never_touches_the_project(rem, ctx, store, trees):
    head, base = trees
    before = (head / "package.json").read_text()
    p = plan_for(rem, ctx, "GHSA-1", "upgrade_to_fixed", "1.2.4")
    rem.decide(p.id, "approve", "Dana", "ok")
    out = applier.apply_plan(store, p.id, ctx.src, ctx.base_src, fake_lock)
    assert (head / "package.json").read_text() == before  # the analysed project is untouched
    repo = Path(out["repo"])
    assert out["branch"] == f"guardian/fix/{p.id}" and out["pushed"] is False
    assert '"foo": "^1.2.4"' in (repo / "package.json").read_text() and "regenerated" in (repo / "package-lock.json").read_text()
    assert any(s["name"] == "lockfile post-condition" and s["status"] == "ok" for s in out["steps"])
    remotes = subprocess.run(["git", "-C", str(repo), "remote"], capture_output=True, text=True).stdout.strip()
    assert remotes == ""  # no remote: it cannot be pushed
    assert "package.json" in out["diff_stat"] and store.get_plan(p.id).status == "applied"
    log = subprocess.run(["git", "-C", str(repo), "log", "--format=%s", "--all"], capture_output=True, text=True).stdout
    assert "base (original base ref export)" in log and "head (original PR head export)" in log and f"guardian fix {p.id}" in log


def test_apply_ignores_node_modules_and_does_not_follow_symlink_escape(rem, ctx, store, trees):
    head, _ = trees
    (head / "node_modules" / "x").mkdir(parents=True)
    (head / "node_modules" / "x" / "evil.js").write_text("boom")
    p = plan_for(rem, ctx, "GHSA-1", "upgrade_to_fixed", "1.2.4")
    rem.decide(p.id, "approve", "Dana")
    out = applier.apply_plan(store, p.id, ctx.src, ctx.base_src, fake_lock)
    assert not (Path(out["repo"]) / "node_modules").exists()
    with pytest.raises(applier.ApplyRefused, match="outside the working copy"):
        applier._inside(Path(out["repo"]), "../../escape.txt")


def test_lockfile_failure_marks_the_plan_failed_and_is_reported(rem, ctx, store):
    p = plan_for(rem, ctx, "GHSA-1", "upgrade_to_fixed", "1.2.4")
    rem.decide(p.id, "approve", "Dana")
    res = validator.validate(store, p.id, ctx, lockfile=lambda t: {"status": "failed", "detail": "E404 no such version"}, rescan=rescan_without(ctx, set()))
    assert res.outcome == "failed" and res.steps[-1]["status"] == "failed" and "E404" in res.steps[-1]["detail"]
    assert store.get_plan(p.id).status == "failed"


# ------------------------------------------------------------------------------------------------ validation (C11)
def test_tier1_is_remediated_but_never_verified(rem, ctx, store):
    p = plan_for(rem, ctx, "GHSA-1", "upgrade_to_fixed", "1.2.4")
    rem.decide(p.id, "approve", "Dana")
    res = validator.validate(store, p.id, ctx, lockfile=fake_lock, rescan=rescan_without(ctx, set(p.finding_ids)))
    assert res.outcome == "remediated_tests_not_run" and "Not verified" in res.wording
    assert res.delta["failed_conditions"] == ["build_tests_pass"] and res.delta["conditions"]["target_resolved"]
    assert store.get_plan(p.id).status == "applied"  # NOT verified
    assert res.comparison_frame.startswith("original base ref")
    assert store.validation(p.id).outcome == "remediated_tests_not_run"


def test_tier2_pass_is_the_only_way_to_verified(rem, ctx, store):
    p = plan_for(rem, ctx, "GHSA-1", "upgrade_to_fixed", "1.2.4")
    rem.decide(p.id, "approve", "Dana")
    res = validator.validate(store, p.id, ctx, tier="tier2", lockfile=fake_lock, rescan=rescan_without(ctx, set(p.finding_ids)),
                             tier2=lambda repo: {"status": "pass", "steps": [{"name": "build", "status": "ok", "detail": ""}]})
    assert res.outcome == "verified" and res.delta["verified"] and store.get_plan(p.id).status == "verified"


def test_failing_tests_or_missing_docker_never_verify(rem, ctx, store):
    p = plan_for(rem, ctx, "GHSA-1", "upgrade_to_fixed", "1.2.4")
    rem.decide(p.id, "approve", "Dana")
    res = validator.validate(store, p.id, ctx, tier="tier2", lockfile=fake_lock, rescan=rescan_without(ctx, set(p.finding_ids)),
                             tier2=lambda repo: {"status": "fail", "steps": [{"name": "npm test", "status": "failed", "detail": "1 failing"}]})
    assert res.outcome == "not_verified" and "build_tests_pass" in res.wording and store.get_plan(p.id).status == "not_verified"


def test_new_high_finding_after_the_fix_blocks_verification(rem, ctx, store):
    p = plan_for(rem, ctx, "GHSA-1", "upgrade_to_fixed", "1.2.4")
    rem.decide(p.id, "approve", "Dana")
    new_vuln = {"name": "foo", "version": "1.2.4", "id": "GHSA-NEW", "ids": ["GHSA-NEW"], "key": "foo@1.2.4#GHSA-NEW", "severity": "critical", "fixed": [],
                "malicious": False, "direct": True, "runtime": True, "label": "introduced", "summary": "new", "sources": ["osv"], "component_key": "node_modules/foo"}
    res = validator.validate(store, p.id, ctx, tier="tier2", lockfile=fake_lock, rescan=rescan_without(ctx, set(p.finding_ids), extra=[new_vuln]),
                             tier2=lambda repo: {"status": "pass", "steps": []})
    assert res.outcome == "not_verified" and "no_new_high" in res.delta["failed_conditions"] and not res.delta["verified"]
    assert res.delta["new_findings"]


def test_unresolved_target_blocks_verification(rem, ctx, store):
    p = plan_for(rem, ctx, "GHSA-1", "upgrade_to_fixed", "1.2.4")
    rem.decide(p.id, "approve", "Dana")
    res = validator.validate(store, p.id, ctx, tier="tier2", lockfile=fake_lock, rescan=rescan_without(ctx, set()),  # the fix did not clear it
                             tier2=lambda repo: {"status": "pass", "steps": []})
    assert res.outcome == "not_verified" and "target_resolved" in res.delta["failed_conditions"]


def test_rescan_failure_is_reported_not_hidden(rem, ctx, store):
    p = plan_for(rem, ctx, "GHSA-1", "upgrade_to_fixed", "1.2.4")
    rem.decide(p.id, "approve", "Dana")

    def boom(*a):
        raise RuntimeError("osv-scanner not installed")
    res = validator.validate(store, p.id, ctx, lockfile=fake_lock, rescan=boom)
    assert res.outcome == "failed" and "osv-scanner" in res.steps[-1]["detail"] and store.get_plan(p.id).status == "failed"


def test_package_diff_reports_new_packages_as_new_risk(ctx):
    d = validator.package_diff(ctx.inventory, ctx.inventory + [{"name": "newpkg", "version": "1.0.0"}])
    assert d["added"] == ["newpkg@1.0.0"] and d["removed"] == []


def test_tier2_is_not_run_without_a_digest_pinned_image(tmp_path, monkeypatch):
    monkeypatch.delenv("GUARDIAN_TIER2_IMAGE", raising=False)
    monkeypatch.setattr(validator, "tier2_config", lambda: {"image": "node:22", "commands": [], "timeout": 5})
    monkeypatch.setattr(validator.shutil, "which", lambda x: "/usr/bin/docker")
    r = validator.docker_tier2(tmp_path)
    assert r["status"] == "not_run" and "digest-pinned" in r["steps"][0]["detail"]


def test_safe_env_drops_secrets(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-secret")
    monkeypatch.setenv("GOOGLE_API_KEY", "g-secret")
    env = applier.safe_env()
    assert "ANTHROPIC_API_KEY" not in env and "GOOGLE_API_KEY" not in env


# ------------------------------------------------------------------------------------------------ lockfile post-condition
def test_a_lockfile_step_that_exits_ok_without_changing_anything_is_a_failure(rem, ctx, store):
    """npm once exited 0 without regenerating the lock: that must fail the plan, never count as remediated."""
    p = plan_for(rem, ctx, "GHSA-1", "upgrade_to_fixed", "1.2.4")
    rem.decide(p.id, "approve", "Dana")
    res = validator.validate(store, p.id, ctx, lockfile=lambda t: {"status": "ok", "detail": "(did nothing)"}, rescan=rescan_without(ctx, set(p.finding_ids)))
    assert res.outcome == "failed" and "does not contain the planned change" in res.steps[-1]["detail"]
    assert store.get_plan(p.id).status == "failed" and any(e["event"] == "apply_failed" for e in store.audit())


def test_verify_lock_rules(tmp_path):
    from guardian.remediation.models import FixPlan
    def plan(t, target):
        return FixPlan(id="FP-001", run_id="r", finding_ids=["x"], candidate_id="c", type=t, target=target, package="foo", produced_by="rule_based")
    def lock(pk):
        (tmp_path / "package-lock.json").write_text(json.dumps({"packages": pk}))
    lock({"node_modules/foo": {"version": "1.2.6"}})
    assert applier.verify_lock(plan("upgrade_to_fixed", "1.2.4"), tmp_path)[0]            # newer than the target is fine
    assert not applier.verify_lock(plan("upgrade_to_fixed", "1.3.0"), tmp_path)[0]
    lock({"node_modules/bar/node_modules/foo": {"version": "1.2.0"}, "node_modules/foo": {"version": "1.2.4"}})
    assert not applier.verify_lock(plan("override_transitive", "1.2.4"), tmp_path)[0]       # a nested copy was not overridden
    assert not applier.verify_lock(plan("remove_package", None), tmp_path)[0]               # still needed by another package
    lock({})
    assert applier.verify_lock(plan("remove_package", None), tmp_path)[0]
    (tmp_path / "package-lock.json").write_text("not json")
    assert not applier.verify_lock(plan("upgrade_to_fixed", "1.2.4"), tmp_path)[0]
    assert applier.verify_lock(plan("revert_change", None), tmp_path)[0]                    # no post-condition for other types
