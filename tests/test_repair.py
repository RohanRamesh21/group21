"""Repair loop: a failed validation is remembered and the next fix avoids what failed (needs re-approval)."""
import json

from guardian.remediation import repair as rp


def _plan(to="1.16.0", extra=()):
    c = [{"id": "c1", "type": "upgrade_to_fixed", "package": "follow-redirects", "from": "1.15.5", "to": to, "finding_ids": ["f"]}]
    c += [{"id": f"c{i+2}", "type": "upgrade_to_fixed", "package": p, "from": "1.0.0", "to": "1.0.1", "finding_ids": []} for i, p in enumerate(extra)]
    return {"repo": "/r", "base_sha": "b", "head_sha": "h", "candidates": c, "patch": {"patch_sha256": "p1"}}


def _val(started=1.0, new_high=(), stages=None, verified=False):
    return {"started": started, "gate": {"verified": verified, "reasons": ["x"], "new_high": list(new_high), "targets_remaining": []},
            "baseline": {"stages": [{"id": "build", "status": "passed", "required": True}]},
            "candidate": {"stages": stages or [{"id": "build", "status": "passed", "required": True}]}}


def _write(tmp, plan, val):
    (tmp / "fix-plan.json").write_text(json.dumps(plan))
    (tmp / "validation.json").write_text(json.dumps(val))


def test_a_version_with_its_own_advisories_is_remembered(tmp_path):
    _write(tmp_path, _plan(), _val(new_high=["follow-redirects@1.16.0: GHSA-8r9p-f939-6h3c"]))
    a = rp.remember(tmp_path)
    assert a["failed_versions"]["follow-redirects"]["versions"] == ["1.16.0"]
    assert rp.remember(tmp_path) is None  # the same validation is remembered once


def test_the_fixer_agent_blames_only_packages_in_the_plan(tmp_path):
    failing = [{"id": "build", "status": "failed", "required": True, "output": "TypeError in ws"}]
    _write(tmp_path, _plan(extra=["ws"]), _val(stages=failing))
    a = rp.remember(tmp_path, chat=lambda p, **k: ({"suspects": ["ws", "invented-pkg"], "why": "the error is in ws"}, {}))
    assert list(a["failed_versions"]) == ["ws"] and a["blame"].startswith("Fixer agent")


def test_without_a_usable_answer_every_upgrade_is_retried(tmp_path):
    failing = [{"id": "unit", "status": "failed", "required": True, "output": "boom"}]
    _write(tmp_path, _plan(extra=["ws"]), _val(stages=failing))
    a = rp.remember(tmp_path, chat=lambda p, **k: ({"suspects": ["nope"]}, {}))
    assert set(a["failed_versions"]) == {"follow-redirects", "ws"}


def test_repair_recomputes_without_the_failed_version_and_needs_approval(tmp_path):
    _write(tmp_path, _plan(), _val(new_high=["follow-redirects@1.16.0: GHSA-x"]))
    seen = {}

    def propose(repo, base, head, out, include, sources):
        seen["exclude"] = sources.exclude
        new = _plan(to="1.16.2")
        new["patch"]["patch_sha256"] = "p2"
        (out / "fix-plan.json").write_text(json.dumps(new))
        return new
    r = rp.repair(tmp_path, propose=propose)
    assert seen["exclude"] == {"follow-redirects": ["1.16.0"]}
    assert r["status"] == "repaired" and r["needs_approval"] and r["changes"] == [{"package": "follow-redirects", "was": "1.16.0", "now": "1.16.2"}]
    assert rp.load(tmp_path)[-1]["repaired_to"] == "p2"


def test_a_verified_fix_needs_no_repair_and_the_loop_stops_after_the_limit(tmp_path):
    _write(tmp_path, _plan(), _val(verified=True))
    assert rp.repair(tmp_path)["status"] == "nothing_to_repair"
    mem = [{"attempt": i, "verified": False, "validation_started": i, "failed_versions": {"x": {"versions": ["1"]}}} for i in range(rp.MAX_ATTEMPTS + 1)]
    (tmp_path / rp.MEMORY).write_text(json.dumps(mem))
    _write(tmp_path, _plan(), _val(started=99.0, new_high=["follow-redirects@1.16.0: G"]))
    assert rp.repair(tmp_path)["status"] == "give_up"
