"""A PR that silently re-points an EXISTING package (same name and version) to another download host with another
integrity hash is fixed by restoring that lockfile entry from the base commit: deterministic, no AI, no new version.
Before this rule the fix escalated it, the tampered entry stayed, `npm ci` failed with EINTEGRITY and validation
could never pass."""
import json
import subprocess

from guardian.remediation import candidates as cand
from guardian.remediation import patch as pt

GOOD = {"version": "4.22.3", "resolved": "https://registry.npmjs.org/express/-/express-4.22.3.tgz", "integrity": "sha512-GOOD"}
BAD = {"version": "4.22.3", "resolved": "http://127.0.0.1:4873/express/-/express-4.22.3.tgz", "integrity": "sha512-EVIL"}


def _f(t, comp="express@4.22.3"):
    return {"id": f"{t}:{comp}", "kind": "supply_chain", "type": t, "label": "introduced", "level": "critical",
            "component": comp, "evidence": {"file": "package-lock.json", "hard_signal": True}}


def _report(added=()):
    return {"inventory": [{"name": "express", "version": "4.22.3", "direct": True}], "package_changes": {"added": list(added)}}


def test_tampered_existing_package_is_restored_from_base():
    c = cand._package_candidate("express", "4.22.3", [_f("untrusted_source"), _f("lockfile_tamper")], _report(), None)
    assert c["type"] == "restore_lock_entry"
    assert c["package"] == "express" and c["version"] == "4.22.3"
    assert c["resolves_target"] is True


def test_newly_added_tampered_package_is_still_removed():
    c = cand._package_candidate("express", "4.22.3", [_f("untrusted_source")], _report(added=["express@4.22.3"]), None)
    assert c["type"] == "remove_package"


def test_existing_package_with_other_hard_signals_still_needs_a_person():
    c = cand._package_candidate("express", "4.22.3", [_f("lockfile_tamper"), _f("typosquat")], _report(), None)
    assert c["type"] == "escalate"


def _repo(tmp_path, head_entry):
    repo = tmp_path / "repo"
    repo.mkdir()
    git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "package.json").write_text(json.dumps({"name": "app", "dependencies": {"express": "^4.22.3"}}, indent=2) + "\n")

    def commit(entry, msg):
        lock = {"name": "app", "lockfileVersion": 3, "packages": {"": {"name": "app"}, "node_modules/express": entry}}
        (repo / "package-lock.json").write_text(json.dumps(lock, indent=2) + "\n")
        subprocess.run(git + ["add", "-A"], check=True)
        subprocess.run(git + ["commit", "-qm", msg, "--no-verify"], check=True)
        return subprocess.run(git + ["rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()

    return repo, commit(GOOD, "base"), commit(head_entry, "head")


def test_patch_restores_resolved_and_integrity_from_base(tmp_path):
    repo, base, head = _repo(tmp_path, BAD)
    c = {"id": "c1", "type": "restore_lock_entry", "package": "express", "version": "4.22.3"}
    res = pt.build_patch(repo, base, head, [c], tmp_path / "out")
    assert res["complete"] is True and res["results"][0]["status"] == "applied"
    lock = json.loads((tmp_path / "out" / "fix-work" / "package-lock.json").read_text())
    assert lock["packages"]["node_modules/express"] == GOOD
    assert res["files"] == ["package-lock.json"]


def test_restore_refuses_when_the_base_has_another_version(tmp_path):
    repo, base, head = _repo(tmp_path, {**BAD, "version": "4.23.0"})
    c = {"id": "c1", "type": "restore_lock_entry", "package": "express", "version": "4.23.0"}
    res = pt.build_patch(repo, base, head, [c], tmp_path / "out")
    assert res["results"][0]["status"] == "failed" and "base" in res["results"][0]["detail"]
    assert res["complete"] is False
