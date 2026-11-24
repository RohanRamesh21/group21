"""M4: deterministic fix generation (no AI). Targets are computed from advisory ranges and registry versions."""
import pytest

from guardian.remediation.versions import affected, parse, smallest_safe

ADV = {"id": "GHSA-66mm", "affected": [{"package": {"ecosystem": "npm", "name": "jsonata"},
       "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.8.8"}, {"introduced": "2.0.0"}, {"fixed": "2.2.1"}]}]}]}


def test_parse_orders_prereleases_before_releases():
    assert parse("2.2.1") > parse("2.2.0") > parse("2.2.0-beta.1") > parse("1.10.0") > parse("1.9.9")


@pytest.mark.parametrize("ver,hit", [("2.2.0", True), ("2.2.1", False), ("1.8.7", True), ("1.8.8", False), ("1.9.0", False),
                                     ("2.0.0", True), ("3.0.0", False)])
def test_affected_uses_introduced_fixed_intervals(ver, hit):
    assert affected(ver, "jsonata", [ADV]) is hit


def test_affected_honours_explicit_versions_and_last_affected():
    adv = {"affected": [{"package": {"ecosystem": "npm", "name": "x"}, "versions": ["1.0.0"],
                         "ranges": [{"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"last_affected": "2.1.0"}]}]}]}
    assert affected("1.0.0", "x", [adv]) and affected("2.1.0", "x", [adv]) and not affected("2.1.1", "x", [adv])
    assert not affected("1.0.0", "other-package", [adv])


def test_smallest_safe_prefers_same_major_and_skips_prereleases_and_deprecated():
    versions = {"2.2.0": {}, "2.2.1-rc.1": {}, "2.2.1": {"deprecated": "broken"}, "2.2.2": {}, "3.0.0": {}}
    assert smallest_safe("jsonata", "2.2.0", versions, [ADV]) == "2.2.2"


def test_smallest_safe_returns_none_when_nothing_is_safe():
    assert smallest_safe("jsonata", "2.2.0", {"2.2.0": {}}, [ADV]) is None


# ---------- candidate generation ----------

def _vf(name, ver, adv, label="pre_existing", direct=True, sev="critical"):
    return {"id": f"{name}@{ver}#{adv}", "kind": "vulnerability", "title": f"{name}@{ver}: {adv}", "component": f"{name}@{ver}",
            "label": label, "level": sev, "severity": sev, "version": ver, "evidence": {"advisory": adv}, "_direct": direct}


def _sf(comp, typ, label="introduced", hard=True, level="critical", file=None):
    return {"id": f"{typ}:{comp}", "kind": "supply_chain", "type": typ, "title": f"{comp}: {typ}", "component": comp,
            "label": label, "level": level, "severity": level, "evidence": {"file": file, "hard_signal": hard}}


REPORT = {"inventory": [{"name": "jsonata", "version": "2.2.0", "ecosystem": "npm", "direct": True},
                        {"name": "axois", "version": "1.0.0", "ecosystem": "npm", "direct": True},
                        {"name": "qs", "version": "6.0.0", "ecosystem": "npm", "direct": False}],
          "package_changes": {"added": ["axois@1.0.0"], "removed": [], "updated": []}}


def _src():
    from guardian.remediation.candidates import Sources
    regs = {"jsonata": {"2.2.0": {}, "2.2.1": {}, "2.2.2": {}, "3.0.0": {}}, "qs": {"6.0.0": {}, "6.0.4": {}}}
    advs = {"GHSA-66mm": ADV, "GHSA-qs": {"affected": [{"package": {"ecosystem": "npm", "name": "qs"},
                                                       "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "6.0.4"}]}]}]}}
    return Sources(versions=lambda n: (regs.get(n, {}), {"url": f"registry/{n}", "sha256": "x"}),
                   advisory=lambda i: (advs.get(i), {"url": f"osv/{i}", "sha256": "y"}))


def test_new_malicious_package_gets_one_remove_candidate_covering_all_its_findings():
    from guardian.remediation.candidates import generate
    fs = [_sf("axois@1.0.0", "typosquat"), _sf("axois@1.0.0", "untrusted_source"),
          _vf("axois", "1.0.0", "MAL-2025-15245", label="introduced")]
    cands = generate(fs, REPORT, _src())
    assert len(cands) == 1
    c = cands[0]
    assert c["type"] == "remove_package" and c["package"] == "axois" and sorted(c["finding_ids"]) == sorted(f["id"] for f in fs)
    assert c["expected_risk_reduction"]["critical"] == 3 and c["rollback"]


def test_config_redirect_gets_revert_change():
    from guardian.remediation.candidates import generate
    c = generate([_sf(".npmrc", "source_change", file=".npmrc")], REPORT, _src())[0]
    assert c["type"] == "revert_change" and c["file"] == ".npmrc"


def test_vulnerable_direct_dependency_upgrades_to_smallest_safe_same_major():
    from guardian.remediation.candidates import generate
    c = generate([_vf("jsonata", "2.2.0", "GHSA-66mm")], REPORT, _src())[0]
    assert (c["type"], c["from"], c["to"], c["semver_jump"]) == ("upgrade_to_fixed", "2.2.0", "2.2.1", "patch")
    assert c["sources"] and all("sha256" in s for s in c["sources"])


def test_transitive_dependency_uses_override():
    from guardian.remediation.candidates import generate
    c = generate([_vf("qs", "6.0.0", "GHSA-qs", direct=False)], REPORT, _src())[0]
    assert c["type"] == "override_transitive" and c["to"] == "6.0.4"


def test_no_safe_version_escalates_instead_of_guessing():
    from guardian.remediation.candidates import Sources, generate
    src = Sources(versions=lambda n: ({"2.2.0": {}}, {"url": "r", "sha256": "x"}), advisory=lambda i: (ADV, {"url": "o", "sha256": "y"}))
    c = generate([_vf("jsonata", "2.2.0", "GHSA-66mm")], REPORT, src)[0]
    assert c["type"] == "escalate" and "no published version" in c["rationale"]


def test_unknown_advisory_record_escalates():
    from guardian.remediation.candidates import Sources, generate
    src = Sources(versions=lambda n: ({"2.2.1": {}}, {"url": "r", "sha256": "x"}), advisory=lambda i: (None, None))
    assert generate([_vf("jsonata", "2.2.0", "GHSA-unknown")], REPORT, src)[0]["type"] == "escalate"


def test_ci_finding_without_resolvable_pin_escalates_honestly():
    from guardian.remediation.candidates import generate
    f = {"id": "D10:wf", "kind": "ci_image", "title": "wf: action_not_pinned", "component": "actions/checkout@v4", "label": "introduced",
         "level": "medium", "severity": "medium", "evidence": {"file": ".github/workflows/a.yml", "line": 3}}
    c = generate([f], REPORT, _src())[0]
    assert c["type"] in ("pin_action_sha", "escalate")


def test_order_prefers_resolving_then_smaller_jump_then_fewer_changes():
    from guardian.remediation.candidates import order
    a = {"id": "a", "resolves_target": True, "semver_jump": "major", "lock_changes": 1, "rollback_ease": 1}
    b = {"id": "b", "resolves_target": True, "semver_jump": "patch", "lock_changes": 5, "rollback_ease": 1}
    c = {"id": "c", "resolves_target": False, "semver_jump": "patch", "lock_changes": 1, "rollback_ease": 1}
    d = {"id": "d", "resolves_target": True, "semver_jump": "patch", "lock_changes": 2, "rollback_ease": 1}
    assert [x["id"] for x in order([a, b, c, d])] == ["d", "b", "a", "c"]


# ---------- combined patch ----------

def _repo(tmp_path, base_files, head_files):
    import subprocess
    repo = tmp_path / "repo"
    repo.mkdir()
    git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    for files in (base_files, head_files):
        for name, text in files.items():
            if text is None:
                (repo / name).unlink()
            else:
                (repo / name).write_text(text)
        subprocess.run(git + ["add", "-A"], check=True)
        subprocess.run(git + ["commit", "-qm", "c", "--allow-empty"], check=True)
    return repo


def test_patch_reverts_config_and_is_bound_to_a_hash(tmp_path):
    from guardian.remediation.patch import build_patch
    repo = _repo(tmp_path, {"README.md": "x", ".npmrc": "save-exact=true\n"},
                 {".npmrc": "save-exact=true\nregistry=http://127.0.0.1:4873/\n"})
    cand = {"id": "FIX-1", "type": "revert_change", "file": ".npmrc"}
    res = build_patch(repo, "HEAD~1", "HEAD", [cand], tmp_path / "out")
    patch = open(res["patch_path"], "rb").read()
    import hashlib
    assert res["patch_sha256"] == hashlib.sha256(patch).hexdigest()
    assert res["files"] == [".npmrc"] and b"-registry=http://127.0.0.1:4873/" in patch
    assert res["complete"] and res["results"][0]["status"] == "applied"
    # the user's repository is untouched
    assert "127.0.0.1" in (repo / ".npmrc").read_text()


def test_patch_removes_a_file_added_by_the_change(tmp_path):
    from guardian.remediation.patch import build_patch
    repo = _repo(tmp_path, {"README.md": "x"}, {".npmrc": "registry=http://evil/\n"})
    res = build_patch(repo, "HEAD~1", "HEAD", [{"id": "F", "type": "revert_change", "file": ".npmrc"}], tmp_path / "out")
    assert res["files"] == [".npmrc"] and "removed" in res["results"][0]["detail"]


def test_escalations_are_not_applied(tmp_path):
    from guardian.remediation.patch import build_patch
    repo = _repo(tmp_path, {"README.md": "x"}, {"README.md": "y"})
    res = build_patch(repo, "HEAD~1", "HEAD", [{"id": "E", "type": "escalate"}], tmp_path / "out")
    assert res["results"] == [] and res["files"] == []


def test_package_json_edit_preserves_original_indentation(tmp_path):
    from guardian.remediation.patch import write_json_like
    p = tmp_path / "package.json"
    p.write_text('{\n    "name": "a",\n    "dependencies": {\n        "x": "1.0.0"\n    }\n}\n')
    write_json_like(p, {"name": "a", "dependencies": {"x": "1.0.1"}})
    assert p.read_text() == '{\n    "name": "a",\n    "dependencies": {\n        "x": "1.0.1"\n    }\n}\n'


def test_lock_entry_changes_counts_added_removed_and_modified_entries():
    import json

    from guardian.remediation.patch import lock_entry_changes
    old = json.dumps({"packages": {"": {}, "node_modules/a": {"version": "1"}, "node_modules/b": {"version": "1"}}})
    new = json.dumps({"packages": {"": {}, "node_modules/a": {"version": "2"}, "node_modules/c": {"version": "1"}}})
    assert lock_entry_changes(old, new) == {"added": ["node_modules/c"], "removed": ["node_modules/b"], "changed": ["node_modules/a"]}


# ---------- fix plan for a finished run ----------

def test_propose_builds_a_plan_bound_to_full_commits(tmp_path, monkeypatch):
    import json
    import subprocess

    from guardian import universal as u
    from guardian.remediation.candidates import Sources
    from guardian.remediation.plan import propose
    from guardian.scoring import intel
    monkeypatch.setattr(u, "run_syft", lambda src, out: ({}, None))
    monkeypatch.setattr(u, "osv_api", lambda inv: ([], None))
    monkeypatch.setattr(u, "grype_all", lambda sbom: ([], None))
    monkeypatch.setattr(intel, "epss", lambda c: ({}, None))
    monkeypatch.setattr(intel, "kev", lambda: ({}, None))
    repo = _repo(tmp_path, {"README.md": "x", "package.json": '{"name":"app"}'},
                 {".npmrc": "registry=http://127.0.0.1:4873/\n"})
    out = tmp_path / "out"
    u.check_any(repo, "HEAD~1", "HEAD", out, "app")
    plan = propose(repo, "HEAD~1", "HEAD", out, sources=Sources(versions=lambda n: ({}, None), advisory=lambda i: (None, None)))
    heads = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD~1", "HEAD"], capture_output=True, text=True).stdout.split()
    assert (plan["base_sha"], plan["head_sha"]) == tuple(heads)
    assert any(c["type"] == "revert_change" and c["file"] == ".npmrc" for c in plan["candidates"])
    assert plan["patch"]["patch_sha256"] and plan["patch"]["files"] == [".npmrc"]
    assert json.loads((out / "fix-plan.json").read_text())["patch"]["patch_sha256"] == plan["patch"]["patch_sha256"]


def test_propose_refuses_when_the_run_is_for_other_commits(tmp_path, monkeypatch):
    from guardian import universal as u
    from guardian.remediation.plan import StaleRun, propose
    from guardian.scoring import intel
    monkeypatch.setattr(u, "run_syft", lambda src, out: ({}, None))
    monkeypatch.setattr(u, "osv_api", lambda inv: ([], None))
    monkeypatch.setattr(u, "grype_all", lambda sbom: ([], None))
    monkeypatch.setattr(intel, "epss", lambda c: ({}, None))
    monkeypatch.setattr(intel, "kev", lambda: ({}, None))
    repo = _repo(tmp_path, {"README.md": "x"}, {"README.md": "y"})
    out = tmp_path / "out"
    u.check_any(repo, "HEAD~1", "HEAD", out, "app")
    (repo / "README.md").write_text("z")
    import subprocess
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "newer"], check=True)
    with pytest.raises(StaleRun):
        propose(repo, "HEAD~1", "HEAD", out)


def test_engine_report_records_where_it_came_from(tmp_path, monkeypatch):
    from guardian import universal as u
    from guardian.scoring import intel
    monkeypatch.setattr(u, "run_syft", lambda src, out: ({}, None))
    monkeypatch.setattr(u, "osv_api", lambda inv: ([], None))
    monkeypatch.setattr(u, "grype_all", lambda sbom: ([], None))
    monkeypatch.setattr(intel, "epss", lambda c: ({}, None))
    monkeypatch.setattr(intel, "kev", lambda: ({}, None))
    repo = _repo(tmp_path, {"README.md": "x"}, {"README.md": "y"})
    h = u.check_any(repo, "HEAD~1", "HEAD", tmp_path / "out", "app")["headline"]
    assert h["repo_path"] == str(repo.resolve()) and len(h["base_sha"]) == 40 and len(h["head_sha"]) == 40


def test_cli_fix_uses_the_run_report(monkeypatch, tmp_path, capsys):
    import json

    import guardian.remediation.plan as plan_mod
    from guardian import cli
    out = tmp_path / "run"
    out.mkdir()
    rep = tmp_path / "r.json"
    rep.write_text(json.dumps({"headline": {"repo_path": "/x/repo", "base_sha": "a" * 40, "head_sha": "b" * 40}}))
    (out / "latest.json").write_text(json.dumps({"path": str(rep)}))
    seen = {}
    monkeypatch.setattr(plan_mod, "propose", lambda repo, base, head, o, include=(): seen.update(
        repo=str(repo), base=base, head=head, include=list(include)) or {"patch": {"patch_sha256": "f" * 64, "files": []}, "candidates": []})
    assert cli.main(["fix", "--out", str(out), "--include", "jsonata@2.2.0#GHSA-1"]) == 0
    assert seen == {"repo": "/x/repo", "base": "a" * 40, "head": "b" * 40, "include": ["jsonata@2.2.0#GHSA-1"]}


def test_newly_added_vulnerable_dependency_is_upgraded_not_removed():
    """Adding a dependency is a low signal, not an attack: the feature needs the package, so the fix is the safe version.
    (Found live on the ShipLog demo: jsonata@2.2.0 added by a PR was being removed, which would break the feature.)"""
    from guardian.remediation.candidates import generate
    report = {**REPORT, "package_changes": {"added": ["jsonata@2.2.0"], "removed": [], "updated": []}}
    fs = [_vf("jsonata", "2.2.0", "GHSA-66mm"), _sf("jsonata@2.2.0", "new_dependency", hard=False, level="low")]
    c = generate(fs, report, _src())[0]
    assert (c["type"], c["from"], c["to"]) == ("upgrade_to_fixed", "2.2.0", "2.2.1")
    assert sorted(c["finding_ids"]) == sorted(f["id"] for f in fs)
