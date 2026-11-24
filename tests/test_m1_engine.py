"""M1: one engine. The universal pipeline must reproduce the npm pipeline's decisions on the attack pattern."""
import json
import subprocess

import pytest

from guardian import universal as u


@pytest.fixture
def offline(monkeypatch):
    monkeypatch.setattr(u, "run_syft", lambda src, out: ({}, None))
    monkeypatch.setattr(u, "osv_api", lambda inv: ([], None))
    monkeypatch.setattr(u, "grype_all", lambda sbom: ([], None))
    from guardian.scoring import intel
    monkeypatch.setattr(intel, "epss", lambda cves: ({}, None))
    monkeypatch.setattr(intel, "kev", lambda: ({}, None))


def _lock(pkgs: dict) -> str:
    packages = {"": {"name": "app", "dependencies": {n: v["version"] for n, v in pkgs.items()}}}
    for n, v in pkgs.items():
        packages[f"node_modules/{n}"] = v
    return json.dumps({"name": "app", "lockfileVersion": 3, "packages": packages})


def _repo(tmp_path, base: dict, head: dict):
    repo = tmp_path / "repo"
    repo.mkdir()
    git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    for files in (base, head):
        for name, text in files.items():
            (repo / name).write_text(text)
        subprocess.run(git + ["add", "-A"], check=True)
        subprocess.run(git + ["commit", "-qm", "c", "--allow-empty"], check=True)
    return repo


GOOD = {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", "integrity": "sha512-A"}


def test_package_from_unapproved_http_host_is_a_critical_hard_signal(tmp_path, offline):
    evil = {"version": "1.0.0", "resolved": "http://127.0.0.1:4873/evilpkg/-/evilpkg-1.0.0.tgz", "integrity": "sha512-B"}
    repo = _repo(tmp_path, {"package.json": '{"name":"app"}', "package-lock.json": _lock({"left-pad": GOOD})},
                 {"package-lock.json": _lock({"left-pad": GOOD, "evilpkg": evil})})
    rep = u.check_any(repo, "HEAD~1", "HEAD", tmp_path / "out", "app")
    hits = [s for s in rep["suspicious_changes"] if s["type"] == "untrusted_source"]
    assert hits and hits[0]["severity"] == "critical" and hits[0]["hard_signal"] and hits[0]["label"] == "introduced"
    assert rep["headline"]["verdict"] == "block"


def test_git_source_is_non_registry_source_not_a_hard_signal(tmp_path, offline):
    gitdep = {"version": "1.0.0", "resolved": "git+https://github.com/x/y.git#abc", "integrity": None}
    repo = _repo(tmp_path, {"package.json": '{"name":"app"}', "package-lock.json": _lock({"left-pad": GOOD})},
                 {"package-lock.json": _lock({"left-pad": GOOD, "y": gitdep})})
    rep = u.check_any(repo, "HEAD~1", "HEAD", tmp_path / "out", "app")
    hits = [s for s in rep["suspicious_changes"] if s["component"].startswith("y@") and s["detector"] == "D3"]
    assert hits and hits[0]["type"] == "non_registry_source" and not hits[0]["hard_signal"]


def test_untrusted_source_has_a_scoring_floor():
    from guardian.scoring.score import FLOORS
    assert FLOORS["untrusted_source"][0] == "critical"


def test_cli_check_runs_the_universal_engine(monkeypatch, tmp_path):
    import guardian.universal
    from guardian import cli
    seen = {}

    def fake(repo, base, head, out, app, log=None):
        seen.update(repo=repo, base=base, head=head, app=app)
        return {"headline": {"verdict": "allow", "complete": True}, "path": str(tmp_path / "r.json")}
    monkeypatch.setattr(guardian.universal, "check_any", fake)
    assert cli.main(["check", str(tmp_path / "myapp"), "--base", "a", "--head", "b"]) == 0
    assert seen == {"repo": tmp_path / "myapp", "base": "a", "head": "b", "app": "myapp"}


def test_engine_accepts_relative_repo_and_output_paths(tmp_path, offline, monkeypatch):
    repo = _repo(tmp_path, {"package.json": '{"name":"app"}', "package-lock.json": _lock({"left-pad": GOOD})},
                 {"README.md": "changed"})
    monkeypatch.chdir(tmp_path)
    rep = u.check_any(__import__("pathlib").Path("repo"), "HEAD~1", "HEAD", __import__("pathlib").Path("out/check"), "app")
    assert rep["headline"]["verdict"] == "allow" and (tmp_path / "out" / "check" / "latest.json").exists()
