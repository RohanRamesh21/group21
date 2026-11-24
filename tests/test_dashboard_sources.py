"""Dashboard intake: local-path sources, pipeline stages, project-neutral metadata and agent runs on any scan."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from guardian import config, projects, server

GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@localhost", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"]


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(GIT + list(args), cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


def _repo(path: Path) -> Path:
    path.mkdir(parents=True)
    _git(path, "init", "-q")
    (path / "app.js").write_text("console.log(1)\n")
    _git(path, "add", "-A")
    _git(path, "commit", "-q", "-m", "first")
    _git(path, "checkout", "-q", "-b", "feature")
    (path / "app.js").write_text("console.log(2)\n")
    _git(path, "commit", "-q", "-am", "second")
    _git(path, "checkout", "-q", "main")
    return path


@pytest.fixture
def intake(tmp_path, monkeypatch):
    """Project storage in tmp, the user's home as tmp, and the heavy pipeline replaced by a recorder."""
    monkeypatch.setattr(projects, "BASE", tmp_path / "out")
    monkeypatch.setenv("GUARDIAN_PATH_ROOTS", str(tmp_path / "home"))
    calls = []
    monkeypatch.setattr(projects, "_analyse", lambda pid, repo, base, head, label: calls.append((pid, repo, base, head, label)))
    (tmp_path / "home").mkdir()
    return tmp_path / "home", calls


def test_stages_follow_the_pipeline_and_never_go_back():
    assert projects.stage_of("Cloning read-only (shallow, no checkout)") == "fetch"
    assert projects.stage_of("Building the SBOM with Syft (CycloneDX + SPDX), all ecosystems") == "sbom"
    assert projects.stage_of("Scanning the previous state 5aa5dec4 to find what changed", "vulns") == "compare"
    # the base version is scanned with the same steps: the stage stays at "compare"
    assert projects.stage_of("Building the SBOM with Syft (CycloneDX + SPDX), all ecosystems", "compare") == "compare"
    assert projects.stage_of("Evaluating policy-as-code (Conftest/OPA, policies/*.rego)", "registry") == "policy"
    assert projects.stage_of("something new", "ci") == "ci"


def test_local_path_rules(intake, tmp_path, monkeypatch):
    home, _ = intake
    (home / "app").mkdir()
    assert projects.validate_local_path(str(home / "app")) == (home / "app").resolve()
    for bad, why in [("relative/app", "absolute"), (str(tmp_path), "inside"), (str(home / "missing"), "not a folder"), ("", "enter")]:
        with pytest.raises(ValueError, match=why):
            projects.validate_local_path(bad)
    # a whole home directory is never one project, even when it is an allowed root
    monkeypatch.setenv("GUARDIAN_PATH_ROOTS", str(Path.home()))
    with pytest.raises(ValueError, match="inside"):
        projects.validate_local_path(str(Path.home()))


def test_safe_copy_skips_links_and_dependency_folders(tmp_path, monkeypatch):
    src = tmp_path / "src"
    (src / "node_modules" / "x").mkdir(parents=True)
    (src / "node_modules" / "x" / "index.js").write_text("x")
    (src / "lib").mkdir()
    (src / "lib" / "a.py").write_text("a")
    (tmp_path / "secret").write_text("outside")
    os.symlink(tmp_path / "secret", src / "lib" / "link")
    os.symlink(tmp_path, src / "linked-dir")
    assert projects.safe_copy(src, tmp_path / "dst") == 1
    copied = sorted(p.relative_to(tmp_path / "dst").as_posix() for p in (tmp_path / "dst").rglob("*") if p.is_file())
    assert copied == ["lib/a.py"]
    monkeypatch.setattr(projects, "MAX_FILES", 0)
    with pytest.raises(ValueError, match="more than"):
        projects.safe_copy(src, tmp_path / "dst2")


def test_local_git_repo_is_cloned_with_its_branches_and_left_untouched(intake):
    home, calls = intake
    repo = _repo(home / "app")
    before = (_git(repo, "for-each-ref"), _git(repo, "status", "--porcelain"), _git(repo, "rev-parse", "HEAD"))
    pid = projects._new("path", "app", {"path": str(repo), "git": True})
    projects._run_path(pid, repo, True, "main", "feature")
    assert projects.JOBS[pid]["status"] != "error", projects.JOBS[pid]["message"]
    (_, clone, base, head, label), = calls
    assert (base, head, label) == ("main", "feature", "app")
    assert clone != repo and clone.is_relative_to(projects.BASE)
    assert _git(clone, "rev-parse", "feature") == _git(repo, "rev-parse", "feature")
    assert not list(clone.glob("*.js")), "nothing is checked out"
    assert (_git(repo, "for-each-ref"), _git(repo, "status", "--porcelain"), _git(repo, "rev-parse", "HEAD")) == before


def test_local_git_repo_defaults_to_the_latest_commit_and_rejects_unknown_refs(intake):
    home, calls = intake
    repo = _repo(home / "app")
    pid = projects._new("path", "app", {})
    projects._run_path(pid, repo, True, None, "feature")
    assert calls[-1][2:4] == ("feature~1", "feature")
    pid = projects._new("path", "app", {})
    projects._run_path(pid, repo, True, "v9.9.9", None)
    assert projects.JOBS[pid]["status"] == "error" and "v9.9.9" in projects.JOBS[pid]["message"]


def test_plain_folder_is_copied_and_scanned_once(intake):
    home, calls = intake
    (home / "site").mkdir()
    (home / "site" / "package.json").write_text("{}")
    pid = projects._new("path", "site", {})
    projects._run_path(pid, home / "site", False, "ignored", "ignored")
    (_, copy, base, head, _label), = calls
    assert (base, head) == (None, "HEAD") and (copy / "package.json").exists()
    assert [s["stage"] for s in projects.JOBS[pid]["steps"]] == ["fetch", "fetch"]


def test_working_tree_snapshot_captures_saved_edits_without_mutating_source(intake):
    home, calls = intake
    repo = _repo(home / "app")
    (repo / ".gitignore").write_text("ignored.txt\n")
    (repo / "ignored.txt").write_text("local data")
    (repo / "notes.txt").write_text("new file")
    (repo / "app.js").unlink()
    (repo / "link.txt").symlink_to(home / "outside.txt")
    before = _git(repo, "status", "--porcelain")
    pid = projects._new("path", "app", {})
    projects._run_path(pid, repo, True, None, None, working_tree=True)
    assert projects.JOBS[pid]["status"] != "error", projects.JOBS[pid]["message"]
    _, clone, base, head, _ = calls[0]
    assert base == "HEAD"
    assert _git(clone, "rev-parse", f"{head}^") == _git(repo, "rev-parse", "HEAD")
    assert set(_git(clone, "ls-tree", "--name-only", head).splitlines()) == {".gitignore", "notes.txt"}
    assert _git(repo, "status", "--porcelain") == before


def test_folder_snapshot_compares_against_saved_files(intake):
    home, calls = intake
    path = home / "site"
    path.mkdir()
    (path / "versions.txt").write_text("old\n")
    old = projects._new("path", "site", {"git": False})
    projects._run_path(old, path, False, None, None)
    _, old_repo, _, _, _ = calls[0]
    out = projects.BASE / old / "check"
    out.mkdir()
    report = out / "report.json"
    report.write_text(json.dumps({"repo": str(old_repo), "headline": {"head_commit_full": _git(old_repo, "rev-parse", "HEAD")}}))
    (out / "latest.json").write_text(json.dumps({"path": str(report)}))
    projects._job(old, status="done")
    (path / "versions.txt").write_text("new\n")
    new = projects._new("path", "site", {"git": False})
    projects._run_path(new, path, False, None, None, baseline=old)
    assert projects.JOBS[new]["status"] != "error", projects.JOBS[new]["message"]
    _, repo, base, head, _ = calls[1]
    assert _git(repo, "show", f"{base}:versions.txt") == "old"
    assert _git(repo, "show", f"{head}:versions.txt") == "new"
    assert _git(repo, "rev-parse", f"{head}^") == _git(repo, "rev-parse", base)


@pytest.fixture
def api(tmp_path, monkeypatch):
    directory = tmp_path / "check"
    directory.mkdir()
    monkeypatch.setattr(server, "_check_dir", lambda project: directory)
    monkeypatch.setenv("GUARDIAN_PATH_ROOTS", str(tmp_path))

    def publish(repo: str | None):
        report = {"headline": {"app": "fixture", "base": "a", "head": "b", "base_commit": "a" * 12, "head_commit": "b" * 12,
                               "base_commit_full": "a" * 40, "head_commit_full": "b" * 40, "verdict": "allow",
                               "inventory": {"packages": 0}}}
        if repo:
            report["repo"] = repo
        (directory / "report.json").write_text(json.dumps(report))
        (directory / "latest.json").write_text(json.dumps({"path": str(directory / "report.json")}))
    return TestClient(server.app), publish


def test_path_endpoint_reports_why_a_folder_is_refused(api):
    client, _ = api
    r = client.post("/api/projects/path", json={"path": "/definitely/not/here"})
    assert r.status_code == 400 and "absolute" not in r.json()["detail"]
    assert client.post("/api/projects/path", json={"path": "rel/x"}).status_code == 400


def test_meta_names_no_sample_app(api):
    client, _ = api
    body = client.get("/api/meta").json()
    assert set(body) >= {"provider", "live_available", "replay_available"}
    assert not {"repo", "base", "head", "components"} & set(body)


def test_live_run_needs_a_key_and_a_scan_with_a_repository(api, monkeypatch):
    client, publish = api
    monkeypatch.setattr(config, "provider", lambda: "replay")
    assert client.post("/api/runs", json={"mode": "live"}).status_code == 400
    monkeypatch.setattr(config, "provider", lambda: "claude")
    publish(None)
    r = client.post("/api/runs", json={"mode": "live"})
    assert r.status_code == 409 and "repository" in r.json()["detail"]


def test_live_run_investigates_the_chosen_scan(api, monkeypatch, tmp_path):
    client, publish = api
    repo = _repo(tmp_path / "repo")
    publish(str(repo))
    monkeypatch.setattr(config, "provider", lambda: "claude")
    seen = {}
    import guardian.agents.run as agent_run
    monkeypatch.setattr(agent_run, "run", lambda out, **kw: seen.update(kw))
    r = client.post("/api/runs", json={"mode": "live"})
    assert r.status_code == 200
    for _ in range(100):
        if seen:
            break
        import time
        time.sleep(0.02)
    assert seen["repo"] == repo and seen["base"] == "a" * 40 and seen["head"] == "b" * 40 and seen["world_kind"] == "real"
    state = server._state(server.RUNS[r.json()["run_id"]])
    assert state["target"]["app"] == "fixture" and "repo" not in state["target"]


def test_agents_examine_a_repository_without_a_lockfile(tmp_path):
    from guardian.agents.realworld import RealFacts
    from guardian.store.evidence import EvidenceStore
    repo = _repo(tmp_path / "repo")
    root = Path(__file__).resolve().parents[1]
    facts = RealFacts(repo, "main", "feature", EvidenceStore(tmp_path / "ev"), root / "guardian.yaml", tmp_path / "cache")
    assert facts.base_pkgs == {} and facts.head_pkgs == {} and len(facts.missing_lockfile) == 2
    assert facts.diff["files_changed"] == ["app.js"]
    assert any(c.startswith("commit:") for c in facts.coverage_required())
