"""Scans saved by an older Guardian version: a clear 409 instead of a 500, and a rescan of the same commits."""
import json
import subprocess

from fastapi.testclient import TestClient


def _old_project(tmp_path, monkeypatch):
    from guardian import projects
    monkeypatch.setattr(projects, "BASE", tmp_path)
    pid = "183352-abcdef"
    src = tmp_path / pid / "src"
    src.mkdir(parents=True)
    g = ["git", "-C", str(src), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(["git", "init", "-q", str(src)], check=True)
    (src / "a.txt").write_text("1\n")
    subprocess.run(g + ["add", "-A"], check=True)
    subprocess.run(g + ["commit", "-qm", "one"], check=True)
    (src / "a.txt").write_text("2\n")
    subprocess.run(g + ["commit", "-qam", "two"], check=True)
    rev = lambda r: subprocess.run(g + ["rev-parse", r], capture_output=True, text=True).stdout.strip()  # noqa: E731
    out = tmp_path / pid / "check"
    out.mkdir()
    report = out / "report-old.json"
    report.write_text(json.dumps({"headline": {"app": "demo", "base_commit": rev("HEAD~1")[:12], "head_commit": rev("HEAD")[:12],
                                               "mode": "universal", "verdict": "allow"}}))
    (out / "latest.json").write_text(json.dumps({"path": str(report)}))
    job = {"id": pid, "kind": "git", "label": "github.com/me/demo", "url": "https://github.com/me/demo", "status": "done",
           "created": 0, "steps": [], "base": None, "head": None}
    (tmp_path / pid / "job.json").write_text(json.dumps(job))
    projects.JOBS.pop(pid, None)
    return projects, pid, rev("HEAD~1"), rev("HEAD")


def test_old_format_scan_gives_a_clear_409_not_a_500(tmp_path, monkeypatch):
    from guardian import server
    projects, pid, _, _ = _old_project(tmp_path, monkeypatch)
    r = TestClient(server.app).get(f"/api/run?project={pid}")
    assert r.status_code == 409 and "older Guardian version" in r.json()["detail"]


def test_rescan_scans_the_same_commits_with_the_current_engine(tmp_path, monkeypatch):
    projects, pid, base, head = _old_project(tmp_path, monkeypatch)
    seen = {}
    monkeypatch.setattr(projects, "_analyse", lambda p, repo, b, h, label: seen.update(pid=p, repo=repo, base=b, head=h, label=label))
    projects.rescan(pid, background=False)
    assert seen["pid"] == pid and seen["repo"] == tmp_path / pid / "src"
    assert seen["base"].startswith(base[:12]) and seen["head"].startswith(head[:12]) and seen["label"] == "demo"
    assert any(d.name.startswith("check-outdated-") for d in (tmp_path / pid).iterdir())  # old evidence kept, not deleted


def test_rescan_endpoint_starts_a_rescan(tmp_path, monkeypatch):
    from guardian import server
    projects, pid, _, _ = _old_project(tmp_path, monkeypatch)
    called = []
    monkeypatch.setattr(projects, "rescan", lambda p, background=True: called.append(p))
    r = TestClient(server.app).post(f"/api/projects/{pid}/rescan")
    assert r.status_code == 200 and called == [pid]
