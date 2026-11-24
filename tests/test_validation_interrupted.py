"""A validation cut off by a server restart must say so (never an endless "Validating…"), and its orphaned sandbox
containers must be removed when the server starts again."""
import json

from fastapi.testclient import TestClient

from guardian import server
from guardian.validation import runner


def _client(monkeypatch, out):
    monkeypatch.setattr(server, "_check_dir", lambda project: out)
    server._VALIDATING.pop(str(out), None)
    return TestClient(server.app)


def test_no_validation_yet_is_404(monkeypatch, tmp_path):
    r = _client(monkeypatch, tmp_path).get("/api/validation?project=x")
    assert r.status_code == 404


def test_work_left_without_result_after_restart_is_interrupted(monkeypatch, tmp_path):
    (tmp_path / "validation" / "baseline").mkdir(parents=True)  # started, then the server process was replaced
    r = _client(monkeypatch, tmp_path).get("/api/validation?project=x")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "interrupted"
    assert "run it again" in body["message"].lower()


def test_running_in_this_process_is_not_interrupted(monkeypatch, tmp_path):
    (tmp_path / "validation" / "baseline").mkdir(parents=True)
    c = _client(monkeypatch, tmp_path)
    server._VALIDATING[str(tmp_path)] = "running"
    try:
        assert c.get("/api/validation?project=x").json()["status"] == "running"
    finally:
        server._VALIDATING.pop(str(tmp_path), None)


def test_finished_result_is_returned(monkeypatch, tmp_path):
    (tmp_path / "validation").mkdir()
    (tmp_path / "validation.json").write_text(json.dumps({"executed": True, "gate": {"verified": True}}))
    body = _client(monkeypatch, tmp_path).get("/api/validation?project=x").json()
    assert body["gate"]["verified"] is True and body["status"] == "done"


def test_remove_orphans_removes_only_guardian_sandbox_containers(monkeypatch):
    calls = []

    class R:
        def __init__(self, out=""):
            self.returncode, self.stdout, self.stderr = 0, out, ""

    def fake_run(cmd, timeout=None, **kw):
        calls.append(cmd)
        return R("abc123\ndef456\n") if cmd[:3] == ["docker", "ps", "-aq"] else R()

    monkeypatch.setattr(runner, "_run", fake_run)
    assert runner.remove_orphans() == 2
    assert ["docker", "ps", "-aq", "--filter", "name=^guardian-val-"] == calls[0]
    assert calls[1] == ["docker", "rm", "-f", "abc123", "def456"]


def test_remove_orphans_without_docker_is_harmless(monkeypatch):
    def boom(cmd, timeout=None, **kw):
        raise FileNotFoundError("docker")
    monkeypatch.setattr(runner, "_run", boom)
    assert runner.remove_orphans() == 0
