"""M4 API: fix plans are created from a run and read back; nothing is applied."""
import json

from fastapi.testclient import TestClient


def test_fix_plan_endpoint_round_trip(monkeypatch, tmp_path):
    from guardian import server
    import guardian.remediation.plan as plan_mod
    out = tmp_path / "check"
    out.mkdir()
    rep = tmp_path / "r.json"
    rep.write_text(json.dumps({"headline": {"repo_path": "/r", "base_sha": "a" * 40, "head_sha": "b" * 40}}))
    (out / "latest.json").write_text(json.dumps({"path": str(rep)}))
    monkeypatch.setattr(server, "_check_dir", lambda project: out)

    def fake(repo, base, head, o, include=()):
        plan = {"candidates": [{"id": "FIX-1", "type": "revert_change"}], "patch": {"patch_sha256": "c" * 64, "patch_path": str(o / "p.patch")}}
        (o / "p.patch").write_text("diff --git a/.npmrc b/.npmrc\n")
        (o / "fix-plan.json").write_text(json.dumps(plan))
        return plan
    monkeypatch.setattr(plan_mod, "propose", fake)
    c = TestClient(server.app)
    r = c.post("/api/fix-plan", json={"project": None, "include": []})
    assert r.status_code == 200 and r.json()["patch"]["patch_sha256"] == "c" * 64
    g = c.get("/api/fix-plan").json()
    assert g["candidates"][0]["id"] == "FIX-1" and g["patch_text"].startswith("diff --git")


def test_fix_plan_get_404_before_any_plan(monkeypatch, tmp_path):
    from guardian import server
    monkeypatch.setattr(server, "_check_dir", lambda project: tmp_path)
    assert TestClient(server.app).get("/api/fix-plan").status_code == 404
