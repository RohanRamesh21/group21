"""API for approval, validation and report. Approval needs a person and a reason; validation refuses without approval."""
import json

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    from guardian import server
    out = tmp_path / "check"
    out.mkdir()
    plan = {"repo": str(tmp_path), "base_sha": "a" * 40, "head_sha": "b" * 40, "candidates": [],
            "patch": {"patch_sha256": "c" * 64, "patch_path": str(out / "p.patch"), "files": []}}
    (out / "fix-plan.json").write_text(json.dumps(plan))
    monkeypatch.setattr(server, "_check_dir", lambda project: out)
    return TestClient(server.app), out


def test_approval_endpoint_binds_policy_and_profile_hashes(client):
    c, out = client
    r = c.post("/api/approval", json={"decision": "approve", "approver": "kiran", "reason": "reviewed the diff", "reviewed": True})
    assert r.status_code == 200
    rec = r.json()
    assert rec["patch_sha256"] == "c" * 64 and len(rec["policy_sha256"]) == 64 and len(rec["profile_sha256"]) == 64
    assert (out / "audit.jsonl").exists()


def test_approval_without_reason_is_rejected(client):
    c, _ = client
    assert c.post("/api/approval", json={"decision": "approve", "approver": "kiran", "reason": " "}).status_code == 400


def test_risk_acceptance_endpoint(client):
    c, out = client
    r = c.post("/api/risk-acceptance", json={"finding_id": "x#1", "owner": "kiran", "scope": "this PR", "reason": "no fix", "days": 7})
    assert r.status_code == 200 and r.json()["finding_id"] == "x#1"


def test_validate_endpoint_refuses_without_approval(client, monkeypatch):
    from guardian.validation import runner
    c, out = client
    monkeypatch.setattr(runner, "run_profile", lambda *a, **k: pytest.fail("must not run"))
    r = c.post("/api/validate", json={})
    assert r.status_code == 200
    import time
    for _ in range(50):
        if (out / "validation.json").exists():
            break
        time.sleep(0.05)
    v = c.get("/api/validation").json()
    assert v["executed"] is False and v["gate"]["verified"] is False
