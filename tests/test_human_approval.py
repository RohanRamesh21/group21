"""Human approval contract + risk acceptance as the dashboard uses them; AI quota errors are named, not generic."""
import json

import pytest
from fastapi.testclient import TestClient

from tests.test_m5_m6_api import client  # noqa: F401  (fixture: run folder with a fix plan)


def test_approval_view_shows_the_contract_before_anyone_signs(client):  # noqa: F811
    c, out = client
    v = c.get("/api/approval").json()
    k = v["contract"]
    assert k["patch_sha256"] == "c" * 64 and k["head_sha"] == "b" * 40 and len(k["policy_sha256"]) == 64 and k["profile"]
    assert v["approval"] is None and v["valid"] is False and "no decision" in v["reason"]


def test_approve_requires_confirming_the_patch_was_reviewed(client):  # noqa: F811
    c, out = client
    r = c.post("/api/approval", json={"decision": "approve", "approver": "kiran", "reason": "ok", "reviewed": False})
    assert r.status_code == 400 and "review the patch" in r.json()["detail"]
    ok = c.post("/api/approval", json={"decision": "approve", "approver": "kiran", "reason": "diff checked", "reviewed": True})
    assert ok.status_code == 200 and ok.json()["reviewed_patch"] is True
    v = c.get("/api/approval").json()
    assert v["valid"] is True and v["approval"]["approver"] == "kiran" and v["audit_ok"] is True


def test_reject_needs_no_review_flag_and_is_never_valid(client):  # noqa: F811
    c, _ = client
    assert c.post("/api/approval", json={"decision": "reject", "approver": "kiran", "reason": "too risky"}).status_code == 200
    v = c.get("/api/approval").json()
    assert v["valid"] is False and "rejected" in v["reason"]


def test_approval_becomes_invalid_when_the_patch_changes(client):  # noqa: F811
    c, out = client
    c.post("/api/approval", json={"decision": "approve", "approver": "kiran", "reason": "ok", "reviewed": True})
    plan = json.loads((out / "fix-plan.json").read_text())
    plan["patch"]["patch_sha256"] = "d" * 64
    (out / "fix-plan.json").write_text(json.dumps(plan))
    v = c.get("/api/approval").json()
    assert v["valid"] is False and "patch" in v["reason"]


def test_accepted_risks_are_listed(client):  # noqa: F811
    c, _ = client
    c.post("/api/risk-acceptance", json={"finding_id": "x#1", "owner": "kiran", "scope": "this PR", "reason": "no fix yet", "days": 7})
    rows = c.get("/api/risk-acceptance").json()
    assert rows[0]["finding_id"] == "x#1" and rows[0]["owner"] == "kiran"


def test_quota_exhausted_is_reported_by_name(monkeypatch):
    from guardian import llm_client
    from tests.test_llm_freemodel import FakeResp

    class S:
        def post(self, *a, **k):
            return FakeResp({"error": {"message": "Your plan tokens are used up.", "code": "tokens_exhausted"}}, code=402)
    monkeypatch.setenv("FM_API_KEY", "fm_x")
    with pytest.raises(RuntimeError, match="AI quota used up"):
        llm_client.chat_json("p", session=S(), max_tokens=100, cache=False)
