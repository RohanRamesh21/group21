"""M4 agent part: model reviews the computed plan; code checks it; the plan itself never changes."""
import json

PLAN = {"candidates": [
    {"id": "FIX-a", "type": "upgrade_to_fixed", "package": "jsonata", "from": "2.2.0", "to": "2.2.1", "semver_jump": "patch",
     "rationale": "2.2.1 is the smallest published version outside every affected range", "finding_ids": ["jsonata@2.2.0#GHSA-1"],
     "expected_risk_reduction": {"critical": 2, "high": 0, "medium": 1, "low": 0}, "compatibility": {"note": "bug-fix release"},
     "rollback": "git revert"},
    {"id": "FIX-b", "type": "remove_package", "package": "axois", "rationale": "adds malware", "finding_ids": ["axois@1.0.0#MAL-1"],
     "expected_risk_reduction": {"critical": 4, "high": 1, "medium": 0, "low": 2}, "rollback": "git revert"}],
    "patch": {"patch_sha256": "c" * 64}}


def test_review_keeps_checked_sentences_and_drops_invented_facts(monkeypatch):
    from guardian.remediation import review as rv
    raw = {"explanations": [
        {"candidate_id": "FIX-a", "text": "Upgrade jsonata from 2.2.0 to 2.2.1, a patch release.", "cites": ["from", "to", "semver_jump"]},
        {"candidate_id": "FIX-a", "text": "Version 3.1.0 would also work.", "cites": ["to"]},
        {"candidate_id": "FIX-zzz", "text": "made up", "cites": []}],
        "challenges": [{"candidate_id": "FIX-b", "concern": "Confirm nothing imports axois before removal.", "cites": ["rationale"]}]}
    monkeypatch.setattr(rv.llm_client, "chat_json", lambda prompt, **k: (raw, {"model": "deepseek-v4-flash-0731", "usage": {}}))
    before = json.dumps(PLAN, sort_keys=True)
    r = rv.review(PLAN)
    assert json.dumps(PLAN, sort_keys=True) == before          # the plan is not modified
    texts = [e["text"] for e in r["explanations"]]
    assert texts == ["Upgrade jsonata from 2.2.0 to 2.2.1, a patch release."]
    assert {x["reason"] for x in r["rejected"]} >= {"unknown candidate FIX-zzz", "mentions 3.1.0, not in the candidate"}
    assert r["challenges"][0]["candidate_id"] == "FIX-b" and all(x["status"] == "inferred" for x in r["explanations"] + r["challenges"])
    assert r["model"] == "deepseek-v4-flash-0731" and r["patch_sha256"] == "c" * 64


def test_review_failure_is_reported_not_hidden(monkeypatch):
    from guardian.remediation import review as rv

    def boom(prompt, **k):
        raise RuntimeError("model call failed (HTTP 503)")
    monkeypatch.setattr(rv.llm_client, "chat_json", boom)
    r = rv.review(PLAN)
    assert r["status"] == "unavailable" and "503" in r["error"] and r["explanations"] == []


def test_review_endpoint_saves_review_into_the_plan(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from guardian import server
    from guardian.remediation import review as rv
    (tmp_path / "fix-plan.json").write_text(json.dumps({**PLAN, "pending": ["Fixer/Verifier explanations need the AI model"]}))
    monkeypatch.setattr(server, "_check_dir", lambda project: tmp_path)
    monkeypatch.setattr(rv.llm_client, "chat_json", lambda prompt, **k: (
        {"explanations": [{"candidate_id": "FIX-b", "text": "Remove the malicious package.", "cites": ["rationale"]}], "challenges": []},
        {"model": "deepseek-v4-flash-0731", "usage": {"prompt_tokens": 10}}))
    r = TestClient(server.app).post("/api/fix-plan/review", json={})
    assert r.status_code == 200 and r.json()["status"] == "done"
    saved = json.loads((tmp_path / "fix-plan.json").read_text())
    assert saved["review"]["explanations"][0]["candidate_id"] == "FIX-b" and saved["pending"] == []
