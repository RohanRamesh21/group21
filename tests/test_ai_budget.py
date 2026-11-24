"""Token ledger, budget guard and response cache around every model call (no real API calls)."""
import json

import pytest

from tests.test_llm_freemodel import REPLY, FakeSession


@pytest.fixture
def fm(monkeypatch, tmp_path):
    from guardian import llm_client
    monkeypatch.setenv("FM_API_KEY", "fm_test_secret")
    monkeypatch.setenv("GUARDIAN_LEDGER", str(tmp_path / "ledger.jsonl"))
    monkeypatch.setenv("GUARDIAN_LLM_CACHE", str(tmp_path / "cache"))
    monkeypatch.setenv("GUARDIAN_RUN_TOKEN_BUDGET", "1000")
    monkeypatch.setenv("GUARDIAN_MONTH_TOKEN_BUDGET", "5000")
    monkeypatch.setenv("GUARDIAN_REASONING_ALLOWANCE", "0")
    return llm_client, tmp_path


def test_every_call_is_written_to_the_ledger_without_the_key(fm):
    llm, tmp = fm
    llm.chat_json("prompt", session=FakeSession(REPLY), max_tokens=200, purpose="test", run_id="R1", cache=False)
    rows = [json.loads(x) for x in (tmp / "ledger.jsonl").read_text().splitlines()]
    assert rows[0]["purpose"] == "test" and rows[0]["run_id"] == "R1"
    assert rows[0]["prompt_tokens"] == 100 and rows[0]["completion_tokens"] == 20 and rows[0]["cached"] is False
    assert "fm_test_secret" not in (tmp / "ledger.jsonl").read_text()


def test_call_is_refused_before_sending_when_run_budget_would_be_crossed(fm):
    llm, _ = fm
    s = FakeSession(REPLY)
    with pytest.raises(llm.BudgetExceeded, match="run budget"):
        llm.chat_json("x" * 300, session=s, max_tokens=2000, run_id="R1", cache=False)
    assert s.sent == []  # nothing left the machine


def test_month_budget_counts_earlier_calls(fm):
    llm, tmp = fm
    (tmp / "ledger.jsonl").write_text(json.dumps({"ts": __import__("time").time(), "run_id": "old", "purpose": "x",
                                                  "prompt_tokens": 4800, "completion_tokens": 100, "cached": False}) + "\n")
    s = FakeSession(REPLY)
    with pytest.raises(llm.BudgetExceeded, match="month budget"):
        llm.chat_json("p", session=s, max_tokens=200, run_id="R2", cache=False)
    assert s.sent == []


def test_same_prompt_is_answered_from_cache_with_zero_tokens(fm):
    llm, tmp = fm
    s = FakeSession(REPLY)
    a, m1 = llm.chat_json("same prompt", session=s, max_tokens=200, run_id="R1")
    b, m2 = llm.chat_json("same prompt", session=s, max_tokens=200, run_id="R1")
    assert a == b and len(s.sent) == 1
    assert m1["cached"] is False and m2["cached"] is True and m2["cached_at"]
    rows = [json.loads(x) for x in (tmp / "ledger.jsonl").read_text().splitlines()]
    assert rows[1]["cached"] is True and rows[1]["prompt_tokens"] == 0


def test_usage_summary_reports_run_and_month_totals(fm):
    llm, _ = fm
    llm.chat_json("p1", session=FakeSession(REPLY), max_tokens=200, run_id="R1", cache=False)
    llm.chat_json("p2", session=FakeSession(REPLY), max_tokens=200, run_id="R1", cache=False)
    u = llm.usage_summary("R1")
    assert u["run"]["calls"] == 2 and u["run"]["tokens"] == 240
    assert u["month"]["tokens"] == 240 and u["budget"] == {"run": 1000, "month": 5000}


def test_deep_mode_backend_is_budgeted_too(fm, monkeypatch):
    llm, tmp = fm
    from guardian.agents.llm import FreeModelBackend
    b = FreeModelBackend()
    b.session = FakeSession(REPLY)
    monkeypatch.setenv("GUARDIAN_RUN_TOKEN_BUDGET", "10")
    with pytest.raises(llm.BudgetExceeded):
        b.step("lead", "sys", [{"role": "user", "content": "go"}], [], "medium")
    assert b.session.sent == []


def test_explanations_for_many_findings_use_one_batched_call(monkeypatch, tmp_path):
    from guardian.scoring import explain as ex
    monkeypatch.setenv("GUARDIAN_LLM_PROVIDER", "freemodel")
    monkeypatch.setattr(ex, "CACHE", tmp_path)
    calls = []

    def chat(prompt, **k):
        calls.append(k)
        cards = json.loads(prompt.split("CARDS:\n", 1)[1])
        return {"explanations": [{"card": c["card"], "headline": "h", "sentences": [{"text": "It scored 100.", "cites": ["score"]}]}
                                 for c in cards]}, {"model": "deepseek-v4-flash-0731", "usage": {}, "cached": False}
    monkeypatch.setattr(ex.llm_client, "chat_json", chat)
    fs = [{"title": f"p{i}@1.0.0: MAL-{i}", "kind": "vulnerability", "component": f"p{i}@1.0.0", "label": "introduced",
           "decision": "Act", "level": "critical", "score": 100, "ssvc": None, "floor": "malware", "contributions": [],
           "counterfactuals": [], "evidence": {"advisory": f"MAL-{i}"}, "summary": ""} for i in range(5)]
    ex.warm(fs)
    assert len(calls) == 1 and calls[0]["purpose"] == "explain"
    assert all(ex.is_cached(f) for f in fs)
    assert ex.explain(fs[0])["cached"] is True


def test_fix_review_is_tagged_in_the_ledger(monkeypatch):
    from guardian.remediation import review as rv
    seen = {}
    monkeypatch.setattr(rv.llm_client, "chat_json", lambda prompt, **k: (seen.update(k) or {"explanations": [], "challenges": []},
                                                                          {"model": "m", "usage": {}}))
    # one fix that changes something (an empty plan no longer calls the model at all: nothing to explain)
    rv.review({"candidates": [{"id": "c1", "type": "upgrade_to_fixed", "package": "p", "from": "1.0.0", "to": "1.0.1"}],
               "patch": {"patch_sha256": "abc123"}})
    assert seen["purpose"] == "fix_review" and seen["run_id"] == "fix-abc123"


def test_budget_estimate_includes_hidden_reasoning_tokens(monkeypatch):
    from guardian import llm_budget
    monkeypatch.setenv("GUARDIAN_REASONING_ALLOWANCE", "3000")
    assert llm_budget.estimate("x" * 30, 1500) == 10 + 1 + 1500 + 3000


def test_empty_reply_is_an_error_with_finish_reason_and_is_not_cached(fm):
    llm, tmp = fm
    empty = {"choices": [{"message": {"content": ""}, "finish_reason": "length"}], "usage": {"prompt_tokens": 50, "completion_tokens": 400}}
    with pytest.raises(RuntimeError, match="finish_reason=length"):
        llm.chat_json("p", session=FakeSession(empty), max_tokens=200, run_id="R1")
    assert not any((tmp / "cache").glob("*.json")) if (tmp / "cache").exists() else True
    row = json.loads((tmp / "ledger.jsonl").read_text().splitlines()[-1])
    assert row["finish_reason"] == "length" and row["completion_tokens"] == 400  # tokens were still spent: recorded


def test_explanations_use_their_own_reasoning_effort(fm, monkeypatch):
    llm, _ = fm
    monkeypatch.setenv("GUARDIAN_EFFORT", "medium")
    s = FakeSession(REPLY)
    llm.chat_json("p", session=s, max_tokens=200, run_id="R1", cache=False, effort="low")
    assert s.sent[0][1]["reasoning_effort"] == "low"


def test_explain_requests_low_effort_by_default(monkeypatch, tmp_path):
    from guardian.scoring import explain as ex
    monkeypatch.setenv("GUARDIAN_LLM_PROVIDER", "freemodel")
    monkeypatch.delenv("GUARDIAN_EXPLAIN_EFFORT", raising=False)
    monkeypatch.setattr(ex, "CACHE", tmp_path)
    seen = {}
    monkeypatch.setattr(ex.llm_client, "chat_json", lambda p, **k: (seen.update(k) or {"headline": "h", "sentences": []}, {"model": "m"}))
    ex.explain({"title": "a@1.0.0: MAL-1", "label": "introduced", "contributions": [], "evidence": {}, "summary": ""}, force=True)
    assert seen["effort"] == "low"


def test_investigate_endpoint_does_not_explain_unless_asked():
    from guardian.server import InvestigateReq
    assert InvestigateReq().explain is False
