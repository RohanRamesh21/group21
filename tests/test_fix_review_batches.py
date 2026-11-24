"""Fixer + Verifier review is planned like the Investigators: only fixes that change something, most important first,
small parallel batches; a batch the model refuses is split and retried; whatever still fails keeps its rule rationale
and is listed as not AI-reviewed. One oversized call no longer turns the whole Fixer into "failed"."""
import json

import pytest

from guardian import llm_client
from guardian.remediation import review as rv


def _c(i, t="upgrade_to_fixed"):
    return {"id": f"c{i:03d}", "type": t, "package": f"pkg{i}", "from": "1.0.0", "to": "1.0.1", "rationale": "r",
            "finding_ids": [f"f{i}"], "expected_risk_reduction": {"high": 1}}


def _ids(prompt):
    return [c["id"] for c in json.loads(prompt.split("Candidates:\n", 1)[1])]


def _ok(prompt, **kw):
    return {"explanations": [{"candidate_id": i, "text": "upgrades to 1.0.1", "cites": ["to"]} for i in _ids(prompt)],
            "challenges": []}, {"model": "m", "usage": {"total_tokens": 100}}


@pytest.fixture
def calls(monkeypatch):
    seen = []

    def fake(prompt, **kw):
        seen.append(_ids(prompt))
        return _ok(prompt)
    monkeypatch.setattr(llm_client, "chat_json", fake)
    return seen


def test_escalations_are_not_sent_and_batches_are_small(calls):
    plan = {"candidates": [_c(i) for i in range(30)] + [_c(100 + i, "escalate") for i in range(50)]}
    r = rv.review(plan)
    sent = [i for b in calls for i in b]
    assert r["status"] == "done"
    assert len(sent) == 30 and not any(i.startswith("c1") and int(i[1:]) >= 100 for i in sent)
    assert max(len(b) for b in calls) <= rv.BATCH
    assert r["coverage"]["needs_person"] == 50 and r["coverage"]["reviewed"] == 30
    assert len(r["explanations"]) == 30


def test_most_important_fixes_are_reviewed_first(calls):
    plan = {"candidates": [_c(1, "override_transitive"), _c(2, "remove_package"), _c(3, "revert_change"), _c(4, "restore_lock_entry")]}
    rv.review(plan)
    assert calls[0] == ["c002", "c004", "c003", "c001"]


def test_a_refused_batch_is_split_and_retried(monkeypatch):
    def fake(prompt, **kw):
        if len(_ids(prompt)) > 3:
            raise RuntimeError("month budget: 900 used + up to 500 for this call > 1000 tokens")
        return _ok(prompt)
    monkeypatch.setattr(llm_client, "chat_json", fake)
    r = rv.review({"candidates": [_c(i) for i in range(rv.BATCH)]})
    assert r["status"] == "done" and len(r["explanations"]) == rv.BATCH
    assert r["coverage"]["retries"] > 0


def test_what_still_fails_is_partial_with_reasons_not_failed(monkeypatch):
    def fake(prompt, **kw):
        if "c000" in _ids(prompt):
            raise RuntimeError("provider unavailable")
        return _ok(prompt)
    monkeypatch.setattr(llm_client, "chat_json", fake)
    r = rv.review({"candidates": [_c(i) for i in range(5)]})
    assert r["status"] == "partial"
    assert [x["candidate_id"] for x in r["coverage"]["not_reviewed"]] == ["c000"]
    assert "unavailable" in r["coverage"]["not_reviewed"][0]["reason"]
    assert len(r["explanations"]) == 4


def test_nothing_reviewable_is_done_not_failed(calls):
    r = rv.review({"candidates": [_c(i, "escalate") for i in range(3)]})
    assert r["status"] == "done" and calls == [] and r["coverage"]["needs_person"] == 3


def test_everything_failing_is_unavailable(monkeypatch):
    monkeypatch.setattr(llm_client, "chat_json", lambda p, **k: (_ for _ in ()).throw(RuntimeError("down")))
    r = rv.review({"candidates": [_c(i) for i in range(3)]})
    assert r["status"] == "unavailable" and "down" in r["error"]


def test_review_cap_keeps_the_rest_on_rule_rationale(calls):
    r = rv.review({"candidates": [_c(i) for i in range(rv.MAX_REVIEWED + 5)]})
    assert r["coverage"]["reviewed"] == rv.MAX_REVIEWED
    assert len(r["coverage"]["not_reviewed"]) == 5 and "limit" in r["coverage"]["not_reviewed"][0]["reason"]
    assert r["status"] == "partial"
