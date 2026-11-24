"""API + CLI for the budgeted investigation workflow (fake model, no tokens)."""
import json
import time

from fastapi.testclient import TestClient

from tests.test_ai_workflow import _fake_chat, run  # noqa: F401  (fixture)


def _client(monkeypatch, out):
    from guardian import server
    monkeypatch.setattr(server, "_check_dir", lambda project: out)
    return TestClient(server.app), server


def test_investigate_endpoint_runs_in_background_and_saves_result(run, monkeypatch):  # noqa: F811
    from guardian.ai import workflow
    c, server = _client(monkeypatch, run)
    real = workflow.investigate
    monkeypatch.setattr(workflow, "investigate", lambda out, **k: real(out, chat=_fake_chat([]), on_event=k.get("on_event")))
    assert c.post("/api/investigate", json={}).json()["status"] == "started"
    for _ in range(50):
        r = c.get("/api/investigation").json()
        if r.get("status") in ("done", "partial"):
            break
        time.sleep(0.05)
    assert r["status"] == "done" and r["mode"] == "workflow" and len(r["cases"]) == 2
    assert (run / "agents" / "verdict.json").exists()


def test_investigation_before_any_run_is_404(run, monkeypatch):  # noqa: F811
    c, _ = _client(monkeypatch, run)
    assert c.get("/api/investigation").status_code == 404


def test_usage_endpoint_shows_budget_and_never_the_key(run, monkeypatch):  # noqa: F811
    from guardian import llm_budget
    monkeypatch.setenv("FM_API_KEY", "fm_secret_value")
    llm_budget.record(run_id="inv-x", purpose="investigate", model="m", usage={"prompt_tokens": 7, "completion_tokens": 3}, cached=False)
    c, _ = _client(monkeypatch, run)
    r = c.get("/api/ai/usage")
    body = r.json()
    assert body["month"]["tokens"] == 10 and body["budget"]["run"] > 0 and body["by_purpose"]["investigate"]["tokens"] == 10
    assert "fm_secret_value" not in r.text


def test_scores_page_does_not_spend_tokens_unless_enabled(monkeypatch, tmp_path):
    from guardian import server
    monkeypatch.delenv("GUARDIAN_AUTO_EXPLAIN", raising=False)
    assert server._auto_explain() is False
    monkeypatch.setenv("GUARDIAN_AUTO_EXPLAIN", "1")
    assert server._auto_explain() is True


def test_cli_investigate_defaults_to_the_workflow(run, monkeypatch, capsys):  # noqa: F811
    from guardian import cli
    from guardian.ai import workflow
    real = workflow.investigate
    monkeypatch.setattr(workflow, "investigate", lambda out, **k: real(out, chat=_fake_chat([])))
    code = cli.main(["investigate", "--out", str(run)])
    assert code == 0 and "inv-" in capsys.readouterr().out


def test_workflow_emits_one_event_stream_per_agent(run):  # noqa: F811
    from guardian.ai import workflow
    events = []
    workflow.investigate(run, chat=_fake_chat([]), on_event=events.append)
    agents = [e["agent"] for e in events]
    assert agents[0] == "lead" and events[0]["cases"] == 2
    assert agents.count("investigator") >= 2 and "verifier" in agents and events[-1]["agent"] == "gatekeeper"
    assert "rejected" in events[-1]


def test_one_click_runs_fixer_after_investigation(run, monkeypatch):  # noqa: F811
    from guardian.ai import workflow
    from guardian.remediation import review as rv
    c, server = _client(monkeypatch, run)
    real = workflow.investigate
    monkeypatch.setattr(workflow, "investigate", lambda out, **k: real(out, chat=_fake_chat([]), on_event=k.get("on_event")))
    plan = {"candidates": [{"id": "FIX-1"}], "patch": {"patch_sha256": "ab" * 32}, "pending": []}
    (run / "fix-plan.json").write_text(json.dumps(plan))  # rules already proposed the fix
    monkeypatch.setattr(rv, "review", lambda p: {"status": "done", "explanations": [{"candidate_id": "FIX-1", "text": "t"}],
                                                 "challenges": [], "rejected": []})
    c.post("/api/investigate", json={"fix_review": True})
    for _ in range(60):
        r = c.get("/api/investigation").json()
        if r.get("status") in ("done", "partial") and not r.get("running"):
            break
        time.sleep(0.05)
    saved = json.loads((run / "fix-plan.json").read_text())
    assert saved["review"]["status"] == "done"
    ev = c.get("/api/investigation/events").json()["events"]
    assert any(e["agent"] == "fixer" and e["state"] == "done" for e in ev)
