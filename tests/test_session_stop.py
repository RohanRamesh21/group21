"""Stop session (Buddy 'Stop' button): a running scan, agent run or validation of a PR run stops cleanly.
A stopped scan posts no verdict and starts no agents; stopped agents ask for no approval; nothing is faked as a result."""
import json

from fastapi.testclient import TestClient

from tests.test_ai_workflow import run  # noqa: F401  (pytest fixture)
from tests.test_m8_trigger import IDN, Recorder, _event, _svc


def test_queue_cancel_marks_run_and_it_is_no_longer_current(tmp_path):
    from guardian.trigger import queue as q
    rq = q.RunQueue(tmp_path)
    r = rq.submit(_event(), **IDN)
    rq.start(r["id"])
    assert rq.cancel(r["id"]) is True
    rq.finish(r["id"], {"verdict": "block"})  # the late engine result does not revive it
    assert rq.get(r["id"])["status"] == "cancelled" and rq.current("me/uptime-kuma", 7) is None
    assert rq.cancel(r["id"]) is False


def test_stopped_scan_posts_no_verdict_and_starts_no_agents(tmp_path):
    gh = Recorder()
    svc, _ = _svc(tmp_path, gh=gh)
    seen = []
    svc.after_scan = lambda *a: seen.append(a)
    inner = svc.engine

    def engine(*a):
        rid = next(iter(svc.queue.runs))
        svc.queue.cancel(rid)  # the user presses Stop while the engine runs
        return inner(*a)
    svc.engine = engine
    res = svc.handle(_event())
    assert res["status"] == "cancelled" and seen == []
    assert ("b" * 40, "guardian/scan", "failure") not in gh.statuses
    assert "scan_finished" not in [e["kind"] for e in svc.events.since(0)]


def test_workflow_stops_before_the_next_model_call(run):
    from guardian.ai import workflow
    from tests.test_ai_workflow import _fake_chat
    calls = []
    v = workflow.investigate(run, chat=_fake_chat(calls), workers=1, should_stop=lambda: len(calls) >= 1)
    assert v["status"] == "cancelled" and len(calls) == 1
    assert [c["status"] for c in v["cases"]].count("cancelled") == 1 and v["verifier"]["status"] != "done"


def test_stopped_auto_agents_do_not_ask_for_approval(monkeypatch, tmp_path):
    from guardian import server
    from guardian.ai import workflow
    svc, _ = _svc(tmp_path, gh=Recorder(), verdict="block")

    def fake(out, on_event=None, should_stop=None, **k):
        server.stop_session_flags[str(out)] = True  # Stop pressed during the run
        assert should_stop()
        return {"status": "cancelled", "usage": {"run": {"tokens": 0}}}
    monkeypatch.setattr(workflow, "investigate", fake)
    monkeypatch.setattr(server, "_fixer", lambda out, emit: (_ for _ in ()).throw(AssertionError("fixer must not run")))
    server._auto_agents(svc, "RID1", tmp_path, {"verdict": "block"}, {"repo": "me/app", "pr": 3}, background=False)
    kinds = [e["kind"] for e in svc.events.since(0)]
    assert "approval_needed" not in kinds
    fin = next(e for e in svc.events.since(0) if e["kind"] == "agents_finished")
    assert fin["data"]["status"] == "cancelled"


def test_stop_endpoint_cancels_a_running_scan_and_says_what_it_stopped(monkeypatch, tmp_path):
    from guardian import server
    gh = Recorder()
    svc, _ = _svc(tmp_path, gh=gh)
    monkeypatch.setattr(server, "_trigger_service", lambda: svc)
    run = svc.queue.submit(_event(), **IDN)
    svc.queue.start(run["id"])
    r = TestClient(server.app).post("/api/session/stop", json={"project": f"gh-{run['id']}"})
    assert r.status_code == 200 and "scan" in r.json()["stopped"]
    assert svc.queue.get(run["id"])["status"] == "cancelled"
    assert gh.statuses[-1][2] == "error"  # PR check says 'stopped', never a pass or a fail
    assert any(e["kind"] == "session_stopped" for e in svc.events.since(0))


def test_stop_endpoint_with_nothing_running_is_harmless(monkeypatch, tmp_path):
    from guardian import server
    svc, _ = _svc(tmp_path, gh=Recorder(), verdict="allow")
    monkeypatch.setattr(server, "_trigger_service", lambda: svc)
    res = svc.handle(_event())
    out = svc.root / "runs" / res["run"]["id"]
    out.mkdir(parents=True, exist_ok=True)
    r = TestClient(server.app).post("/api/session/stop", json={"project": f"gh-{res['run']['id']}"})
    assert r.status_code == 200 and r.json()["stopped"] == []
    assert svc.queue.get(res["run"]["id"])["status"] == "done"
    assert json.loads(json.dumps(r.json()))  # plain JSON
