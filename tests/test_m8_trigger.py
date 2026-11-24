"""M8: PR trigger. Run identity, supersede, ordered events with resume, status mapping, comment, GitHub client, submit."""
import json

import pytest

from guardian.trigger import events as ev
from guardian.trigger import queue as q
from guardian.trigger.github import GitHub, comment_body, status_for


def _event(**kw):
    e = {"repo": "me/uptime-kuma", "pr": 7, "action": "opened", "base_sha": "a" * 40, "head_sha": "b" * 40, "draft": False}
    e.update(kw)
    return e


IDN = {"policy_sha256": "p" * 64, "profile_sha256": "f" * 64, "intel": "2026-11-24"}


def test_run_identity_includes_policy_profile_and_intelligence():
    k1 = q.identity(_event(), **IDN)
    assert k1 != q.identity(_event(), **{**IDN, "intel": "2026-11-25"})
    assert k1 != q.identity(_event(head_sha="c" * 40), **IDN)
    assert k1 == q.identity(_event(action="synchronize"), **IDN)  # same state, different event name: same analysis


def test_queue_dedups_supersedes_and_ignores_drafts(tmp_path):
    rq = q.RunQueue(tmp_path)
    r1 = rq.submit(_event(), **IDN)
    assert r1["status"] == "queued"
    assert rq.submit(_event(action="synchronize"), **IDN)["id"] == r1["id"]  # duplicate delivery: same run
    r2 = rq.submit(_event(action="synchronize", head_sha="c" * 40), **IDN)
    assert r2["id"] != r1["id"] and rq.get(r1["id"])["status"] == "superseded"
    assert rq.current("me/uptime-kuma", 7)["id"] == r2["id"]
    assert rq.submit(_event(pr=8, draft=True), **IDN) is None
    rq.submit(_event(action="closed", head_sha="c" * 40), **IDN)
    assert rq.current("me/uptime-kuma", 7) is None


def test_explicit_rerun_creates_a_new_run(tmp_path):
    rq = q.RunQueue(tmp_path)
    r1 = rq.submit(_event(), **IDN)
    r2 = rq.submit(_event(), rerun=True, **IDN)
    assert r2["id"] != r1["id"]


def test_late_result_of_superseded_run_does_not_become_current(tmp_path):
    rq = q.RunQueue(tmp_path)
    r1 = rq.submit(_event(), **IDN)
    r2 = rq.submit(_event(head_sha="c" * 40), **IDN)
    rq.finish(r1["id"], {"verdict": "allow"})
    assert rq.get(r1["id"])["status"] == "superseded" and rq.current("me/uptime-kuma", 7)["id"] == r2["id"]


def test_events_are_numbered_and_resumable(tmp_path):
    store = ev.EventStore(tmp_path)
    for i in range(5):
        store.append("run-1", "stage", {"i": i})
    assert [e["seq"] for e in store.since(0)] == [1, 2, 3, 4, 5]
    assert [e["data"]["i"] for e in store.since(3)] == [3, 4]
    assert ev.EventStore(tmp_path).since(4)[0]["seq"] == 5  # survives restart


@pytest.mark.parametrize("verdict,complete,state", [("block", True, "failure"), ("review", True, "failure"),
                                                    ("allow", True, "success"), ("allow", False, "error"), (None, False, "error")])
def test_scan_status_mapping_uses_only_github_states(verdict, complete, state):
    s = status_for({"verdict": verdict, "complete": complete})
    assert s["state"] == state and s["context"] == "guardian/scan" and len(s["description"]) <= 140
    if state == "success":
        assert "scan policy passed" in s["description"] and "verified" not in s["description"]


def test_comment_body_is_marked_for_in_place_update_and_escapes_markdown():
    body = comment_body({"verdict": "block", "complete": True, "verdict_reasons": ["axois@1.0.0: `MAL-1` <img src=x>"],
                         "head_sha": "b" * 40}, run_url="http://localhost:8765/#run-1")
    assert body.startswith("<!-- guardian:comment -->") and "BLOCK" in body and "<img" not in body


class FakeHTTP:
    def __init__(self, pages):
        self.pages, self.calls = pages, []

    def request(self, method, url, headers=None, json=None, timeout=None):
        self.calls.append((method, url, headers, json))
        from urllib.parse import parse_qs, urlparse
        u = urlparse(url)
        page = self.pages.get((method, f"{u.scheme}://{u.netloc}{u.path}", parse_qs(u.query).get("page", ["1"])[0]))
        class R:
            status_code = page[0] if page else 404
            headers = page[2] if page and len(page) > 2 else {}
            def json(self_inner):
                return page[1] if page else {}
            text = json and "" or ""
        return R()


def test_github_client_paginates_and_never_leaks_the_token(caplog):
    base = "https://api.github.com/repos/me/r/pulls"
    http = FakeHTTP({("GET", base, "1"): (200, [{"number": 1}], {"Link": f'<{base}?state=open&per_page=100&page=2>; rel="next"'}),
                     ("GET", base, "2"): (200, [{"number": 2}], {})})
    gh = GitHub("secret-token-123", http=http)
    assert [p["number"] for p in gh.open_pulls("me/r")] == [1, 2]
    assert all(c[2]["Authorization"] == "Bearer secret-token-123" for c in http.calls)
    assert "secret-token-123" not in repr(gh) and "secret-token-123" not in caplog.text


def test_github_comment_is_updated_in_place():
    url_c = "https://api.github.com/repos/me/r/issues/7/comments"
    http = FakeHTTP({("GET", url_c, "1"): (200, [{"id": 55, "body": "<!-- guardian:comment -->\nold"}], {}),
                     ("PATCH", "https://api.github.com/repos/me/r/issues/comments/55", "1"): (200, {"id": 55}, {})})
    GitHub("t", http=http).upsert_comment("me/r", 7, "<!-- guardian:comment -->\nnew")
    assert [c[0] for c in http.calls] == ["GET", "PATCH"]


def test_submit_reads_env_and_maps_decision_to_exit_code(monkeypatch):
    from guardian.trigger import submit
    sent = {}

    def fake_post(url, payload, timeout):
        sent.update(url=url, payload=payload)
        return {"run": {"id": "r1"}, "headline": {"verdict": "block", "complete": True}}
    monkeypatch.setattr(submit, "_post", fake_post)
    env = {"REPO": "me/uptime-kuma", "PR": "7", "ACTION": "opened", "BASE_SHA": "a" * 40, "HEAD_SHA": "b" * 40,
           "GUARDIAN_URL": "http://127.0.0.1:8765"}
    assert submit.main(env) == 2
    assert sent["payload"]["pr"] == 7 and sent["url"].endswith("/api/github/event")


def test_submit_rejects_malformed_input():
    from guardian.trigger import submit
    assert submit.main({"REPO": "me/r; rm -rf /", "PR": "7", "ACTION": "opened", "BASE_SHA": "a" * 40, "HEAD_SHA": "b" * 40}) == 64
    assert submit.main({"REPO": "me/r", "PR": "x", "ACTION": "opened", "BASE_SHA": "a" * 40, "HEAD_SHA": "b" * 40}) == 64


def test_workflow_template_follows_the_lock_down_rules():
    from pathlib import Path
    wf = (Path(__file__).resolve().parents[1] / "ci" / "github" / "guardian.yml").read_text()
    assert "actions/checkout" not in wf and "runs-on: [self-hosted, guardian-demo]" in wf
    assert "cancel-in-progress: true" in wf  # the title is passed only as an env var (checked below)
    run_lines = [ln for ln in wf.splitlines() if ln.strip().startswith("run:")]
    assert run_lines and all("${{" not in ln for ln in run_lines)  # event data only via env vars


# ---------- service: event -> queue -> fetch (SHA verified) -> engine -> events -> GitHub (only with a token) ----------

class Recorder:
    def __init__(self):
        self.statuses, self.comments = [], []

    def set_status(self, repo, sha, status, target_url=None):
        self.statuses.append((sha, status["context"], status["state"]))

    def upsert_comment(self, repo, pr, body):
        self.comments.append(body)


def _svc(tmp_path, fetched_sha="b" * 40, gh=None, verdict="block"):
    from guardian.trigger.service import Service
    calls = {}

    def fetch(repo, pr, head_sha, base_sha):
        calls["fetch"] = (repo, pr, head_sha)
        return tmp_path / "mirror", fetched_sha

    def engine(mirror, base, head, out, app):
        calls["engine"] = (base, head, app)
        return {"headline": {"verdict": verdict, "complete": True, "verdict_reasons": ["x"], "head_sha": head}}
    return Service(tmp_path, fetch=fetch, engine=engine, github=gh, identity_parts=lambda: IDN), calls


def test_service_runs_engine_on_the_verified_commit_and_posts_when_token_present(tmp_path):
    gh = Recorder()
    svc, calls = _svc(tmp_path, gh=gh)
    res = svc.handle(_event())
    assert res["headline"]["verdict"] == "block" and calls["engine"] == ("a" * 40, "b" * 40, "uptime-kuma")
    assert gh.statuses == [("b" * 40, "guardian/scan", "pending"), ("b" * 40, "guardian/scan", "failure")]
    assert gh.comments and "BLOCK" in gh.comments[0]
    kinds = [e["kind"] for e in svc.events.since(0)]
    assert kinds[0] == "run_queued" and "scan_finished" in kinds


def test_service_stops_when_the_branch_moved_before_fetch(tmp_path):
    svc, calls = _svc(tmp_path, fetched_sha="9" * 40)
    res = svc.handle(_event())
    assert res["status"] == "stale" and "engine" not in calls


def test_service_without_token_records_not_posted(tmp_path):
    svc, _ = _svc(tmp_path, gh=None, verdict="allow")
    res = svc.handle(_event())
    assert res["github"] == "not posted: no GitHub token configured"


# ---------- server wiring ----------

def test_github_event_endpoint_validates_and_delegates(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from guardian import server
    svc, _ = _svc(tmp_path, verdict="allow")
    monkeypatch.setattr(server, "_trigger_service", lambda: svc)
    c = TestClient(server.app)
    bad = c.post("/api/github/event", json={"repo": "x; rm", "pr": 1, "action": "opened", "head_sha": "b" * 40})
    assert bad.status_code == 422
    ok = c.post("/api/github/event", json={"repo": "me/uptime-kuma", "pr": 7, "action": "opened", "base_sha": "a" * 40,
                                           "head_sha": "b" * 40, "draft": False})
    assert ok.status_code == 200 and ok.json()["headline"]["verdict"] == "allow"
    cur = c.get("/api/trigger/current").json()
    assert cur["runs"][0]["pr"] == 7 and cur["last_seq"] >= 2
    evs = c.get("/api/trigger/events?since=0").json()
    assert [e["seq"] for e in evs] == sorted(e["seq"] for e in evs)


# ---------- polling backup ----------

class FakeGH:
    def __init__(self, pulls):
        self.pulls = pulls

    def open_pulls(self, repo):
        return self.pulls


def _pull(n=7, head="b" * 40, base="a" * 40, draft=False, ref="main"):
    return {"number": n, "draft": draft, "head": {"sha": head}, "base": {"sha": base, "ref": ref}}


def test_poll_detects_new_pr_new_commit_ready_base_change_and_close(tmp_path):
    from guardian.trigger.watcher import poll_once
    seen = []
    state = {}
    handle = seen.append
    poll_once(FakeGH([_pull(draft=True)]), "me/r", state, handle)
    assert seen == []                                            # draft: skipped
    poll_once(FakeGH([_pull()]), "me/r", state, handle)
    assert seen[-1]["action"] == "ready_for_review"              # draft -> ready without a new commit
    poll_once(FakeGH([_pull()]), "me/r", state, handle)
    assert len(seen) == 1                                        # nothing changed
    poll_once(FakeGH([_pull(head="c" * 40)]), "me/r", state, handle)
    assert seen[-1]["action"] == "synchronize" and seen[-1]["head_sha"] == "c" * 40
    poll_once(FakeGH([_pull(head="c" * 40, base="d" * 40, ref="release")]), "me/r", state, handle)
    assert seen[-1]["action"] == "edited"
    poll_once(FakeGH([]), "me/r", state, handle)
    assert seen[-1]["action"] == "closed"
