"""Live GitHub flow: PR title, per-repo validation profile, PR runs in the dashboard, auto agents, validation status, nightly."""
import json
from pathlib import Path

from fastapi.testclient import TestClient

from tests.test_m8_trigger import IDN, Recorder, _event, _svc

ROOT = Path(__file__).resolve().parents[1]


# ---------- submit + event model ----------

def test_submit_passes_a_cleaned_title_and_supports_nightly(monkeypatch):
    from guardian.trigger import submit
    sent = []
    monkeypatch.setattr(submit, "_post", lambda url, payload, timeout: sent.append(payload) or {"headline": {"verdict": "allow", "complete": True}})
    env = {"REPO": "me/app", "PR": "3", "ACTION": "opened", "BASE_SHA": "a" * 40, "HEAD_SHA": "b" * 40,
           "TITLE": "feat: chart\x1b[31m" + "x" * 400}
    assert submit.main(env) == 0
    assert "\x1b" not in sent[0]["title"] and len(sent[0]["title"]) <= 200
    assert submit.main({"REPO": "me/app", "ACTION": "nightly", "HEAD_SHA": "c" * 40}) == 0
    assert sent[1]["action"] == "nightly" and sent[1]["pr"] == 0


def test_event_model_allows_pr_zero_only_for_nightly():
    import pytest

    from guardian.server import GitHubEvent
    GitHubEvent(repo="me/app", pr=0, action="nightly", head_sha="c" * 40)
    with pytest.raises(ValueError):
        GitHubEvent(repo="me/app", pr=0, action="opened", head_sha="c" * 40)
    with pytest.raises(ValueError):
        GitHubEvent(repo="me/app", pr=1, action="opened", head_sha="c" * 40, title="x" * 201)


def test_workflow_template_uses_pull_request_target_without_checkout():
    wf = (ROOT / "ci" / "github" / "guardian.yml").read_text()
    assert "pull_request_target:" in wf and "actions/checkout" not in wf and "permissions: {}" in wf
    run_lines = [ln for ln in wf.splitlines() if ln.strip().startswith("run:")]
    assert run_lines and all("${{" not in ln for ln in run_lines)


# ---------- service ----------

def test_title_is_stored_and_sent_with_the_queued_event(tmp_path):
    svc, _ = _svc(tmp_path, gh=Recorder())
    res = svc.handle({**_event(), "title": "feat: alert rules"})
    assert svc.queue.get(res["run"]["id"])["title"] == "feat: alert rules"
    queued = next(e for e in svc.events.since(0) if e["kind"] == "run_queued")
    assert queued["data"]["title"] == "feat: alert rules"


def test_after_scan_hook_runs_for_block_and_review_only(tmp_path):
    for verdict, expect in (("block", 1), ("review", 1), ("allow", 0)):
        svc, _ = _svc(tmp_path / verdict, verdict=verdict)
        seen = []
        svc.after_scan = lambda rid, out, h, e: seen.append((rid, h["verdict"]))
        svc.handle(_event())
        assert len(seen) == expect


def test_nightly_reports_only_newly_disclosed_findings_in_one_issue(tmp_path):
    from guardian.trigger.service import Service
    found = [["GHSA-old"], ["GHSA-old", "GHSA-new"], ["GHSA-old", "GHSA-new"]]

    class GH(Recorder):
        issues = []

        def upsert_issue(self, repo, title, body):
            self.issues.append((title, body))

    def engine(mirror, base, head, out, app):
        ids = found.pop(0)
        return {"headline": {"verdict": "allow", "complete": True, "head_sha": head},
                "vulnerabilities": [{"key": f"pkg@1.0.0#{i}", "id": i, "severity": "high"} for i in ids]}
    gh = GH()
    svc = Service(tmp_path, fetch=lambda repo, pr, head, base: (tmp_path, head), engine=engine, github=gh, identity_parts=lambda: IDN)
    first = svc.handle({"repo": "me/app", "pr": 0, "action": "nightly", "head_sha": "c" * 40})
    assert first["newly_disclosed"] == []  # first night = baseline
    second = svc.handle({"repo": "me/app", "pr": 0, "action": "nightly", "head_sha": "c" * 40})
    assert second["newly_disclosed"] == ["pkg@1.0.0#GHSA-new"] and "GHSA-new" in gh.issues[-1][1]
    third = svc.handle({"repo": "me/app", "pr": 0, "action": "nightly", "head_sha": "c" * 40})
    assert third["newly_disclosed"] == [] and len(gh.issues) == 1  # no repeat alert


# ---------- validation profile per repo + validation status ----------

def test_profile_is_chosen_by_repository():
    from guardian.validation.runner import profile_for
    assert profile_for("kirankishoreV-07/PIPELINE_CHECK") == "shiplog"
    assert profile_for("someone/uptime-kuma") == "uptime-kuma"


def test_validation_status_mapping():
    from guardian.trigger.github import validation_status
    assert validation_status({"status": "executed", "gate": {"verified": True}})["state"] == "success"
    assert validation_status({"status": "executed", "gate": {"verified": False, "validation": "failed"}})["state"] == "failure"
    assert validation_status({"status": "refused", "reason": "no approval"})["state"] == "error"
    assert validation_status({"status": "executed", "gate": {"verified": True}})["context"] == "guardian/validation"


# ---------- dashboard: PR runs are first-class runs ----------

def _server_with_run(monkeypatch, tmp_path):
    from guardian import server
    svc, _ = _svc(tmp_path, gh=Recorder(), verdict="allow")
    monkeypatch.setattr(server, "_trigger_service", lambda: svc)
    res = svc.handle({**_event(), "title": "feat: chart"})
    rid = res["run"]["id"]
    out = svc.root / "runs" / rid
    out.mkdir(parents=True, exist_ok=True)
    (out / "latest.json").write_text(json.dumps({"path": "x"}))
    return server, svc, rid, out


def test_pr_run_ids_resolve_to_their_run_folder(monkeypatch, tmp_path):
    server, _, rid, out = _server_with_run(monkeypatch, tmp_path)
    assert server._check_dir(f"gh-{rid}") == out


def test_pr_runs_are_listed_newest_first_with_title_and_verdict(monkeypatch, tmp_path):
    server, _, rid, _ = _server_with_run(monkeypatch, tmp_path)
    runs = TestClient(server.app).get("/api/pr-runs").json()
    assert runs[0]["project"] == f"gh-{rid}" and runs[0]["title"] == "feat: chart" and runs[0]["verdict"] == "allow"


def test_auto_agents_emit_trigger_events_for_buddy(monkeypatch, tmp_path):
    from guardian import server
    from guardian.ai import workflow
    svc, _ = _svc(tmp_path, gh=Recorder(), verdict="block")
    monkeypatch.setenv("GUARDIAN_AUTO_AGENTS", "1")
    monkeypatch.setattr(workflow, "investigate", lambda out, on_event=None, **k: (on_event({"agent": "lead", "state": "done", "cases": 1}),
                                                                                 {"status": "done", "usage": {"run": {"tokens": 0}}})[1])
    monkeypatch.setattr(server, "_fixer", lambda out, emit: emit({"agent": "fixer", "state": "done"}))
    server._auto_agents(svc, "RID1", tmp_path, {"verdict": "block"}, {"repo": "me/app", "pr": 3}, background=False)
    kinds = [e["kind"] for e in svc.events.since(0)]
    assert kinds[0] == "agents_started" and "agent" in kinds and kinds[-1] == "approval_needed"


def test_failed_github_posts_are_visible_events_not_silent(tmp_path):
    class Broken(Recorder):
        def set_status(self, *a, **k):
            raise RuntimeError("status update failed with 403")
    svc, _ = _svc(tmp_path, gh=Broken(), verdict="allow")
    svc.handle(_event())
    ev = [e for e in svc.events.since(0) if e["kind"] == "github_post" and e["data"]["what"] == "status"]
    assert ev and ev[-1]["data"]["result"].startswith("post failed") and "403" in ev[-1]["data"]["result"]


def test_each_repository_can_have_its_own_token(monkeypatch):
    from guardian.trigger.github import GitHubRouter, token_env_name
    assert token_env_name("kirankishoreV-07/uptime-kuma") == "GUARDIAN_GITHUB_TOKEN__KIRANKISHOREV_07__UPTIME_KUMA"
    seen = []

    class Fake:
        def __init__(self, token):
            self.token = token

        def set_status(self, repo, sha, status, target_url=None):
            seen.append((repo, self.token))
    env = {"GUARDIAN_GITHUB_TOKEN": "default", "GUARDIAN_GITHUB_TOKEN__KIRANKISHOREV_07__UPTIME_KUMA": "kuma"}
    r = GitHubRouter(env, client=Fake)
    r.set_status("kirankishoreV-07/uptime-kuma", "a" * 40, {"state": "success", "context": "c"})
    r.set_status("kirankishoreV-07/PIPELINE_CHECK", "a" * 40, {"state": "success", "context": "c"})
    assert seen == [("kirankishoreV-07/uptime-kuma", "kuma"), ("kirankishoreV-07/PIPELINE_CHECK", "default")]
    assert "kuma" not in repr(r) and "default" not in repr(r)
    assert GitHubRouter({}, client=Fake).configured is False


def test_a_403_token_falls_back_to_another_configured_token(monkeypatch):
    from guardian.trigger.github import GitHubRouter
    calls = []

    class Fake:
        def __init__(self, token):
            self.token = token

        def set_status(self, repo, sha, status, target_url=None):
            calls.append(self.token)
            if self.token == "old":
                raise RuntimeError("status update failed with 403: Resource not accessible by personal access token")
    env = {"GUARDIAN_GITHUB_TOKEN": "old", "GUARDIAN_GITHUB_TOKEN__ME__OTHER": "new"}
    r = GitHubRouter(env, client=Fake)
    r.set_status("me/app", "a" * 40, {"state": "success", "context": "c"})
    assert calls == ["old", "new"]
    r.set_status("me/app", "a" * 40, {"state": "success", "context": "c"})
    assert calls == ["old", "new", "new"]  # the token that worked is remembered for this repo
    calls.clear()

    class AllFail(Fake):
        def set_status(self, *a, **k):
            raise RuntimeError("status update failed with 403")
    import pytest
    with pytest.raises(RuntimeError, match="403"):
        GitHubRouter(env, client=AllFail).set_status("me/x", "a" * 40, {"state": "success", "context": "c"})


def test_a_reused_run_reposts_its_result_to_github(tmp_path):
    """Found live: a post failed (403), the token was fixed, the workflow was re-run on the same commit, and the reused
    result was never posted. Reuse must post the stored result again (statuses/comments are idempotent)."""
    gh = Recorder()
    svc, _ = _svc(tmp_path, gh=gh, verdict="allow")
    svc.handle(_event())
    gh.statuses.clear(); gh.comments.clear()
    res = svc.handle(_event())
    assert res["status"] == "reused"
    assert ("b" * 40, "guardian/scan", "success") in gh.statuses and gh.comments
