from __future__ import annotations

import importlib
import json
import time
from types import SimpleNamespace

from fastapi.testclient import TestClient

from guardian import projects, server, universal
from guardian.agents.board import Board
from guardian.agents.realworld import ADVISORY_MAX_AGE_SECONDS, RealFacts
from guardian.agents.tools import ToolRegistry
from guardian.store.evidence import EvidenceStore


def test_osv_evidence_requires_a_complete_batch(monkeypatch):
    import requests

    response = SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"results": [{}]})
    monkeypatch.setattr(requests, "post", lambda *_, **__: response)
    monkeypatch.setattr(universal, "_osv_get", lambda _: None)
    components = [{"ecosystem": "npm", "name": "one", "version": "2.0.0"},
                  {"ecosystem": "npm", "name": "two", "version": "3.0.0"}]
    receipt = []
    assert universal.osv_api(components, checked=receipt)[1]
    assert receipt == []
    response.json = lambda: {"results": [{}, {"vulns": [{"id": "TEST-1"}]}]}
    found, error = universal.osv_api(components, checked=receipt)
    assert error is None
    assert receipt == [{**components[0], "advisories": []}, {**components[1], "advisories": ["TEST-1"]}]
    assert found[0]["ids"] == ["TEST-1"]


def test_exact_npm_scan_evidence_replaces_network_lookup(tmp_path):
    facts = RealFacts.__new__(RealFacts)
    facts.head = "a" * 40
    facts.store = EvidenceStore(tmp_path)
    facts._memo = {}
    facts.checked_advisories = set()
    facts._changed_packages = lambda: {("one", "2.0.0")}
    facts._request = lambda *_, **__: (_ for _ in ()).throw(AssertionError("query should have been reused"))
    receipt = {
        "schema": 1, "source": "osv.dev/querybatch", "head": facts.head, "queried_at": int(time.time()),
        "queries": [{"ecosystem": "npm", "name": "one", "version": "1.0.0", "advisories": ["OLD"]},
                    {"ecosystem": "maven", "name": "one", "version": "2.0.0", "advisories": ["WRONG"]},
                    {"ecosystem": "npm", "name": "one", "version": "2.0.0", "advisories": ["MAL-TEST-1"]}],
    }
    assert facts.reuse_scan_advisories({**receipt, "head": "b" * 40}) == {}
    assert facts.reuse_scan_advisories({**receipt, "queried_at": int(time.time()) - ADVISORY_MAX_AGE_SECONDS - 1}) == {}
    assert set(facts.reuse_scan_advisories(receipt)) == {"pkg:pkg:npm/one@2.0.0"}
    finding, = facts.iter_signals("D0")
    assert finding["hard_signal"]
    assert finding["summary"] == "MAL-TEST-1"


def test_question_requires_specialist_and_independent_skeptic_review(tmp_path):
    report = {
        "headline": {"verdict": "review"},
        "suspicious_changes": [
            {"type": "unusual_release", "component": "package", "label": "introduced", "severity": "medium", "detector": "D21"},
            {"type": "extra_repository", "component": "ci", "label": "introduced", "severity": "medium"},
            {"type": "known", "component": "old", "label": "pre_existing", "severity": "critical"},
        ],
    }
    board = Board("RUN-test", "base", "head", focused=True)
    store = EvidenceStore(tmp_path)
    registry = ToolRegistry(board, store, {"scan_report": report}, lambda *_: "")
    registry.dispatch_focused_review()
    assert len(board.tasks) == 2
    task = next(t for t in board.tasks.values() if t.assignee == "hunter")
    question, = task.scope
    other, = set(board.review_questions) - {question}
    eid = board.review_questions[question]["evidence_id"]
    assert "REJECTED" in registry.call("hunter", "review_question", {"id": other}, {"task_id": task.id})

    def post(role, kind, recipient, **extra):
        return registry.call(role, "post_message", {"recipient": recipient, "kind": kind, "claim": "Reviewed evidence.",
                                                   "evidence_ids": [eid], **extra},
                             {"task_id": task.id} if role == "hunter" else {})

    assert post("hunter", "hypothesis", "skeptic").startswith("ACCEPTED")
    hypothesis = board.messages[-1].id
    assert post("skeptic", "corroborate", "lead", in_reply_to=hypothesis).startswith("ACCEPTED")
    assert question in board.coverage_gaps()
    assert post("hunter", "task_result", "lead").startswith("ACCEPTED")
    assert post("skeptic", "corroborate", "lead", in_reply_to=hypothesis).startswith("ACCEPTED")
    assert question not in board.coverage_gaps()
    assert post("skeptic", "dispute", "lead", in_reply_to=hypothesis).startswith("ACCEPTED")
    assert question in board.coverage_gaps()


def test_project_workflow_waits_for_scan_and_keeps_token_private(tmp_path, monkeypatch):
    run_module = importlib.import_module("guardian.agents.run")
    monkeypatch.setattr(server.config, "provider", lambda: "deepseek")
    monkeypatch.setattr(server, "RUNS", {})
    monkeypatch.setattr(server, "PROJECT_RUNS", {})
    reports = []
    job = {"id": "test-project", "status": "running"}
    report = {"repo": str(tmp_path), "headline": {"base_commit_full": "a", "head_commit_full": "b"}}
    monkeypatch.setattr(projects, "start_example", lambda _: job["id"])
    monkeypatch.setattr(projects, "get", lambda _: job)
    monkeypatch.setattr(server, "_latest", lambda _: (report, None))
    monkeypatch.setattr(run_module, "run", lambda *_, **kwargs: reports.append(kwargs["scan_report"]))
    client = TestClient(server.app)
    started = client.post("/api/projects/example", json={"name": "test", "investigate": True}).json()
    assert started["review_token"]
    assert server.RUNS[started["run_id"]].status == "scanning"
    assert reports == []
    project = client.get(f"/api/projects/{job['id']}").json()
    assert project["investigation_run"] == started["run_id"]
    assert "review_token" not in project
    job["status"] = "done"
    response = client.get(f"/api/runs/{started['run_id']}/events")
    states = [json.loads(line[6:]) for line in response.text.splitlines() if line.startswith('data: {"run_id"')]
    assert states[-1]["status"] == "done"
    assert started["review_token"] not in response.text
    assert reports == [report]


def test_related_image_findings_share_one_question(tmp_path):
    rows = [{"type": kind, "file": f"Dockerfile.{arch}", "component": f"ghcr.io/project/compiler:{arch}",
             "label": "introduced", "severity": "medium"}
            for arch in ("x86", "arm") for kind in ("untrusted_image", "image_not_pinned")]
    report = {"headline": {"verdict": "review"}, "ci_image": rows}
    board = Board("RUN-test", "base", "head", focused=True)
    store = EvidenceStore(tmp_path)
    registry = ToolRegistry(board, store, {"scan_report": report}, lambda *_: "")
    registry.dispatch_focused_review()
    question, = board.review_questions.values()
    assert question["component"] == "ghcr.io/project/compiler"
    assert question["observations"] == 4
    assert json.loads(store.content(question["evidence_id"]))["findings"] == sorted(rows, key=lambda f: (f["type"], f["component"]))
