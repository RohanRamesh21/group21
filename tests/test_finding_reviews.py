"""Saved-report and API regressions for finding reviews."""
from __future__ import annotations

import json
from datetime import date

import pytest
from fastapi.testclient import TestClient

from guardian import reviews, server
from guardian.scoring import score


@pytest.fixture
def saved_scan(tmp_path, monkeypatch):
    directory = tmp_path / "check"
    directory.mkdir()
    monkeypatch.setattr(server, "_check_dir", lambda project: directory)
    monkeypatch.setattr(server, "REVIEW_DB", tmp_path / "reviews.sqlite3")
    monkeypatch.setattr(score.intel, "osv_details", lambda ids: {vid: {"aliases": []} for vid in ids})
    monkeypatch.setattr(score.intel, "epss", lambda _: ({}, None))
    monkeypatch.setattr(score.intel, "kev", lambda: ({}, None))

    def publish(head="a", *, line=3, imports=1, repo="local-app"):
        commit = head * 40
        report = {
            "repo": str(tmp_path / repo),
            "headline": {"app": "fixture", "base_commit_full": "0" * 40, "head_commit_full": commit, "verdict": "block"},
            "suspicious_changes": [
                {"detector": "D13", "type": "undeclared_dependency", "component": "pypi:gdb", "label": "pre_existing",
                 "severity": "low", "file": "pretty.py", "line": line,
                 "summary": f"'gdb' is imported ({imports}x, e.g. pretty.py:{line}) but no manifest declares it"},
                {"detector": "D7", "type": "lockfile_tamper", "component": "fixture@1.0.0", "label": "introduced",
                 "severity": "critical", "file": "package-lock.json", "line": 8, "hard_signal": True,
                 "summary": "The integrity hash in the lockfile changed."},
            ],
        }
        rp, sp = directory / f"report-{head}.json", directory / f"scores-{head}.json"
        rp.write_text(json.dumps(report))
        sp.write_text(json.dumps(score.score_report(report)))
        (directory / "latest.json").write_text(json.dumps({"path": str(rp), "scores": str(sp)}))

    publish()
    return TestClient(server.app), publish


def _finding(client, detector="D13"):
    response = client.get("/api/scores")
    assert response.status_code == 200
    return next(f for f in response.json()["findings"] if f["evidence"]["detector"] == detector)


def _review(finding: dict, action="challenge", **fields):
    disposition = finding["review"]
    payload = {"revision": disposition["revision"], "previous_id": disposition["latest_id"], "action": action,
               "reviewer": "Maintainer", "rationale": "GDB supplies the module to the pretty-printer.", **fields}
    return f"/api/reviews/{disposition['key']}", payload


def test_review_persists_across_line_moves_and_reopens_on_evidence_change(saved_scan):
    client, publish = saved_scan
    finding = _finding(client)
    url, payload = _review(finding)
    response = client.post(url, json=payload)
    assert response.status_code == 201
    assert response.json()["review"]["status"] == "challenged"

    publish("b", line=29)
    moved = _finding(client)
    assert moved["review"]["key"] == finding["review"]["key"]
    assert moved["review"]["status"] == "challenged"
    assert moved["review"]["revision"] != finding["review"]["revision"]
    assert client.post(url, json=payload).status_code == 409

    publish("c", line=29, imports=2)
    reopened = _finding(client)
    assert reopened["review"]["status"] == "reopened"
    assert reopened["review"]["reason"] == "evidence_changed"
    exported = client.get(url, params={"download": True})
    assert 'attachment; filename="guardian-review-' in exported.headers["content-disposition"]
    result = exported.json()
    assert result["verdict"] == "block"
    assert result["head_commit"] == "c" * 40
    assert result["finding"]["evidence"]["lockfile_line"] == 29
    assert result["history"][0]["finding"] == {k: v for k, v in finding.items() if k != "review"}
    assert result["history"][0]["head_commit"] == "a" * 40

    url, confirmed = _review(reopened, "confirm")
    assert client.post(url, json=confirmed).json()["review"]["status"] == "confirmed"
    assert client.post(url, json=confirmed).status_code == 409
    assert [row["action"] for row in client.get(url).json()["history"]] == ["confirm", "challenge"]


def test_deferral_expiry_and_hard_floor_are_independent(saved_scan, monkeypatch):
    client, _ = saved_scan
    monkeypatch.setattr(reviews, "today", lambda: date(2026, 11, 24))
    finding = _finding(client, "D7")
    url, payload = _review(finding, "defer", owner="Dependency team", due_date="2026-11-24")
    assert client.post(url, json={**payload, "owner": " "}).status_code == 422
    assert client.post(url, json={**payload, "due_date": "2026-11-23"}).status_code == 422
    assert client.post(url, json=payload).status_code == 201
    response = client.get("/api/scores").json()
    assert response["final_verdict"] == response["verdict"] == "block"
    deferred = _finding(client, "D7")
    assert deferred["review"]["status"] == "deferred"
    assert deferred["floor"] == finding["floor"]

    monkeypatch.setattr(reviews, "today", lambda: date(2026, 11, 25))
    assert _finding(client, "D7")["review"]["reason"] == "deferral_expired"


def test_review_cannot_cross_repository_scope(saved_scan):
    client, publish = saved_scan
    url, payload = _review(_finding(client))
    assert client.post(url, json=payload).status_code == 201
    publish(repo="different-app")
    assert _finding(client)["review"]["status"] == "unreviewed"
    assert client.get(url).json()["history"] == []
    assert client.post(url, json=payload).status_code == 409


def test_same_advisory_reopens_after_integrity_or_exploitation_change():
    report = {"headline": {"head_commit_full": "a" * 40}, "inventory": [
        {"key": "node_modules/example", "name": "example", "version": "1.0.0", "ecosystem": "npm",
         "integrity": "first-digest", "source_file": "package-lock.json", "found_by": "guardian npm lockfile parser"}],
        "vulnerabilities": [{"key": "example@1.0.0#TEST-01", "component_key": "node_modules/example", "name": "example", "ecosystem": "npm"}],
    }
    finding = {"kind": "vulnerability", "id": "example@1.0.0#TEST-01", "component": "example@1.0.0", "evidence": {
        "advisory": "TEST-01", "reachability": {"status": "imported", "evidence": ["main.js:10"]}, "kev": None,
    }}
    original, = reviews.targets(report, [finding], "local:test")
    finding["evidence"]["reachability"]["evidence"] = ["main.js:20"]
    moved, = reviews.targets(report, [finding], "local:test")
    assert moved.evidence_digest == original.evidence_digest

    finding["evidence"]["kev"] = {"date_added": "2026-11-24"}
    active, = reviews.targets(report, [finding], "local:test")
    assert active.key == original.key
    assert active.evidence_digest != original.evidence_digest

    report["inventory"][0]["integrity"] = "different-digest"
    replaced, = reviews.targets(report, [finding], "local:test")
    assert replaced.key == original.key
    assert replaced.evidence_digest != active.evidence_digest


def test_scanning_again_reuses_repository_scope_but_zip_uploads_are_independent(tmp_path):
    first, second = tmp_path / "job1", tmp_path / "job2"
    url = {"kind": "git", "url": "https://github.com/team/app"}
    assert reviews.repository_scope({}, first, url) == reviews.repository_scope({}, second, {**url, "url": url["url"] + ".git/"})

    source = str(tmp_path / "app")
    path_project = {"kind": "path", "path": source}
    assert reviews.repository_scope({}, first, path_project) == reviews.repository_scope({"repo": source}, second, None)
    assert reviews.repository_scope({}, first, {"kind": "zip"}) != reviews.repository_scope({}, second, {"kind": "zip"})
