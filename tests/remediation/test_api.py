"""HTTP API: the approval gate over HTTP. Lockfile and rescan are injected; no network, no scanners."""
import time

import pytest
from fastapi.testclient import TestClient

from guardian.remediation import api, validate
from guardian.remediation.service import Remediator
from tests.remediation.conftest import fake_providers, have_git
from tests.remediation.test_apply_validate import fake_lock, rescan_without

pytestmark = pytest.mark.skipif(not have_git(), reason="git is required")


@pytest.fixture
def client(ctx, tmp_path, monkeypatch):
    import guardian.remediation.store as st
    monkeypatch.setattr(st, "BASE", tmp_path / "rem")
    monkeypatch.setattr(api, "BASE", tmp_path / "rem")
    monkeypatch.setattr(api.RemediationContext, "load", classmethod(lambda cls, project=None: ctx))
    monkeypatch.setattr(api.service, "Remediator", lambda c, s, providers=None: Remediator(c, s, fake_providers()))
    api.RUNS.clear()
    api.JOBS.clear()
    real = validate.validate
    monkeypatch.setattr(api.validate, "validate", lambda store, pid, c, tier="tier1", **k: real(
        store, pid, c, tier=tier, lockfile=fake_lock, rescan=rescan_without(c, set(store.get_plan(pid).finding_ids)),
        tier2=lambda repo: {"status": "pass", "steps": []}))
    return TestClient(api.router.routes and __import__("guardian.server", fromlist=["app"]).app)


def wait(client, run_id, key="status", want="done", t=10):
    end = time.time() + t
    while time.time() < end:
        d = client.get(f"/api/remediation/{run_id}").json()
        if d[key] == want:
            return d
        time.sleep(0.05)
    raise AssertionError(d)


def test_run_decide_apply_report_over_http(client):
    r = client.post("/api/remediation/runs", json={"top_n": 2, "mode": "rule_based"})
    assert r.status_code == 200
    d = wait(client, r.json()["run_id"])
    run = r.json()["run_id"]
    assert d["plans"] and d["meta"]["mode_used"] == "rule_based" and all(p["status"] == "proposed" for p in d["plans"])
    plan = next(p for p in d["plans"] if p["patch"]["supported"] and p["type"] == "upgrade_to_fixed")
    pid = plan["id"]
    # apply before approval is refused (409) and nothing runs
    assert client.post(f"/api/remediation/{run}/plans/{pid}/apply", json={"tier": "tier1"}).status_code == 409
    # decision needs a reviewer
    assert client.post(f"/api/remediation/{run}/plans/{pid}/decision", json={"decision": "approve", "reviewer": ""}).status_code == 409
    ok = client.post(f"/api/remediation/{run}/plans/{pid}/decision", json={"decision": "approve", "reviewer": "Dana", "note": "ok"})
    assert ok.status_code == 200 and ok.json()["plan_sha256"] == plan["plan_sha256"]
    assert client.post(f"/api/remediation/{run}/plans/{pid}/decision", json={"decision": "reject", "reviewer": "Dana"}).status_code == 409  # already decided
    assert client.post(f"/api/remediation/{run}/plans/{pid}/apply", json={"tier": "tier1"}).status_code == 200
    end = time.time() + 15
    while time.time() < end and client.get(f"/api/remediation/{run}/plans/{pid}/validation").status_code == 404:
        time.sleep(0.1)
    v = client.get(f"/api/remediation/{run}/plans/{pid}/validation").json()
    assert v["outcome"] == "remediated_tests_not_run" and v["delta"]["conditions"]["target_resolved"]
    rep = client.get(f"/api/remediation/{run}/report").json()
    e = next(x for x in rep["plans"] if x["plan_id"] == pid)
    assert e["approval"]["reviewer"] == "Dana" and e["validation"]["build_tests"] == "not_run" and rep["audit_trail"]["events"]
    md = client.get(f"/api/remediation/{run}/report?fmt=md").text
    assert "Not verified" in md and "FORECAST" in md
    assert client.get(f"/api/remediation/{run}/report?fmt=html").status_code == 200


def test_unknown_run_and_bad_mode(client):
    assert client.get("/api/remediation/REM-NOPE").status_code == 404
    assert client.post("/api/remediation/runs", json={"mode": "magic"}).status_code == 400
    assert client.get("/api/remediation/runs").status_code == 200


def test_evidence_endpoint_serves_cited_records(client):
    run = client.post("/api/remediation/runs", json={"top_n": 1}).json()["run_id"]
    d = wait(client, run)
    eid = d["plans"][0]["evidence_ids"][0]
    e = client.get(f"/api/remediation/{run}/evidence/{eid}")
    assert e.status_code == 200 and e.json()["sha256"] and client.get(f"/api/remediation/{run}/evidence/E-nope").status_code == 404
