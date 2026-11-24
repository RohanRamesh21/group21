"""M6: Guardian report (HTML + JSON) built from one run folder; every section present; pending parts labelled."""
import json

import pytest

from guardian import approval as ap
from guardian import universal as u


@pytest.fixture
def run(tmp_path, monkeypatch):
    import subprocess

    from guardian.scoring import intel
    monkeypatch.setattr(u, "run_syft", lambda src, out: ({}, None))
    monkeypatch.setattr(u, "osv_api", lambda inv: ([], None))
    monkeypatch.setattr(u, "grype_all", lambda sbom: ([], None))
    monkeypatch.setattr(intel, "epss", lambda c: ({}, None))
    monkeypatch.setattr(intel, "kev", lambda: ({}, None))
    repo = tmp_path / "repo"
    repo.mkdir()
    git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "README.md").write_text("x")
    subprocess.run(git + ["add", "-A"], check=True)
    subprocess.run(git + ["commit", "-qm", "base"], check=True)
    (repo / ".npmrc").write_text("registry=http://127.0.0.1:4873/\n<script>alert(1)</script>\n")
    subprocess.run(git + ["add", "-A"], check=True)
    subprocess.run(git + ["commit", "-qm", "head"], check=True)
    out = tmp_path / "out"
    u.check_any(repo, "HEAD~1", "HEAD", out, "app")
    return out


SECTIONS = ["run", "inventory", "findings", "investigation", "remediation", "validation", "before_after", "remaining_risk",
            "confidence", "audit"]


def test_report_has_every_section_and_marks_pending_parts(run):
    from guardian.report.build import build
    rep = build(run)
    assert list(rep["sections"]) == SECTIONS
    s = rep["sections"]
    assert s["run"]["head_sha"] and s["run"]["capability_level"] == "L2" and s["run"]["complete"] is True
    assert s["findings"]["items"] and all("confidence" in f and "evidence" in f for f in s["findings"]["items"])
    assert s["investigation"]["status"] == "pending" and "API key" in s["investigation"]["reason"]
    assert s["remediation"]["status"] == "not_started" and s["validation"]["status"] == "not_started"
    assert s["audit"]["chain_ok"] is True


def test_report_includes_plan_approval_and_accepted_risks(run):
    from guardian.report.build import build
    plan = {"base_sha": "a" * 40, "head_sha": "b" * 40, "candidates": [{"id": "FIX-1", "type": "revert_change"}],
            "patch": {"patch_sha256": "c" * 64, "files": [".npmrc"]}}
    (run / "fix-plan.json").write_text(json.dumps(plan))
    ap.decide(run, plan, "approve", approver="kiran", reason="ok", ttl_seconds=3600, policy_sha256="d" * 64, profile_sha256="e" * 64)
    ap.accept_risk(run, "x@1#GHSA-1", owner="kiran", scope="PR", reason="no fix yet", ttl_seconds=3600)
    s = build(run)["sections"]
    assert s["remediation"]["status"] == "approved" and s["remediation"]["approval"]["approver"] == "kiran"
    assert s["remaining_risk"]["accepted"][0]["finding_id"] == "x@1#GHSA-1"
    assert s["run"]["capability_level"] == "L3"


def test_write_produces_matching_json_and_escaped_html(run):
    from guardian.report.build import write
    paths = write(run)
    data = json.loads(open(paths["json"]).read())
    html = open(paths["html"]).read()
    assert data["run_id"] in html and "<script>alert(1)</script>" not in html
    assert "Guardian report" in html and all(f'id="{s}"' in html for s in SECTIONS)


def test_cli_report_writes_both_files(run, capsys):
    from guardian import cli
    assert cli.main(["report", "--out", str(run)]) == 0
    assert (run / "report.json").exists() and (run / "report.html").exists()


def test_cli_approve_requires_reason(run, capsys):
    from guardian import cli
    (run / "fix-plan.json").write_text(json.dumps({"base_sha": "a" * 40, "head_sha": "b" * 40, "candidates": [],
                                                   "patch": {"patch_sha256": "c" * 64}}))
    assert cli.main(["approve", "--out", str(run), "--approver", "kiran", "--reason", "diff reviewed"]) == 0
    assert ap.latest_approval(run)["approver"] == "kiran"
    with pytest.raises(SystemExit):
        cli.main(["approve", "--out", str(run), "--approver", "kiran"])


def test_run_endpoint_serves_the_report_model(run, monkeypatch):
    from fastapi.testclient import TestClient

    from guardian import server
    monkeypatch.setattr(server, "_check_dir", lambda project: run)
    r = TestClient(server.app).get("/api/run").json()
    assert list(r["sections"])[0] == "run" and r["sections"]["run"]["stages"]
