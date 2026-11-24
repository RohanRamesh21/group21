"""Scoring (floors, SSVC, AHP, explanation checker) and project-intake safety."""
import io
import zipfile

import pytest

from guardian import projects
from guardian.scoring import intel
from guardian.scoring.explain import check as check_explanation
from guardian.scoring.score import AHP, ssvc, score_report


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setattr(intel, "osv_details", lambda ids: {i: {"aliases": [], "cvss_v3": None, "cvss_v4": None, "severity_label": None} for i in ids})
    monkeypatch.setattr(intel, "epss", lambda cves: ({}, None))
    monkeypatch.setattr(intel, "kev", lambda: ({}, None))


def _report(vulns=(), sus=()):
    inv = [{"key": "node_modules/axois", "name": "axois", "version": "1.0.0", "direct": True, "runtime": True, "dev": False,
            "lockfile_line": 10, "resolved": "http://127.0.0.1:4873/axois.tgz"}]
    return {"inventory": inv, "vulnerabilities": list(vulns), "suspicious_changes": list(sus), "ci_image": []}


def test_ahp_weights_are_consistent():
    assert AHP["consistent"] and AHP["consistency_ratio"] < 0.10
    assert abs(sum(AHP["weights"].values()) - 1) < 1e-6


def test_malicious_package_is_critical_and_blocks():
    v = {"name": "axois", "version": "1.0.0", "id": "MAL-1", "key": "axois@1.0.0#MAL-1", "severity": "low", "fixed": [],
         "malicious": True, "direct": True, "runtime": True, "label": "introduced", "summary": "", "sources": ["osv"]}
    s = score_report(_report(vulns=[v]))
    f = s["findings"][0]
    assert f["level"] == "critical" and f["decision"] == "Act" and f["floor"]
    assert s["verdict"] == "block"


def test_floor_survives_low_severity_and_combo_escalates():
    sus = [{"detector": "D1", "type": "typosquat", "component": "pkg:npm/axois@1.0.0", "summary": "", "severity": "low", "hard_signal": False, "label": "introduced"},
           {"detector": "D2", "type": "new_install_script", "component": "axois@1.0.0", "summary": "", "severity": "low", "hard_signal": True, "label": "introduced"}]
    s = score_report(_report(sus=sus))
    assert all(f["level"] == "critical" for f in s["findings"])  # look-alike + install script = critical, despite "low"
    assert s["verdict"] == "block"
    assert s["contextual"]["confidence_ahp"]["consistent"]
    assert s["contextual"]["fix_ahp"]["consistent"]
    assert all(f["confidence"]["band"] in {"high", "medium", "low"} for f in s["findings"])
    assert {f["rank_stability"]["baseline_rank"] for f in s["findings"]} == {1, 2}
    assert all(fix["approval_required"] and fix["forecast"] for f in s["findings"] for fix in f["fix_candidates"])


def test_ssvc_dev_only_lowers_decision():
    assert ssvc("active", "yes", "total", "essential")[0] == "Act"
    assert ssvc("active", "yes", "total", "minimal")[0] == "Attend"
    assert ssvc("none", "no", "partial", "essential")[0] == "Track"


def test_pre_existing_findings_do_not_block():
    v = {"name": "axois", "version": "1.0.0", "id": "GHSA-x", "key": "axois@1.0.0#GHSA-x", "severity": "critical", "fixed": ["1.0.1"],
         "malicious": False, "direct": True, "runtime": True, "label": "pre_existing", "summary": "", "sources": ["osv"]}
    assert score_report(_report(vulns=[v]))["verdict"] == "allow"


def test_explanation_checker_drops_invented_numbers():
    card = {"title": "x@1.0.0: GHSA-abcd", "score": 73.9, "contributions": [{"factor": "impact"}], "evidence": {"advisory": "GHSA-abcd"}}
    res = check_explanation({"headline": "ok", "sentences": [
        {"text": "It scored 73.9 because of impact.", "cites": ["score", "impact"]},
        {"text": "EPSS is 0.97 so it is urgent.", "cites": ["exploitation"]}]}, card)
    assert [s["text"] for s in res["sentences"]] == ["It scored 73.9 because of impact."]
    assert res["sentences"][0]["status"] == "verified" and len(res["rejected"]) == 1


def test_zip_path_traversal_rejected(tmp_path):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("../../evil.txt", "x")
    p = tmp_path / "e.zip"
    p.write_bytes(b.getvalue())
    with pytest.raises(ValueError):
        projects.safe_extract(p, tmp_path / "out")
    assert not (tmp_path.parent / "evil.txt").exists()


@pytest.mark.parametrize("url", ["http://github.com/a/b", "https://evil.example.com/a/b", "https://u:p@github.com/a/b",
                                 "https://github.com/a", "https://github.com/a/b?x=1"])
def test_git_url_rules(url):
    with pytest.raises(ValueError):
        projects.validate_git_url(url)
    assert projects.validate_git_url("https://github.com/louislam/uptime-kuma")
