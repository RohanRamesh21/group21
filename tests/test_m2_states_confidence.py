"""M2: per-stage run states and evidence-based confidence (GUARDIAN_FINAL_PLAN.md §10.4, §12.2)."""
import pytest

from guardian.scoring.confidence import confidence


def _vuln(**kw):
    f = {"kind": "vulnerability", "label": "introduced", "level": "high", "severity": "high",
         "component": "x@1.0.0", "version": "1.0.0",
         "evidence": {"advisory": "GHSA-1", "file": "package-lock.json", "lockfile_line": 10, "sources": ["osv", "grype"],
                      "severity_by_source": {"osv": "high", "grype": "high"}}}
    f.update(kw)
    return f


CTX = {"incomplete": [], "intel_errors": []}


def test_complete_vulnerability_evidence_is_high_confidence():
    c = confidence(_vuln(), CTX)
    assert c["band"] == "high" and c["missing"] == [] and set(c["dimensions"]) == {
        "collection", "applicability", "freshness", "contradictions", "evidence"}


def test_scanner_failure_lowers_collection():
    c = confidence(_vuln(), {"incomplete": ["vulnerabilities/grype: failed"], "intel_errors": []})
    assert c["dimensions"]["collection"]["status"] == "weak" and c["band"] == "medium"


def test_unresolved_version_is_missing_applicability():
    c = confidence(_vuln(version=""), CTX)
    assert c["dimensions"]["applicability"]["status"] == "missing" and c["band"] == "low"
    assert any("version" in m for m in c["missing"])


def test_stale_or_missing_exploit_data_is_weak_freshness():
    assert confidence(_vuln(), {"incomplete": [], "intel_errors": ["EPSS unreachable"]})["dimensions"]["freshness"]["status"] == "weak"


def test_severity_disagreement_is_a_contradiction():
    f = _vuln()
    f["evidence"]["severity_by_source"] = {"osv": "critical", "grype": "medium"}
    assert confidence(f, CTX)["dimensions"]["contradictions"]["status"] == "weak"


def test_missing_lockfile_location_weakens_evidence():
    f = _vuln()
    f["evidence"].update(file=None, lockfile_line=None)
    assert confidence(f, CTX)["dimensions"]["evidence"]["status"] in ("weak", "missing")


def test_registry_redirect_needs_no_advisory():
    f = {"kind": "supply_chain", "type": "source_change", "label": "introduced", "level": "critical", "severity": "critical",
         "component": ".npmrc", "evidence": {"file": ".npmrc", "lockfile_line": 1, "detector": "D4"}}
    c = confidence(f, CTX)
    assert c["band"] == "high"
    assert c["dimensions"]["applicability"]["status"] == "not_applicable"
    assert c["dimensions"]["contradictions"]["status"] == "not_applicable"


def test_ci_finding_requires_file_and_line():
    f = {"kind": "ci_image", "label": "introduced", "level": "medium", "severity": "medium", "component": "a@v1",
         "evidence": {"file": ".github/workflows/a.yml", "line": None}}
    assert confidence(f, CTX)["dimensions"]["evidence"]["status"] == "weak"


def test_score_report_attaches_confidence_and_flags_low_confidence_blockers(monkeypatch):
    from guardian.scoring import intel, score
    monkeypatch.setattr(intel, "osv_details", lambda ids: {i: {"aliases": []} for i in ids})
    monkeypatch.setattr(intel, "epss", lambda c: ({}, None))
    monkeypatch.setattr(intel, "kev", lambda: ({}, None))
    rep = {"inventory": [], "suspicious_changes": [], "ci_image": [], "headline": {},
           "vulnerabilities": [{"key": "npm:x@#GHSA-1", "id": "GHSA-1", "name": "x", "version": "", "severity": "high",
                                "label": "introduced", "runtime": True, "direct": True, "fixed": [], "sources": ["osv"]}]}
    s = score.score_report(rep)
    f = s["findings"][0]
    assert f["confidence"]["band"] == "low"
    assert any(r.startswith("needs human check") for r in s["reasons"])


# ---------- run states ----------

def test_stage_states_reflect_errors():
    from guardian.scoring.states import stages
    h = {"inventory": {"packages": 10}, "syft_error": None,
         "vulnerabilities": {"errors": {"grype": "failed"}, "scanners": {"osv": 3, "grype": 0}},
         "ci_image": {"errors": {}, "actions": {"total": 0}, "images": {"total": 0}}, "suspicious_error": None}
    st = {s["id"]: s for s in stages(h, compared=True, scored=True)}
    assert st["snapshot"]["status"] == "complete"
    assert st["vulnerabilities"]["status"] == "partial" and "grype" in st["vulnerabilities"]["detail"]
    assert st["ci_image"]["status"] == "not_applicable"
    assert st["compare"]["status"] == "complete"
    assert st["scoring"]["status"] == "complete"


@pytest.mark.parametrize("compared,status", [(False, "skipped"), (True, "complete")])
def test_compare_stage_skipped_without_base(compared, status):
    from guardian.scoring.states import stages
    h = {"inventory": {"packages": 0}, "vulnerabilities": {"errors": {}, "scanners": {}},
         "ci_image": {"errors": {}, "actions": {"total": 1}, "images": {"total": 0}}}
    st = {s["id"]: s for s in stages(h, compared=compared, scored=False)}
    assert st["compare"]["status"] == status and st["scoring"]["status"] == "failed"
    assert st["discover"]["status"] == "not_applicable"
