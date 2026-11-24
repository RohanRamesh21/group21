from guardian.scoring.contextual.delta import before_after
from guardian.scoring.score import score_report
from tests.contextual_scoring.conftest import pkg, vuln


def _scored(inv, vulns, sus=()):
    return score_report({"inventory": inv, "vulnerabilities": vulns, "suspicious_changes": list(sus), "ci_image": []})


def _with_kev(monkeypatch):
    """GHSA-1 is exploited in the wild: SSVC gives Act/critical, so the risk index is non-zero."""
    from guardian.scoring import intel
    monkeypatch.setattr(intel, "osv_details", lambda ids: {i: {"aliases": ["CVE-1"] if i == "GHSA-1" else [], "cvss_v3": None, "cvss_v4": None,
                                                              "severity_label": None} for i in ids})
    monkeypatch.setattr(intel, "kev", lambda: ({"CVE-1": {"date_added": "2026-01-01", "ransomware": "Unknown", "name": "x"}}, None))


def _before():
    return _scored([pkg("node_modules/foo", "foo", "1.2.0"), pkg("node_modules/keep", "keep", "1.0.0")],
                   [vuln("foo", "1.2.0", "GHSA-1", "critical", ["1.2.4"], label="introduced"), vuln("keep", "1.0.0", "GHSA-9", "high", ["1.0.1"])])


def test_verified_when_target_gone_nothing_new_and_tests_pass(monkeypatch):
    _with_kev(monkeypatch)
    after = _scored([pkg("node_modules/foo", "foo", "1.2.4"), pkg("node_modules/keep", "keep", "1.0.0")], [vuln("keep", "1.0.0", "GHSA-9", "high", ["1.0.1"])])
    d = before_after(_before(), after, ["foo@1.2.0#GHSA-1"], "pass")
    assert d["verified"] and d["targets"][0]["status"] == "remediated" and d["failed_conditions"] == []
    assert d["risk_index"]["after"] < d["risk_index"]["before"] and d["levels_after"]["critical"] == 0
    assert [r["id"] for r in d["remaining_risk"]] == ["keep@1.0.0#GHSA-9"]   # what is still open is listed, not hidden


def test_matched_by_identity_not_id_when_version_changes_but_still_vulnerable(monkeypatch):
    _with_kev(monkeypatch)
    after = _scored([pkg("node_modules/foo", "foo", "1.2.1")], [vuln("foo", "1.2.1", "GHSA-1", "critical", ["1.2.4"])])
    d = before_after(_before(), after, ["foo@1.2.0#GHSA-1"], "pass")
    assert not d["verified"] and d["targets"][0]["status"] == "unchanged"


def test_not_verified_when_a_new_high_appears(monkeypatch):
    _with_kev(monkeypatch)
    after = _scored([pkg("node_modules/foo", "foo", "1.2.4")], [vuln("keep", "1.0.0", "GHSA-9", "high"), vuln("foo", "1.2.4", "GHSA-NEW", "high")])
    d = before_after(_before(), after, ["foo@1.2.0#GHSA-1"], "pass")
    assert not d["verified"] and "no_new_high" in d["failed_conditions"] and d["new_findings"][0]["id"].endswith("GHSA-NEW")


def test_new_high_severity_advisory_counts_even_when_ssvc_says_track():
    after = _scored([pkg("node_modules/foo", "foo", "1.2.4")], [vuln("foo", "1.2.4", "GHSA-NEW", "critical")])
    assert after["findings"][0]["level"] == "low"   # no exploit data: Track
    d = before_after(_before(), after, [], "pass")
    assert "no_new_high" in d["failed_conditions"]


def test_not_verified_when_a_hard_signal_is_recreated():
    sus = [{"detector": "D1", "type": "typosquat", "component": "pkg:npm/axois@1.0.0", "summary": "x", "severity": "high", "hard_signal": False, "label": "introduced"}]
    after = _scored([pkg("node_modules/foo", "foo", "1.2.4")], [], sus)
    d = before_after(_before(), after, ["foo@1.2.0#GHSA-1"], "pass")
    assert "no_hard_signal_recreated" in d["failed_conditions"] and not d["verified"]


def test_not_verified_when_build_failed_or_not_run():
    after = _scored([pkg("node_modules/foo", "foo", "1.2.4")], [vuln("keep", "1.0.0", "GHSA-9", "high")])
    for result, shown in (("fail", "fail"), (None, "not_run")):
        d = before_after(_before(), after, ["foo@1.2.0#GHSA-1"], result)
        assert not d["verified"] and "build_tests_pass" in d["failed_conditions"] and d["build_tests"] == shown


def test_unknown_target_id_is_not_verified():
    d = before_after(_before(), _before(), ["nope@1#X"], "pass")
    assert not d["verified"] and any("unknown target ids" in c for c in d["failed_conditions"])
