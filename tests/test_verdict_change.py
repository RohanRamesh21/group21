"""Before/after verdict: the PR as submitted vs the PR with the approved fix, rescanned by the same engine."""
from guardian.trigger.github import validation_status
from guardian.validation.validate import verdict_summary


def _f(kind, label="introduced", level="high", fid="x", title="t", severity=None):
    # real shape (scores-*.json): vulnerabilities have kind "vulnerability"; detectors have kind "supply_chain" and
    # their detector name in "type"; CI/image findings keep their own kind
    shape = {"kind": kind} if kind in ("vulnerability", "ci_image") else {"kind": "supply_chain", "type": kind}
    return {**shape, "label": label, "level": level, "id": fid, "title": title, "severity": severity}


BLOCKED = {"verdict": "block", "findings": [
    _f("vulnerability", fid="lodash@4.17.20#GHSA-35jh-r3h4-6jhm"),
    _f("vulnerability", fid="minimist@1.2.5#GHSA-xvch-5gv4-984h", level="critical"),
    _f("vulnerability", fid="axois@1.0.0#MAL-2025-15245", level="critical"),  # a malware record, not an ordinary CVE
    _f("typosquat", level="critical"),
    _f("untrusted_source", level="critical"),
    _f("new_install_script", level="critical"),
    _f("lockfile_tamper", level="critical"),
    _f("source_change", level="critical"),
    _f("action_sha_to_tag", level="medium"),
    _f("new_dependency", level="info"),
    _f("suspicious_update", level="low"),  # "version changed in this PR": after a fix, the safe upgrade itself
    _f("vulnerability", label="pre_existing", fid="jsonata@2.2.0#GHSA-66mm"),
    _f("ci_image", label="pre_existing", level="low"),
]}
FIXED = {"verdict": "allow", "findings": [f for f in BLOCKED["findings"] if f["label"] == "pre_existing"]}


def test_summary_groups_introduced_findings():
    s = verdict_summary(BLOCKED)
    assert s["verdict"] == "block"
    assert s["introduced"] == {"vulnerabilities": 2, "malware_suspicious": 5, "config_ci": 2, "other": 2, "total": 11}
    assert s["high_or_critical"] == 8
    assert s["pre_existing"] == 2  # reported honestly: still in the project, not part of this PR


def test_summary_after_fix_is_clean_but_keeps_pre_existing():
    s = verdict_summary(FIXED)
    assert s["verdict"] == "allow"
    assert s["introduced"]["total"] == 0 and s["high_or_critical"] == 0
    assert s["pre_existing"] == 2


def test_summary_tolerates_missing_scores():
    assert verdict_summary(None)["verdict"] is None
    assert verdict_summary({})["introduced"]["total"] == 0


def test_validation_status_reads_the_real_validate_output():
    # validate() records "executed": True (no "status" key); this used to be posted as "Validation not run"
    st = validation_status({"executed": True, "gate": {"verified": True}})
    assert st["state"] == "success" and st["context"] == "guardian/validation"
    assert validation_status({"executed": True, "gate": {"verified": False, "validation": "failed"}})["state"] == "failure"
    refused = validation_status({"executed": False, "gate": {"verified": False, "reasons": ["approval: no approval has been given"]}})
    assert refused["state"] == "error" and "no approval" in refused["description"]


def test_validation_status_shows_block_to_allow():
    v = {"executed": True, "gate": {"verified": True},
         "verdict_change": {"before": verdict_summary(BLOCKED), "after": verdict_summary(FIXED)}}
    st = validation_status(v)
    assert st["state"] == "success"
    assert "BLOCK → ALLOW" in st["description"]
    assert "0 vulnerabilities" in st["description"] and "0 malware" in st["description"]
    assert len(st["description"]) <= 140


def test_unverified_fix_never_claims_allow():
    v = {"executed": True, "gate": {"verified": False, "validation": "failed"},
         "verdict_change": {"before": verdict_summary(BLOCKED), "after": verdict_summary(FIXED)}}
    st = validation_status(v)
    assert st["state"] == "failure" and "ALLOW" not in st["description"]
