"""M5: approval contract (GUARDIAN_FINAL_PLAN.md §12.3) and append-only audit trail."""
import json

import pytest

from guardian import approval as ap

PLAN = {"base_sha": "a" * 40, "head_sha": "b" * 40, "patch": {"patch_sha256": "c" * 64}}
HASHES = {"policy_sha256": "d" * 64, "profile_sha256": "e" * 64}


def _approve(tmp_path, **kw):
    args = dict(approver="kiran", reason="fix looks right", ttl_seconds=3600, now=1000.0, **HASHES)
    args.update(kw)
    return ap.decide(tmp_path, PLAN, "approve", **args)


def test_approval_binds_every_part_of_the_contract(tmp_path):
    rec = _approve(tmp_path)
    assert {k: rec[k] for k in ("base_sha", "head_sha", "patch_sha256", "policy_sha256", "profile_sha256")} == {
        "base_sha": "a" * 40, "head_sha": "b" * 40, "patch_sha256": "c" * 64, **HASHES}
    assert rec["expires"] == 4600.0 and rec["decision"] == "approve"
    ap.check(rec, PLAN, now=2000.0, **HASHES)  # valid: no exception


@pytest.mark.parametrize("change", ["patch", "head", "base", "policy", "profile"])
def test_any_change_invalidates_the_approval(tmp_path, change):
    rec = _approve(tmp_path)
    plan = json.loads(json.dumps(PLAN))
    hashes = dict(HASHES)
    if change == "patch":
        plan["patch"]["patch_sha256"] = "f" * 64
    elif change == "head":
        plan["head_sha"] = "9" * 40
    elif change == "base":
        plan["base_sha"] = "8" * 40
    else:
        hashes[f"{change}_sha256"] = "0" * 64
    with pytest.raises(ap.ApprovalInvalid, match=change):
        ap.check(rec, plan, now=2000.0, **hashes)


def test_expired_and_rejected_approvals_authorise_nothing(tmp_path):
    with pytest.raises(ap.ApprovalInvalid, match="expired"):
        ap.check(_approve(tmp_path), PLAN, now=99999.0, **HASHES)
    rej = ap.decide(tmp_path, PLAN, "reject", approver="kiran", reason="wrong version", ttl_seconds=3600, now=1000.0, **HASHES)
    with pytest.raises(ap.ApprovalInvalid, match="rejected"):
        ap.check(rej, PLAN, now=1001.0, **HASHES)


def test_decisions_need_a_person_and_a_reason(tmp_path):
    with pytest.raises(ValueError):
        ap.decide(tmp_path, PLAN, "approve", approver="", reason="x", ttl_seconds=60, now=1.0, **HASHES)
    with pytest.raises(ValueError):
        ap.decide(tmp_path, PLAN, "maybe", approver="k", reason="x", ttl_seconds=60, now=1.0, **HASHES)


def test_risk_acceptance_records_owner_scope_reason_expiry(tmp_path):
    r = ap.accept_risk(tmp_path, "jsonata@2.2.0#GHSA-x", owner="kiran", scope="this PR only", reason="no upgrade path yet",
                       ttl_seconds=86400, now=10.0)
    assert (r["owner"], r["scope"], r["expires"]) == ("kiran", "this PR only", 86410.0)
    assert ap.accepted_risks(tmp_path, now=20.0)[0]["finding_id"] == "jsonata@2.2.0#GHSA-x"
    assert ap.accepted_risks(tmp_path, now=10**6) == []  # expired acceptances drop out


def test_audit_log_is_hash_chained_and_tamper_evident(tmp_path):
    _approve(tmp_path)
    ap.accept_risk(tmp_path, "x", owner="k", scope="s", reason="r", ttl_seconds=10, now=1.0)
    assert ap.verify_audit(tmp_path) == (True, 2)
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    ev = json.loads(lines[0])
    ev["event"]["approver"] = "someone-else"
    lines[0] = json.dumps(ev)
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n")
    ok, _ = ap.verify_audit(tmp_path)
    assert ok is False


def test_file_hash_helper(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text("a: 1\n")
    import hashlib
    assert ap.file_sha256(f) == hashlib.sha256(b"a: 1\n").hexdigest()


def test_editing_the_last_audit_line_is_also_detected(tmp_path):
    _approve(tmp_path)
    log = tmp_path / "audit.jsonl"
    ev = json.loads(log.read_text().splitlines()[-1])
    ev["event"]["reason"] = "edited later"
    log.write_text(json.dumps(ev) + "\n")
    assert ap.verify_audit(tmp_path)[0] is False
