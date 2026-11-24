"""A fix target must itself be free of known advisories (PR #11: follow-redirects 1.15.5 -> 1.16.0 escaped the PR's
two advisories but 1.16.0 has three of its own; the rescan then found new High findings and validation failed)."""
from guardian.remediation import candidates as cand


def _adv(aid, introduced, fixed):
    return {"id": aid, "affected": [{"package": {"ecosystem": "npm", "name": "follow-redirects"},
                                     "ranges": [{"type": "SEMVER", "events": [{"introduced": introduced}, {"fixed": fixed}]}]}]}


ADV = {"A1": _adv("A1", "0", "1.16.0"),            # the PR's advisory: everything below 1.16.0
       "B1": _adv("B1", "1.16.0", "1.16.1"),       # newer advisories that hit the first "safe" versions
       "B2": _adv("B2", "1.16.0", "1.16.2")}
VULNS = {"1.16.0": ["B1", "B2"], "1.16.1": ["B2"], "1.16.2": []}


def _src(vulns=VULNS):
    return cand.Sources(versions=lambda n: ({v: {} for v in ["1.15.5", "1.16.0", "1.16.1", "1.16.2"]}, None),
                        advisory=lambda i: (ADV[i], {"url": f"osv/{i}", "sha256": "x"}),
                        vulns_of=lambda n, v: vulns.get(v, []))


def _finding():
    return {"id": "follow-redirects@1.15.5#A1", "kind": "vulnerability", "label": "introduced", "level": "high",
            "component": "follow-redirects@1.15.5", "evidence": {"advisory": "A1"}}


REPORT = {"inventory": [{"name": "follow-redirects", "version": "1.15.5", "direct": True}], "package_changes": {"added": []}}


def test_the_target_skips_versions_that_have_their_own_advisories():
    c = cand._package_candidate("follow-redirects", "1.15.5", [_finding()], REPORT, _src())
    assert c["type"] == "upgrade_to_fixed" and c["to"] == "1.16.2"
    assert "no known advisories" in c["rationale"]


def test_no_clean_version_means_a_person_decides():
    c = cand._package_candidate("follow-redirects", "1.15.5", [_finding()], REPORT, _src({"1.16.0": ["B1"], "1.16.1": ["B2"], "1.16.2": ["B2"]}))
    assert c["type"] == "escalate" and "known advisories" in c["rationale"]


def test_without_a_vulnerability_lookup_the_old_behaviour_stays():
    s = _src()
    s.vulns_of = None
    assert cand._package_candidate("follow-redirects", "1.15.5", [_finding()], REPORT, s)["to"] == "1.16.0"


def test_osv_unreachable_keeps_the_target_without_claiming_it_is_clean():
    c = cand._package_candidate("follow-redirects", "1.15.5", [_finding()], REPORT, _src({"1.16.0": None}))
    assert c["to"] == "1.16.0" and "no known advisories" not in c["rationale"]


def test_versions_that_failed_validation_before_are_skipped():
    s = _src({"1.16.0": [], "1.16.1": [], "1.16.2": []})
    s.exclude = {"follow-redirects": ["1.16.0"]}
    c = cand._package_candidate("follow-redirects", "1.15.5", [_finding()], REPORT, s)
    assert c["to"] == "1.16.1" and "1.16.0" in c["rationale"]
