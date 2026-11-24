import pytest

from guardian.scoring.contextual import confidence, fixrank, semver
from guardian.scoring.contextual.fixrank import AHP, Ctx, generate, validate_proposed
from guardian.scoring.score import score_report
from tests.contextual_scoring.conftest import fake_lookup


@pytest.fixture
def ctx(report, scores):
    for f in scores["findings"]:
        f["confidence"] = confidence.confidence(f)
    return Ctx(scores["findings"], report["inventory"], fake_lookup, lambda key: ["foo@1.2.0"])


def _f(scores, needle):
    return next(f for f in scores["findings"] if needle in f["id"])


def test_fix_ahp_is_consistent():
    assert AHP["consistent"] and AHP["consistency_ratio"] < 0.10


def test_semver_range_evaluation():
    e = {"ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.4"}, {"introduced": "2.0.0"}, {"fixed": "2.0.3"}]}]}
    assert [semver.affected(v, e) for v in ("0.9.0", "1.2.3", "1.2.4", "2.0.0", "2.0.3")] == [False, True, False, True, False]
    assert semver.affected("1.0.0", {"ranges": [{"type": "GIT", "events": []}]}) is None  # undecidable is not "safe"
    assert semver.cmp("1.0.0-rc.1", "1.0.0") == -1 and semver.jump("1.9.0", "2.0.0") == "major"


def test_minimal_and_all_upgrade_candidates_for_two_advisories(scores, ctx):
    cands = generate(_f(scores, "GHSA-1"), ctx)
    targets = {c["target"]: c for c in cands}
    assert set(targets) == {"1.2.4", "2.0.0"}
    assert len(targets["1.2.4"]["resolves"]) == 1 and len(targets["2.0.0"]["resolves"]) == 2   # 1.2.4 does not clear GHSA-2
    assert targets["1.2.4"]["compat"]["semver"] == "patch" and targets["2.0.0"]["compat"]["semver"] == "major"
    assert all(c["approval_required"] and c["forecast"] and c["type"] == "upgrade_to_fixed" for c in cands)
    assert all(c["checks_not_run"] == ["peer_dependencies", "engines"] for c in cands)
    assert cands == sorted(cands, key=lambda c: -c["fix_score"])


def test_transitive_gets_override_with_direct_parents(scores, ctx):
    c = generate(_f(scores, "GHSA-3"), ctx)[0]
    assert c["type"] == "override_transitive" and c["target"] == "3.0.1" and c["compat"]["via_direct_parents"] == ["foo@1.2.0"]
    assert c["compat"]["risk"] > fixrank.JUMP_RISK["patch"]  # overrides cost a bit more than a direct bump


def test_patch_outranks_major_at_equal_risk_reduction(scores, ctx):
    f = _f(scores, "GHSA-1")
    patch = fixrank._candidate(f, "upgrade_to_fixed", "1.2.4", [f], ctx, fixrank.JUMP_RISK["patch"], "t")
    major = fixrank._candidate(f, "upgrade_to_fixed", "2.0.0", [f], ctx, fixrank.JUMP_RISK["major"], "t")
    assert patch["criteria"]["risk_reduction"] == major["criteria"]["risk_reduction"]
    assert patch["fix_score"] > major["fix_score"]


def test_malware_gets_remove_package_clearing_the_whole_component(scores, ctx):
    cands = generate(_f(scores, "MAL-1"), ctx)
    rm = next(c for c in cands if c["type"] == "remove_package")
    assert set(rm["resolves"]) == {f["id"] for f in scores["findings"] if f["component"] == "axois@1.0.0"} and len(rm["resolves"]) == 2
    assert any(c["type"] == "revert_change" for c in generate(next(f for f in scores["findings"] if f["kind"] == "supply_chain"), ctx))
    assert not any(c["type"] == "upgrade_to_fixed" for c in cands)  # malware is removed, never "upgraded"


def test_non_npm_and_no_fix_fall_back_to_escalate(scores, ctx):
    f = dict(_f(scores, "GHSA-3"))
    f["package"] = dict(f["package"], ecosystem="pypi")
    c = generate(f, ctx)
    assert [x["type"] for x in c] == ["escalate"] and c[0]["fix_score"] < generate(_f(scores, "GHSA-3"), ctx)[0]["fix_score"]


def test_referee_blocks_invented_versions_types_and_findings(scores, ctx):
    f = _f(scores, "GHSA-1")
    gen = generate(f, ctx)
    ok, _ = validate_proposed({"finding": f["id"], "type": "upgrade_to_fixed", "target": "1.2.4"}, gen)
    assert ok
    bad_version, why = validate_proposed({"finding": f["id"], "type": "upgrade_to_fixed", "target": "9.9.9"}, gen, known_versions={"1.2.4", "2.0.0"})
    assert not bad_version and "9.9.9" in why
    assert not validate_proposed({"finding": f["id"], "type": "run_shell", "target": None}, gen)[0]
    assert not validate_proposed({"finding": "nope@1#X", "type": "upgrade_to_fixed", "target": "1.2.4"}, gen)[0]


def test_missing_osv_ranges_fall_back_and_say_so(report):
    s = score_report(report)
    for f in s["findings"]:
        f["confidence"] = confidence.confidence(f)
    c = Ctx(s["findings"], report["inventory"], lambda ids: {i: None for i in ids})
    cands = generate(next(f for f in s["findings"] if "GHSA-1" in f["id"]), c)
    assert cands and cands[0]["method"] == "advisory-fixed-list"
