"""Whole contextual-scoring path on a fake run directory: static scan -> scoring with reachability -> enrichment -> JSON-safe."""
import json

from guardian.scoring.contextual.pipeline import enrich, reach_for_report
from guardian.scoring.score import score_report
from tests.contextual_scoring.conftest import fake_lookup


def _head(tmp_path, report):
    head = tmp_path / "run-head"
    (head / "src" / "server").mkdir(parents=True)
    (head / "src" / "server" / "main.js").write_text("const foo = require('foo');\n")
    edges = [{"parent": "", "child": "node_modules/foo", "kind": "prod"}, {"parent": "node_modules/foo", "child": "node_modules/bar", "kind": "prod"},
             {"parent": "", "child": "node_modules/devtool", "kind": "dev"}, {"parent": "", "child": "node_modules/axois", "kind": "prod"}]
    (head / "edges.json").write_text(json.dumps(edges))
    report["runs"] = {"head": str(head)}
    return report


def test_end_to_end(tmp_path, report):
    report = _head(tmp_path, report)
    reach, err = reach_for_report(report)
    assert err is None
    tiers = {k.split("#")[0]: v["tier"] for k, v in reach.items()}
    assert tiers == {"foo@1.2.0": "imported", "bar@3.0.0": "imported", "devtool@0.5.0": "dev_only", "axois@1.0.0": "declared"}
    scores = enrich(score_report(report, reach=reach), report, reach_error=err, affected_lookup=fake_lookup)
    json.dumps(scores)  # everything is serialisable
    mal = next(f for f in scores["findings"] if "MAL-1" in f["id"])
    assert mal["reachability"]["tier"] == "declared" and mal["level"] == "critical" and mal["floor"]  # declared never discounts malware
    assert scores["verdict"] == "block" and scores["fix_candidates"]
    assert all(c["approval_required"] for cs in scores["fix_candidates"].values() for c in cs)
    assert all(f["confidence"]["band"] in ("high", "medium", "low") and f["rank_stability"]["draws"] == 1000 for f in scores["findings"])
    assert scores["contextual"]["not_checked"] == []


def test_missing_source_is_reported_as_not_checked_never_guessed(report):
    reach, err = reach_for_report(report)  # report["runs"] is empty
    assert reach == {} and "not computed" in err
    scores = enrich(score_report(report, reach=reach), report, reach_error=err, affected_lookup=fake_lookup)
    assert scores["contextual"]["not_checked"] == [err]
    assert all(f["reachability"] is None for f in scores["findings"] if f["kind"] == "vulnerability")
