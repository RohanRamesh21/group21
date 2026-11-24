from guardian.scoring.contextual import confidence
from guardian.scoring.contextual.confidence import AHP, confidence as conf
from guardian.scoring.score import score_report


def test_confidence_ahp_is_consistent():
    assert AHP["consistent"] and AHP["consistency_ratio"] < 0.10
    assert abs(sum(AHP["weights"].values()) - 1) < 1e-3


def test_two_scanners_beat_one_and_unknown_exploit_data_is_listed(report):
    two, one = report["vulnerabilities"][0], dict(report["vulnerabilities"][1], sources=["osv"])
    report["vulnerabilities"][1] = one
    s = score_report(report)
    f2 = conf(next(f for f in s["findings"] if f["id"] == two["key"]))
    f1 = conf(next(f for f in s["findings"] if f["id"] == one["key"]))
    assert f2["signals"]["corroboration"] == 1.0 and f1["signals"]["corroboration"] == 0.5
    assert f2["value"] > f1["value"]
    assert "EPSS/KEV unknown" in f2["missing"] and f2["signals"]["exploit_data"] == 0.0  # unknown, never "safe"


def test_malware_is_not_penalised_for_missing_cvss(scores):
    m = conf(next(f for f in scores["findings"] if "MAL-1" in f["id"]))
    assert m["signals"]["cvss_vector"] is None and m["signals"]["exploit_data"] is None
    assert m["band"] == "high"


def test_cached_epss_downgrades_exploit_signal(scores):
    f = next(f for f in scores["findings"] if f["kind"] == "vulnerability" and not f["floor"])
    f["evidence"]["epss"] = {"epss": 0.5, "percentile": 0.9}
    assert conf(f)["signals"]["exploit_data"] == 1.0
    assert conf(f, ["EPSS unavailable (Timeout); using cached values only"])["signals"]["exploit_data"] == 0.5


def test_reachability_evidence_raises_confidence(scores):
    f = next(f for f in scores["findings"] if f["kind"] == "vulnerability" and not f["floor"])
    f["reachability"] = None
    low = conf(f)["value"]
    f["reachability"] = {"tier": "imported", "evidence": ["server/a.js:3"]}
    assert conf(f)["value"] > low


def test_confidence_never_changes_level(scores):
    before = [(f["id"], f["level"], f["decision"], f["floor"]) for f in scores["findings"]]
    for f in scores["findings"]:
        confidence.confidence(f)
    assert before == [(f["id"], f["level"], f["decision"], f["floor"]) for f in scores["findings"]]


def test_bands():
    from guardian.scoring.contextual.confidence import BANDS
    assert [b for _, b in BANDS] == ["high", "medium", "low"]
