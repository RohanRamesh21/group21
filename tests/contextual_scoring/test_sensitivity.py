import json

from guardian.scoring.contextual.sensitivity import rank_stability
from guardian.scoring.score import CRITERIA, W


def _f(i, level, **vals):
    base = dict.fromkeys(CRITERIA, 0.5)
    base.update(vals)
    return {"id": i, "level": level, "contributions": [{"factor": k, "value": v} for k, v in base.items()]}


def test_deterministic_same_seed_same_output():
    fs = [_f("a", "high", exploitation=0.9), _f("b", "high", exploitation=0.2), _f("c", "low")]
    assert json.dumps(rank_stability(fs), sort_keys=True) == json.dumps(rank_stability(fs), sort_keys=True)
    assert rank_stability(fs, seed=1) != rank_stability(fs, seed=2)


def test_dominant_finding_has_narrow_interval_and_near_tie_has_wide_one():
    dominant = _f("dom", "high", **dict.fromkeys(CRITERIA, 1.0))
    weak = _f("weak", "high", **dict.fromkeys(CRITERIA, 0.1))
    tie_a = _f("tie_a", "high", exposure=0.60, introduced=0.50)  # equal AHP weights: order depends on the perturbation
    tie_b = _f("tie_b", "high", exposure=0.50, introduced=0.60)
    per = rank_stability([dominant, weak, tie_a, tie_b])["per_finding"]
    assert per["dom"]["rank_p05"] == per["dom"]["rank_p95"] == 1
    assert per["weak"]["rank_p05"] == per["weak"]["rank_p95"] == 4
    assert per["dom"]["top5_share"] == 1.0
    assert per["tie_a"]["rank_p95"] - per["tie_a"]["rank_p05"] >= 1  # order of the near-tie flips under weight changes


def test_dominant_factor_gap_is_stable_even_when_close_in_score():
    a = _f("a", "high", exploitation=0.60, impact=0.50)   # exploitation weight is far above impact weight:
    b = _f("b", "high", exploitation=0.50, impact=0.60)   # the order cannot flip within +-20%
    per = rank_stability([a, b])["per_finding"]
    assert per["a"]["rank_p05"] == per["a"]["rank_p95"] == 1


def test_level_is_never_reordered_by_weights():
    crit = _f("crit", "critical", **dict.fromkeys(CRITERIA, 0.0))   # lowest possible score but a higher level
    hi = _f("hi", "high", **dict.fromkeys(CRITERIA, 1.0))
    per = rank_stability([hi, crit])["per_finding"]
    assert per["crit"]["rank_p05"] == per["crit"]["rank_p95"] == 1


def test_duplicate_ids_rejected_and_empty_ok():
    import pytest
    with pytest.raises(ValueError):
        rank_stability([_f("a", "low"), _f("a", "low")])
    assert rank_stability([])["per_finding"] == {}


def test_uses_production_weights_by_default():
    assert rank_stability([_f("a", "low")])["summary"]["weights"] == W
