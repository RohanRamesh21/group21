"""Feature A: rank stability. "If the AHP weights were a bit different, would the ranking change?"

Method (deterministic, seeded): multiply every AHP weight by a uniform factor in [1-delta, 1+delta], renormalise,
recompute `score = 100 * sum(w_k * v_k)` from the stored factor values, and re-sort with the production key
(level first, then score). Level and decision do not depend on the weights, so only the order *within* a level
can move; the report says so.
"""
from __future__ import annotations

import random

from guardian.scoring.score import CRITERIA, ORDER, W

SEED = 1337
DRAWS = 1000
DELTA = 0.20
TOP_K = 5
TAU_TOP = 25  # Kendall distance is computed on the top-N baseline findings only (O(N^2) per draw)


def _order(rows: list[tuple[str, int, float]]) -> list[str]:
    """rows: (id, level_index, score). Production order: level desc, score desc; id breaks exact ties."""
    return [r[0] for r in sorted(rows, key=lambda r: (-r[1], -r[2], r[0]))]


def _score(f: dict, w: dict[str, float]) -> float:
    vals = {c["factor"]: c["value"] for c in f["contributions"]}
    return 100 * sum(w[k] * vals[k] for k in CRITERIA)


def _pct(sorted_vals: list[int], q: float) -> int:
    return sorted_vals[min(len(sorted_vals) - 1, int(q * len(sorted_vals)))]


def rank_stability(findings: list[dict], weights: dict[str, float] | None = None, draws: int = DRAWS,
                   delta: float = DELTA, seed: int = SEED, top_k: int = TOP_K) -> dict:
    """Returns {"per_finding": {id: {...}}, "summary": {...}}. Same input and seed give identical output."""
    weights = weights or W
    ids = [f["id"] for f in findings]
    if len(set(ids)) != len(ids):  # ids come from scoring; a duplicate would silently merge two findings
        raise ValueError("finding ids must be unique")
    lvl = {f["id"]: ORDER.index(f["level"]) for f in findings}
    base_order = _order([(f["id"], lvl[f["id"]], _score(f, weights)) for f in findings])
    base_rank = {i: n + 1 for n, i in enumerate(base_order)}
    rng = random.Random(seed)
    ranks: dict[str, list[int]] = {i: [] for i in ids}
    tau_sum, top = 0.0, base_order[:TAU_TOP]
    pairs = [(a, b) for x, a in enumerate(top) for b in top[x + 1:]]
    for _ in range(draws):
        w = {k: weights[k] * rng.uniform(1 - delta, 1 + delta) for k in CRITERIA}
        tot = sum(w.values())
        w = {k: v / tot for k, v in w.items()}
        order = _order([(f["id"], lvl[f["id"]], _score(f, w)) for f in findings])
        pos = {i: n + 1 for n, i in enumerate(order)}
        for i in ids:
            ranks[i].append(pos[i])
        if pairs:
            tau_sum += sum(1 for a, b in pairs if pos[a] > pos[b]) / len(pairs)
    per = {}
    for i in ids:
        rs = sorted(ranks[i])
        per[i] = {"baseline_rank": base_rank[i], "rank_p05": _pct(rs, 0.05), "rank_p95": _pct(rs, 0.95),
                  f"top{top_k}_share": round(sum(1 for r in rs if r <= top_k) / len(rs), 3) if rs else None,
                  "draws": draws, "delta": delta, "seed": seed}
    return {"per_finding": per,
            "summary": {"draws": draws, "delta": delta, "seed": seed, "weights": weights,
                        "mean_pair_disorder_top": round(tau_sum / draws, 4) if (draws and pairs) else 0.0, "top_n": min(TAU_TOP, len(top)),
                        "note": "Only the order within a level can change: level and decision come from floors and SSVC, not from the weights."}}
