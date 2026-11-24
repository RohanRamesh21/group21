"""Start a remediation run in one of three modes and record which one really ran.

  rule_based  no LLM: the top fix_score candidate per priority finding (the demo fallback and the evaluation baseline)
  agent       the Fixer agent (+ Fix Skeptic) on the configured provider (guardian/.env). Any provider failure falls back to
              rule_based and says so in the run record: a plan's `produced_by` is always the truth.
  replay      the same agent loop driven by a SCRIPTED backend (no LLM call). The script is synthesised from the scored data,
              so it is a scripted replay, never presented as a live model run.
"""
from __future__ import annotations

from guardian import config
from guardian.agents.llm import ScriptedBackend, make_backend
from guardian.remediation.agent import run_fixer
from guardian.remediation.service import Remediator, run_meta

MODES = ("rule_based", "agent", "replay")


# ----------------------------------------------------------------------------- scripted replay
def _picks(rem: Remediator, n: int) -> list[tuple[dict, dict]]:
    """Findings the script will plan for, by simulating coverage: (card, best candidate)."""
    picked, covered = [], set()
    for card in rem.ctx.priority(60):
        if card["id"] in covered or len(picked) >= n:
            continue
        cands = rem.ctx.cands(card["id"])
        if not cands:
            continue
        picked.append((card, cands[0]))
        covered |= set(cands[0]["resolves"]) | {card["id"]}
    return picked


def build_script(rem: Remediator, n: int) -> tuple[dict, callable]:
    picks = _picks(rem, n)
    fixer: list = [[["list_priority_findings", {"n": n}]]]
    for card, c in picks:
        fid = card["id"]
        fixer.append([["get_finding", {"finding_id": fid}], ["list_fix_candidates", {"finding_id": fid}]])
        if c["type"] in ("upgrade_to_fixed", "override_transitive"):
            fixer.append([["check_upgrade_safety", {"finding_id": fid, "type": c["type"], "target": c.get("target")}]])
        fixer.append([["propose_fix", {"finding_id": fid, "type": c["type"], "target": c.get("target"),
                                       "rationale": "Scripted replay: the highest-scoring generated candidate for this finding. Forecast only; a human decides.",
                                       "evidence_ids": [f"{{EF:{fid}}}", f"{{EC:{fid}}}"]}]])
        fixer.append([["request_approval", {"plan_id": f"{{PLAN:{fid}}}"}]])  # own turn: the plan id exists only after propose_fix ran
    fixer.append([])
    skeptic: list = []
    for card, c in picks:
        if card["level"] in ("high", "critical") or card["hard_signal"]:
            skeptic += [[["get_plan", {"plan_id": f"{{PLAN:{card['id']}}}"}]],
                        [["submit_review", {"plan_id": f"{{PLAN:{card['id']}}}", "outcome": "accept", "concerns": [], "evidence_ids": [f"{{EC:{card['id']}}}"]}]], []]

    def resolve(obj):
        if isinstance(obj, str):
            def sub(m):
                kind, fid = m.group(1), m.group(2)
                if kind == "EF":
                    return rem.evidence_finding(fid)
                if kind == "EC":
                    return rem.evidence_candidates(fid)
                if kind == "PLAN":
                    return next(p.id for p in rem.store.plans() if fid in p.finding_ids)
                return m.group(0)
            import re
            return re.sub(r"\{(EF|EC|PLAN):([^}]+)\}", sub, obj)
        if isinstance(obj, list):
            return [resolve(x) for x in obj]
        if isinstance(obj, dict):
            return {k: resolve(v) for k, v in obj.items()}
        return obj
    return {"fixer": fixer, "fix_skeptic": skeptic}, resolve


# ----------------------------------------------------------------------------- entry point
def run_remediation(rem: Remediator, mode: str = "rule_based", top_n: int = 3, rounds: int = 1, backend=None) -> dict:
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    meta = {**run_meta(rem.ctx, mode), "requested_mode": mode, "top_n": top_n}
    used, note = mode, None
    rem.store.save_meta(meta)
    rem.store.log("run_start", mode=mode, top_n=top_n)
    try:
        if mode == "rule_based":
            plans = rem.rule_based(top_n)
        elif mode == "replay":
            script, resolver = build_script(rem, top_n)
            plans = run_fixer(rem, ScriptedBackend(script, resolver), top_n, rounds=0)
        else:
            plans = run_fixer(rem, backend or make_backend(config.provider()), top_n, rounds)
    except Exception as e:  # provider down / no key: the run still produces plans, honestly labelled
        note = f"{mode} mode failed ({type(e).__name__}: {e})"[:300] + "; fell back to the rule-based recommender"
        rem.store.log("fallback", reason=note)
        used = "rule_based"
        plans = rem.rule_based(top_n)
    if mode in ("agent", "replay") and not plans and used == mode:  # the agent finished without proposing anything
        note = "the agent proposed nothing; the rule-based recommender filled in"
        rem.store.log("fallback", reason=note)
        plans = rem.rule_based(top_n)
        used = "rule_based"
    rem.store.save_meta({**meta, "mode_used": used, "note": note})
    return {"run_id": rem.store.run_id, "mode_used": used, "note": note, "plans": [p.id for p in plans if p]}
