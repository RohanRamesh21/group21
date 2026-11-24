"""The remediation service: builds fix plans (rule-based or from the Fixer agent), runs the checks, records human decisions.

Everything an agent proposes goes through `Remediator.propose`: referee (C10, C10b, C1, C5) -> patch preview ->
upgrade safety -> deterministic Skeptic checks -> sealed plan (sha256). Nothing here writes to the analysed project.
"""
from __future__ import annotations

import json
import platform
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from guardian.remediation import challenges, patch, referee, upgrade_safety
from guardian.remediation.context import RemediationContext
from guardian.remediation.models import Approval, FixPlan, PatchPreview, SkepticReview
from guardian.remediation.store import RemediationStore, now

INJECTION_PATTERNS = ("ai reviewer", "ignore previous", "ignore all previous", "mark it benign", "this package is safe", "approve this fix",
                      "approve this plan", "apply this fix", "you must approve", "disregard the", "system prompt")
FORECAST_KEYS = ("fix_score", "criteria", "expected_risk_reduction", "compat", "rollback", "checks_not_run", "forecast", "method", "resolves")


class DecisionError(ValueError):
    pass


def new_run_id() -> str:
    return f"REM-{uuid.uuid4().hex[:6].upper()}"


def run_meta(ctx: RemediationContext, mode: str) -> dict:
    data = ctx.scores.get("data") or {}
    return {"project": ctx.project, "mode": mode, "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "scores_path": ctx.scores_path, "report_path": ctx.report_path, "verdict_before": ctx.scores.get("verdict"),
            "tool_versions": {"python": platform.python_version(), "platform": sys.platform,
                              "contextual_scoring": (ctx.scores.get("contextual") or {}).get("version")},
            "data_timestamps": {"kev_catalog_size": data.get("kev_catalog_size"), "epss_found": data.get("epss_found"),
                                "intel_errors": data.get("errors", [])},
            "source_tree": str(ctx.src) if ctx.src else None, "base_tree": str(ctx.base_src) if ctx.base_src else None}


def open_run(ctx: RemediationContext, base=None) -> "Remediator":
    """A new run whose input is FROZEN: the effective scores (incl. an approved AHP matrix) are copied into the run directory,
    so the run is reproducible and a reload sees exactly what the human saw."""
    store = RemediationStore(new_run_id(), base=base)
    frozen = store.root / "scores.json"
    frozen.write_text(json.dumps(ctx.scores, indent=1), encoding="utf-8")
    ctx.scores_path = str(frozen)
    return Remediator(ctx, store)


class Remediator:
    def __init__(self, ctx: RemediationContext, store: RemediationStore, providers: upgrade_safety.Providers | None = None):
        self.ctx, self.store, self.providers = ctx, store, providers or upgrade_safety.Providers()

    # ---- evidence (agents cite these ids; C1 checks rationale text against them) ----------------------------------
    def evidence_finding(self, fid: str) -> str:
        f = self.ctx.finding(fid)
        if f is None:
            raise referee.RefereeError(f"unknown finding id {fid}")
        card = {"id": f["id"], "title": f["title"], "component": f.get("component"), "level": f["level"], "score": f["score"],
                "decision": f["decision"], "label": f["label"], "floor": f.get("floor"), "fixed": f.get("fixed"),
                "package": f.get("package"), "ssvc": f.get("ssvc"), "contributions": f.get("contributions"),
                "reachability": f.get("reachability"), "confidence": f.get("confidence"), "evidence": f.get("evidence"),
                "counterfactuals": f.get("counterfactuals")}
        return self.store.evidence.add(card, kind="tool_output", source="guardian.scoring (scored finding)", path=fid).id

    def evidence_candidates(self, fid: str) -> str:
        return self.store.evidence.add({"finding": fid, "candidates": self.ctx.cands(fid)}, kind="tool_output",
                                       source="guardian.scoring.contextual.fixrank.generate", path=fid).id

    def evidence_safety(self, fid: str, candidate_id: str, safety: dict) -> str:
        return self.store.evidence.add({"finding": fid, "candidate": candidate_id, "upgrade_safety": safety}, kind="tool_output",
                                       source="guardian.remediation.upgrade_safety", path=candidate_id).id

    # ---- computations shared by tools, rule-based path and UI -------------------------------------------------------
    def safety_for(self, finding: dict, cand: dict) -> dict:
        try:
            return upgrade_safety.compute(cand, finding, self.ctx.inventory, self.ctx.app_manifest, self.ctx.src, self.providers)
        except Exception as e:  # no silent failure: say what was not checked
            return {"applicable": True, "risk": "unknown", "reasons": [f"upgrade-safety check failed ({type(e).__name__}: {e})"[:200]],
                    "checks_not_run": ["all upgrade-safety checks"], "coverage": "partial"}

    def preview_for(self, finding: dict, cand: dict) -> PatchPreview:
        needs_tree = cand["type"] not in ("pin_action_sha", "pin_image_digest", "escalate")
        if self.ctx.src is None and needs_tree:
            return PatchPreview(supported=False, notes=["the project source tree is not on disk for this report, so no patch can be previewed"])
        try:
            return patch.preview(cand, finding, self.ctx.src or Path("."), self.ctx.base_src)
        except Exception as e:
            return PatchPreview(supported=False, notes=[f"patch preview failed ({type(e).__name__}: {e})"[:200]])

    def _affected(self, finding: dict) -> dict | None:
        adv = (finding.get("evidence") or {}).get("advisory")
        if not adv or finding["kind"] != "vulnerability":
            return None
        try:
            return self.ctx.affected_lookup([adv])
        except Exception:
            return None

    def scan_injection(self, evidence_ids: list[str], rationale: str = "") -> list[dict]:
        """Instruction-like text in anything the proposer cited (or in its own rationale). It never changes a verdict; it is raised."""
        out = []
        for eid in dict.fromkeys(evidence_ids):
            if not self.store.evidence.exists(eid):
                continue
            hits = [p for p in INJECTION_PATTERNS if p in self.store.evidence.content(eid).lower()]
            if hits:
                out.append({"type": "prompt_injection", "evidence_id": eid, "patterns": hits})
        hits = [p for p in INJECTION_PATTERNS if p in rationale.lower()]
        if hits:
            out.append({"type": "prompt_injection", "evidence_id": "rationale", "patterns": hits})
        return out

    # ---- the only way to create a plan ---------------------------------------------------------------------------
    def propose(self, finding_id: str, ctype: str, target: str | None, rationale: str, evidence_ids: list[str],
                produced_by: str) -> FixPlan:
        finding = self.ctx.finding(finding_id)
        cands = self.ctx.cands(finding_id) if finding else []
        try:
            cand = referee.check_proposal(finding, cands, ctype, target)
            referee.check_claim(rationale, evidence_ids, self.store.evidence)
        except referee.RefereeError as e:
            self.store.log("rejected", producer=produced_by, finding=finding_id, type=ctype, target=target, reason=str(e))
            raise
        for p in self.store.plans():  # idempotent: the same candidate is planned once unless the earlier plan was rejected
            if p.candidate_id == cand["id"] and p.status != "rejected":
                return p
        assert finding is not None
        preview = self.preview_for(finding, cand)
        safety = self.safety_for(finding, cand)
        if safety.get("applicable"):
            evidence_ids = [*evidence_ids, self.evidence_safety(finding_id, cand["id"], safety)]
        flags = self.scan_injection(evidence_ids, rationale)
        for fl in flags:
            self.store.log("prompt_injection", plan_candidate=cand["id"], evidence=fl["evidence_id"], patterns=fl["patterns"])
        checks = challenges.run(finding, cand, safety, preview.supported, self._affected(finding), flags)
        alts = []
        for c in cands:
            if c["id"] == cand["id"]:
                continue
            alts.append({"candidate_id": c["id"], "type": c["type"], "target": c.get("target"), "fix_score": c["fix_score"],
                         "compat_risk": c["compat"]["risk"], "findings_cleared": len(c["resolves"])})
        fids = list(dict.fromkeys([finding_id, *cand.get("resolves", [])]))
        plan = FixPlan(
            id=self.store.next_plan_id(), run_id=self.store.run_id, finding_ids=fids, candidate_id=cand["id"], type=cand["type"],
            target=cand.get("target"), package=patch._package_name(finding), rationale=rationale, evidence_ids=evidence_ids, claim_kind="inferred",
            forecast={k: cand[k] for k in FORECAST_KEYS if k in cand}, upgrade_safety=safety if safety.get("applicable") else None,
            confidence=finding.get("confidence"), patch=preview, produced_by=produced_by,  # type: ignore[arg-type]
            alternatives=alts, flags=flags, finding_summary={k: finding.get(k) for k in ("title", "level", "score", "label", "decision", "floor", "kind")},
            review=SkepticReview(checks=checks, outcome=challenges.outcome(checks)),  # type: ignore[arg-type]
        ).seal()
        self.store.save_plan(plan)
        self.store.log("plan_proposed", plan=plan.id, producer=produced_by, finding=finding_id, candidate=cand["id"], sha=plan.plan_sha256[:12])
        return plan

    # ---- rule-based recommender (no LLM): the fallback and the evaluation baseline ----------------------------------
    def rule_based(self, top_n: int = 5) -> list[FixPlan]:
        covered = {fid for p in self.store.plans() for fid in p.finding_ids}
        plans: list[FixPlan] = []
        for card in self.ctx.priority(top_n * 3, covered):
            if len(plans) >= top_n:
                break
            if card["id"] in covered:
                continue
            f = self.ctx.finding(card["id"])
            cands = self.ctx.cands(card["id"])
            if f is None or not cands:
                continue
            pick = cands[0]
            if not self.preview_for(f, pick).supported and pick["type"] != "escalate":
                # prefer a candidate we can actually apply when it is nearly as good (within 15 fix-score points)
                alt = next((c for c in cands[1:] if c["type"] != "escalate" and c["fix_score"] >= pick["fix_score"] - 15 and self.preview_for(f, c).supported), None)
                pick = alt or pick
            ev = [self.evidence_finding(card["id"]), self.evidence_candidates(card["id"])]
            comp = (f.get("component") or "").strip()
            what = {"upgrade_to_fixed": f"upgrade to {pick.get('target')}", "override_transitive": f"override to {pick.get('target')}",
                    "remove_package": "remove the package", "revert_change": "revert the change", "pin_action_sha": "pin the action to a commit SHA",
                    "pin_image_digest": "pin the image by digest", "escalate": "escalate for a human security review"}[pick["type"]]
            why = (f"Rule-based pick: {comp} {what}. Highest fix score ({pick['fix_score']}) of {len(cands)} generated candidate(s); "
                   f"clears {len(pick['resolves'])} finding(s); forecast compatibility risk {pick['compat']['risk']}. A forecast, not verified.")
            try:
                plans.append(self.propose(card["id"], pick["type"], pick.get("target"), why[:600], ev, "rule_based"))
            except referee.RefereeError as e:
                self.store.log("rule_based_skipped", finding=card["id"], reason=str(e))
            covered |= set(plans[-1].finding_ids) if plans else set()
        return plans

    # ---- human decision (the only writer of approvals) --------------------------------------------------------------
    def decide(self, plan_id: str, decision: str, reviewer: str, note: str | None = None) -> Approval:
        plan = self.store.get_plan(plan_id)
        if plan is None:
            raise DecisionError(f"unknown plan {plan_id}")
        if not reviewer or not reviewer.strip():
            raise DecisionError("a reviewer name is required: decisions are attributed to a person")
        if decision not in ("approve", "reject", "escalate"):
            raise DecisionError("decision must be approve, reject or escalate")
        if not plan.intact():
            self.store.log("tamper_detected", plan=plan_id)
            raise DecisionError("the plan changed after it was sealed (hash mismatch): it cannot be decided; propose it again")
        if plan.status != "proposed":
            raise DecisionError(f"plan {plan_id} is already '{plan.status}'")
        if decision == "approve" and plan.review.outcome == "block" and not (note or "").strip():
            raise DecisionError("this plan has a failed safety check: approving needs a written reason in the note")
        if decision == "approve" and not plan.patch.supported and plan.type != "escalate":
            note = (note + " " if note else "") + "[approved as a recommendation only: it cannot be applied automatically]"
        a = Approval(plan_id=plan.id, plan_sha256=plan.plan_sha256, decision=decision, reviewer=reviewer.strip()[:80],  # type: ignore[arg-type]
                     note=(note or None) and note[:500], at=now())
        self.store.append_approval(a)
        self.store.set_status(plan.id, {"approve": "approved", "reject": "rejected", "escalate": "escalated"}[decision])
        self.store.log("decision", plan=plan.id, decision=decision, reviewer=a.reviewer, sha=plan.plan_sha256[:12])
        return a


def summary(plans: list[FixPlan]) -> str:
    return json.dumps([{"id": p.id, "type": p.type, "target": p.target, "status": p.status, "by": p.produced_by} for p in plans])
