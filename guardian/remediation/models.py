"""Records for the remediation chain (Day 2): a fix PLAN, the human APPROVAL bound to it, and the VALIDATION result.

Design rules (docs/DAY2_PROPOSAL.md section 4.2):
  * A plan is immutable once proposed. Its `plan_sha256` covers everything the human is approving.
  * Only code sets `verified`; no agent tool can write the `verified` status (constitution C11).
  * An approval is bound to one `plan_sha256`; apply refuses a plan whose hash no longer matches (C7 extended).
"""
from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, Field

PlanStatus = Literal["proposed", "approved", "rejected", "escalated", "applied", "verified", "not_verified", "failed"]
Decision = Literal["approve", "reject", "escalate"]
Producer = Literal["fixer_agent", "rule_based"]

# Fields that define WHAT the human approves. `status`, the review, the validation and timestamps are not part of it.
HASHED_FIELDS = ("run_id", "finding_ids", "candidate_id", "type", "target", "rationale", "evidence_ids", "claim_kind",
                 "forecast", "upgrade_safety", "patch", "produced_by", "flags", "package")


class PatchPreview(BaseModel):
    """What applying the plan would change. Computed without writing anywhere (guardian/remediation/patch.py)."""

    supported: bool = True  # False = recommend-only in v1 (pins) or not expressible as a manifest edit
    diff: str = ""  # unified diff of the files that would change (package.json etc.)
    files: dict[str, str] = Field(default_factory=dict)  # repo-relative path -> new full text (applied by apply.py)
    delete_files: list[str] = Field(default_factory=list)
    lockfile: Literal["regenerate", "unchanged", "unknown"] = "unknown"
    notes: list[str] = Field(default_factory=list)


class SkepticReview(BaseModel):
    """Independent challenge of a plan: deterministic checks first, then (optionally) a fresh-context LLM Skeptic."""

    checks: list[dict] = Field(default_factory=list)  # {name, status: pass|warn|fail, detail}
    llm_outcome: Literal["accept", "concerns", "not_run"] = "not_run"
    llm_concerns: list[str] = Field(default_factory=list)
    llm_evidence_ids: list[str] = Field(default_factory=list)
    exchange: list[dict] = Field(default_factory=list)  # challenge/answer messages between Skeptic and Fixer: {from, kind, text, evidence_ids}
    outcome: Literal["accept", "concerns", "block"] = "accept"


class FixPlan(BaseModel):
    id: str  # "FP-001"
    run_id: str
    finding_ids: list[str]  # scored finding ids this plan targets (the finding itself plus siblings it also clears)
    candidate_id: str  # id from fixrank: finding::type::target
    type: str  # upgrade_to_fixed | override_transitive | remove_package | revert_change | pin_action_sha | pin_image_digest | escalate
    target: str | None = None
    package: str | None = None  # npm package name the fix is about (used to check the regenerated lockfile)
    rationale: str = Field("", max_length=600)  # the proposer's own words, never pasted content
    evidence_ids: list[str] = Field(default_factory=list)
    claim_kind: Literal["verified", "inferred"] = "inferred"  # a recommendation is a forecast: never "verified" before a rescan
    forecast: dict = Field(default_factory=dict)  # copied from the candidate (expected_risk_reduction, compat, rollback, checks_not_run, fix_score)
    upgrade_safety: dict | None = None
    confidence: dict | None = None  # the finding's confidence (informational)
    patch: PatchPreview = Field(default_factory=PatchPreview)
    produced_by: Producer
    alternatives: list[dict] = Field(default_factory=list)  # other candidates for the same finding: {candidate_id, type, target, fix_score}
    finding_summary: dict = Field(default_factory=dict)  # title, level, score, label, decision at proposal time (display only)
    flags: list[dict] = Field(default_factory=list)  # e.g. prompt_injection found in cited evidence: {type, evidence_id, patterns}
    review: SkepticReview = Field(default_factory=SkepticReview)
    status: PlanStatus = "proposed"
    plan_sha256: str = ""

    def compute_hash(self) -> str:
        body = {k: getattr(self, k) for k in HASHED_FIELDS}
        body["patch"] = self.patch.model_dump()
        blob = json.dumps(body, sort_keys=True, default=str, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()

    def seal(self) -> "FixPlan":
        self.plan_sha256 = self.compute_hash()
        return self

    def intact(self) -> bool:
        """False when anything the human approved was changed after the plan was sealed."""
        return bool(self.plan_sha256) and self.plan_sha256 == self.compute_hash()


class Approval(BaseModel):
    plan_id: str
    plan_sha256: str
    decision: Decision
    reviewer: str
    note: str | None = None
    at: str


class ValidationResult(BaseModel):
    plan_id: str
    plan_sha256: str
    tier: Literal["tier1", "tier2"]
    started: str
    branch: str | None = None  # local, never pushed
    work_dir: str | None = None
    steps: list[dict] = Field(default_factory=list)  # {name, status: ok|failed|skipped, detail}
    build_tests: Literal["pass", "fail", "not_run"] = "not_run"
    delta: dict | None = None  # delta.before_after(...) output
    sbom_diff: dict | None = None
    comparison_frame: str = ""  # which base/head the rescan used (comparability of the risk index)
    outcome: Literal["verified", "remediated_tests_not_run", "not_verified", "failed"] = "failed"
    wording: str = ""  # the exact sentence the UI/report shows
    checks_not_run: list[str] = Field(default_factory=list)
