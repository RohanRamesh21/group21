"""The constitution (AGENTIC_CORE §2): invariants enforced in code, outside any prompt.

Every agent action that changes the board passes through these checks. A failed check is
returned to the agent as an error it must fix; it is also written to the audit log so the
dashboard can show verifier rejections and floor interventions.
"""
from __future__ import annotations

import re

from guardian.agents.board import Board
from guardian.agents.protocol import RISK_ORDER, AgentMessage
from guardian.store.evidence import EvidenceStore

NEEDS_EVIDENCE = {"hypothesis", "answer", "corroborate", "clear", "dispute", "missed_risk", "resolve", "verdict", "task_result"}
NAME_VERSION = re.compile(r"(@?[a-z0-9][a-z0-9._-]*(?:/[a-z0-9._-]+)?)@(\d+\.\d+\.\d+[0-9A-Za-z.+-]*)")
ADVISORY_ID = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|MAL-\d{4}-\d+)\b", re.I)


class ConstitutionError(ValueError):
    """Raised when an action violates an invariant. The message is shown to the agent."""


def _cited_text(store: EvidenceStore, ids: list[str]) -> str:
    return "\n".join(store.content(i) for i in ids if store.exists(i))


def check_message(msg: AgentMessage, board: Board, store: EvidenceStore) -> None:
    """C1 (facts only from tools), C5 (no pasted content), C9 (explained downgrades)."""
    if msg.kind in NEEDS_EVIDENCE and not msg.evidence_ids:
        raise ConstitutionError(f"C1: a '{msg.kind}' must cite evidence IDs.")
    missing = [i for i in msg.evidence_ids if not store.exists(i)]
    if missing:
        raise ConstitutionError(f"C1: unknown evidence IDs {missing}. Cite only IDs returned by tools.")

    if msg.kind_of_claim == "verified":
        kinds = [store.get(i).kind for i in msg.evidence_ids]
        if kinds and all(k == "agent_note" for k in kinds):
            raise ConstitutionError("C1: a 'verified' claim must rest on tool output, not on agent notes.")

    if msg.claim:
        cited = _cited_text(store, msg.evidence_ids).lower()
        for name, ver in NAME_VERSION.findall(msg.claim.lower()):
            if f"{name}@{ver}" not in cited and not (name in cited and ver in cited):
                raise ConstitutionError(f"C1: '{name}@{ver}' does not appear in the cited evidence.")
        for adv in ADVISORY_ID.findall(msg.claim):
            if adv.lower() not in cited:
                raise ConstitutionError(f"C1: advisory '{adv}' does not appear in the cited evidence.")
        if "<untrusted-data" in msg.claim.lower():
            raise ConstitutionError("C5: do not paste untrusted content into messages; cite its evidence ID.")

    if msg.kind == "clear":
        if msg.sender != "skeptic":
            raise ConstitutionError("C9: only the Skeptic can clear a finding.")
        f = board.findings.get(msg.finding_id or "")
        if f is None:
            raise ConstitutionError("C9: 'clear' must name the finding_id it clears.")
        if f.hard_signal:
            raise ConstitutionError(f"C2: {f.id} is a hard signal ({f.type}); it can never be cleared or lowered.")
        if not set(f.evidence_ids).intersection(msg.evidence_ids):
            raise ConstitutionError("C9: a clearance must cite evidence attached to the finding.")


def check_resolution(board: Board, case_id: str, risk: str, verdict: str) -> None:
    """C2 floors: a case can never be resolved below the highest floor among its findings."""
    case = board.cases[case_id]
    floors = [max(board.findings[f].floor, board.findings[f].risk, key=RISK_ORDER.__getitem__)
              for f in case.finding_ids if f in board.findings and board.findings[f].status != "cleared"]
    top = max(floors, key=lambda r: RISK_ORDER[r], default="info")
    if RISK_ORDER[risk] < RISK_ORDER[top]:
        board.log(event="floor_intervention", case=case_id, proposed=risk, floor=top)
        raise ConstitutionError(f"C2: {case_id} has a risk floor of '{top}'; risk '{risk}' is not allowed.")
    hard = [board.findings[f] for f in case.finding_ids if f in board.findings and board.findings[f].hard_signal]
    if hard and verdict == "benign":
        raise ConstitutionError("C2: a case with a hard signal cannot be resolved as benign.")


def check_verdict(board: Board, decision: str) -> None:
    """C3 coverage before verdict, plus C2 on the overall decision."""
    gaps = board.coverage_gaps()
    if gaps:
        board.log(event="coverage_gap", gaps=gaps)
        raise ConstitutionError(f"C3: coverage incomplete. Examine these surfaces first: {gaps}")
    if decision == "safe_to_merge" and introduced_hard_signals(board):
        raise ConstitutionError("C2: introduced High/Critical hard signals require the decision 'block'.")
    if decision == "safe_to_merge" and (board.investigation_interrupted
                                        or any(status != "passed" for status in board.required_checks.values())):
        raise ConstitutionError("C3: required checks or investigation did not complete.")
    if decision == "safe_to_merge" and (
        any(task.status != "done" for task in board.tasks.values())
        or any(case.verdict == "unresolved" for case in board.cases.values())
    ):
        raise ConstitutionError("C3: outstanding tasks or cases require review.")
    unresolved = [c.id for c in board.cases.values() if not c.resolved]
    if unresolved:
        raise ConstitutionError(f"Resolve every case before the verdict: {unresolved}")
    blocking = [
        c.id for c in board.cases.values()
        if RISK_ORDER[c.risk] >= RISK_ORDER["high"]
        and any(board.findings[f].label == "introduced" for f in c.finding_ids if f in board.findings)
    ]
    if blocking and decision != "block":
        raise ConstitutionError(f"C2: introduced High/Critical cases {blocking} require the decision 'block'.")
    if decision == "block" and not (blocking or introduced_hard_signals(board)):
        raise ConstitutionError("C2: a blocking recommendation requires an introduced High/Critical finding.")
    loose = [f.id for f in board.findings.values()
             if f.status not in ("cleared",) and not any(f.id in c.finding_ids for c in board.cases.values())]
    if loose:
        raise ConstitutionError(f"Every open finding must belong to a case or be cleared: {loose}")


def introduced_hard_signals(board: Board) -> list[str]:
    """Return blocking findings independently of agent-created cases."""
    return [f.id for f in board.findings.values()
            if f.hard_signal and f.label != "fixed"
            and f.label != "pre_existing" and RISK_ORDER[f.floor] >= RISK_ORDER["high"]]
