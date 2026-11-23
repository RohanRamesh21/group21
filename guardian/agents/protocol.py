"""v4 agent protocol (AGENTIC_CORE.md §5): typed messages, tasks, findings and cases on a shared board."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

AgentName = Literal["lead", "hunter", "forensics", "skeptic", "fixer", "human", "system"]
Risk = Literal["critical", "high", "medium", "low", "info"]
RISK_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

MessageKind = Literal[
    "task", "task_result", "handoff", "hypothesis", "challenge", "answer",
    "corroborate", "clear", "dispute", "missed_risk",
    "ask_human", "human_answer", "evidence_request", "resolve", "verdict",
]

# Who may send which kinds to whom (AGENTIC_CORE §5 routing rules).
ROUTING: dict[tuple[str, str], set[str]] = {
    ("lead", "hunter"): {"task"}, ("lead", "forensics"): {"task"}, ("lead", "fixer"): {"task"},
    ("hunter", "lead"): {"task_result"}, ("forensics", "lead"): {"task_result"}, ("fixer", "lead"): {"task_result"},
    ("hunter", "forensics"): {"handoff"}, ("forensics", "hunter"): {"handoff"},
    ("hunter", "skeptic"): {"hypothesis", "answer"}, ("forensics", "skeptic"): {"hypothesis", "answer"},
    ("skeptic", "hunter"): {"challenge"}, ("skeptic", "forensics"): {"challenge"},
    ("skeptic", "lead"): {"corroborate", "clear", "dispute", "missed_risk"},
    ("lead", "human"): {"ask_human", "verdict"}, ("human", "lead"): {"human_answer"},
    ("lead", "board"): {"resolve"},
}


class AgentMessage(BaseModel):
    id: str
    run_id: str
    case_id: str | None = None
    task_id: str | None = None
    finding_id: str | None = None
    sender: AgentName
    recipient: str  # an AgentName or "board"
    kind: MessageKind
    claim: str | None = Field(None, max_length=600)  # the agent's own words only, never pasted content
    evidence_ids: list[str] = Field(default_factory=list)
    kind_of_claim: Literal["verified", "inferred"] | None = None
    confidence: float | None = Field(None, ge=0, le=1)
    proposed_risk: Risk | None = None
    payload: dict = Field(default_factory=dict)  # task spec etc.; never untrusted content
    in_reply_to: str | None = None


class Task(BaseModel):
    id: str
    assignee: Literal["hunter", "forensics", "fixer"]
    goal: str
    scope: list[str]
    depth: Literal["quick", "standard", "deep"] = "standard"
    budget: dict = Field(default_factory=lambda: {"max_steps": 12})
    acceptance: list[str] = Field(default_factory=list)
    status: Literal["open", "running", "done", "cancelled", "exhausted"] = "open"


class BoardFinding(BaseModel):
    id: str
    type: str
    component: str
    summary: str
    evidence_ids: list[str]
    hard_signal: bool = False
    floor: Risk = "info"  # constitution C2: risk can never go below this
    risk: Risk = "info"
    label: Literal["introduced", "pre_existing", "fixed"] | None = None
    status: Literal["candidate", "needs_review", "corroborated", "cleared", "disputed"] = "candidate"
    opened_by: str = "system"  # detector id or agent name ("agent_discovered")


class CaseState(BaseModel):
    id: str
    title: str
    finding_ids: list[str]
    root_cause: str | None = None
    verdict: Literal["malicious", "suspicious", "vulnerable", "benign", "unresolved"] = "unresolved"
    risk: Risk = "info"
    confidence: float = 0.0
    rationale: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    resolved: bool = False
