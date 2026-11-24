"""The shared board: plan, tasks, findings, cases, messages, coverage and budgets (AGENTIC_CORE §8 state)."""
from __future__ import annotations

import itertools
import threading
import time
from dataclasses import dataclass, field

from guardian.agents.protocol import RISK_ORDER, ROUTING, AgentMessage, BoardFinding, CaseState, Task


class RoutingError(ValueError):
    pass


@dataclass
class Board:
    run_id: str
    base: str
    head: str
    plan: list[str] = field(default_factory=list)
    tasks: dict[str, Task] = field(default_factory=dict)
    findings: dict[str, BoardFinding] = field(default_factory=dict)
    cases: dict[str, CaseState] = field(default_factory=dict)
    messages: list[AgentMessage] = field(default_factory=list)
    coverage_required: set[str] = field(default_factory=set)  # surfaces that must be examined (C3)
    coverage_done: set[str] = field(default_factory=set)
    scan_evidence: dict[str, str] = field(default_factory=dict)
    review_questions: dict[str, dict] = field(default_factory=dict)
    focused: bool = False
    required_checks: dict[str, str] = field(default_factory=dict)
    audit: list[dict] = field(default_factory=list)  # every tool call, rejection and floor intervention
    feed: list[dict] = field(default_factory=list)  # audit events and messages in one ordered stream (dashboard)
    verdict: dict | None = None
    budget: dict = field(default_factory=lambda: {"max_messages": 80, "max_rounds": 40, "max_tools": 240,
                                               "max_tasks": 32, "max_model_turns": 120, "max_seconds": 360})
    tool_calls: int = 0
    model_turns: int = 0
    investigation_interrupted: bool = False
    rounds: int = 0
    started_at: float = field(default_factory=time.monotonic)
    _ids: itertools.count = field(default_factory=lambda: itertools.count(1))
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def next_id(self, prefix: str) -> str:
        with self._lock:
            return f"{prefix}-{next(self._ids):03d}"

    # --- messages ------------------------------------------------------------
    def post(self, msg: AgentMessage, handoff: Task | None = None) -> AgentMessage:
        if msg.run_id != self.run_id:
            raise RoutingError("message belongs to another run")
        allowed = ROUTING.get((msg.sender, msg.recipient), set())
        if msg.kind not in allowed and msg.kind != "evidence_request":
            raise RoutingError(f"{msg.sender} may not send '{msg.kind}' to {msg.recipient}")
        with self._lock:
            if len(self.messages) >= self.budget["max_messages"]:
                raise RoutingError("run message budget exhausted (C8)")
            if handoff:
                self._add_task(handoff)
            self.messages.append(msg)
            self.feed.append({"seq": len(self.feed), "ts": time.time(), "type": "message", **msg.model_dump(exclude_none=True)})
        return msg

    def log(self, **event) -> None:
        with self._lock:
            self.audit.append(event)
            self.feed.append({"seq": len(self.feed), "ts": time.time(), "type": "audit", **event})

    # --- findings, cases, tasks ---------------------------------------------
    def add_finding(self, f: BoardFinding) -> BoardFinding:
        with self._lock:
            existing = next((x for x in self.findings.values() if x.type == f.type and x.component == f.component), None)
            if existing:
                existing.evidence_ids = list(dict.fromkeys(existing.evidence_ids + f.evidence_ids))
                if f.label == "introduced":
                    existing.label = "introduced"
                if f.hard_signal and not existing.hard_signal:
                    existing.status = "candidate"
                existing.hard_signal |= f.hard_signal
                existing.floor = max(existing.floor, f.floor, key=RISK_ORDER.__getitem__)
                if existing.hard_signal or existing.status != "cleared":
                    existing.risk = max(existing.risk, f.risk, existing.floor, key=RISK_ORDER.__getitem__)
                return existing
            self.findings[f.id] = f
        return f

    def open_tasks(self, assignee: str | None = None) -> list[Task]:
        return [t for t in self.tasks.values() if t.status == "open" and (assignee is None or t.assignee == assignee)]

    def coverage_gaps(self) -> list[str]:
        return sorted(self.coverage_required - self.coverage_done)

    def take_tool_slot(self) -> bool:
        """Consume a shared tool slot across all specialists."""
        with self._lock:
            if self.tool_calls >= self.budget["max_tools"] or self.out_of_time():
                self.investigation_interrupted = True
                return False
            self.tool_calls += 1
            return True

    def take_model_slot(self) -> bool:
        """Consume a model turn from the shared run budget."""
        with self._lock:
            if self.model_turns >= self.budget["max_model_turns"] or self.out_of_time():
                return False
            self.model_turns += 1
            return True

    def out_of_time(self) -> bool:
        """Check the run's monotonic deadline before starting another action."""
        return time.monotonic() - self.started_at >= self.budget["max_seconds"]

    def add_task(self, task: Task) -> None:
        """Bound total fan-out across dispatches and handoffs."""
        with self._lock:
            self._add_task(task)

    def _add_task(self, task: Task) -> None:
        if len(self.tasks) >= self.budget["max_tasks"]:
            raise RoutingError("run task budget exhausted (C8)")
        self.tasks[task.id] = task

    def snapshot(self) -> dict:
        """Compact view for the Lead and the UI (IDs and summaries only, never untrusted content)."""
        return {
            "plan": self.plan,
            "tasks": {k: t.model_dump(include={"assignee", "goal", "scope", "depth", "status"}) for k, t in self.tasks.items()},
            "findings": {k: f.model_dump(include={"type", "component", "summary", "hard_signal", "floor", "risk", "label", "status", "evidence_ids"}) for k, f in self.findings.items()},
            "cases": {k: c.model_dump(include={"title", "finding_ids", "verdict", "risk", "resolved"}) for k, c in self.cases.items()},
            "coverage_gaps": self.coverage_gaps(),
            "focused": self.focused,
            "scan_evidence": self.scan_evidence.copy(),
            "review_questions": self.review_questions.copy(),
            "required_checks": self.required_checks.copy(),
            "verdict": self.verdict,
        }
