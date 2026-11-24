# READING GUIDE
# Shared notebook for the tool-using loop: tasks, findings, cases, messages, coverage and audit events.
# Workers share this object; its locks protect selected mutations. It is run state, not the persistent evidence store.
#
"""The shared board: plan, tasks, findings, cases, messages, coverage and budgets (AGENTIC_CORE §8 state)."""
from __future__ import annotations

import itertools
import threading
import time
from dataclasses import dataclass, field

from guardian.agents.protocol import ROUTING, AgentMessage, BoardFinding, CaseState, Task


# An agent attempted an unsupported communication route or exhausted the message allowance.
class RoutingError(ValueError):
    pass


# Run-local state shared by the graph, tools and agents; snapshots are compact views of this state.
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
    audit: list[dict] = field(default_factory=list)  # every tool call, rejection and floor intervention
    feed: list[dict] = field(default_factory=list)  # audit events and messages in one ordered stream (dashboard)
    verdict: dict | None = None
    budget: dict = field(default_factory=lambda: {"max_messages": 80, "max_rounds": 40})
    rounds: int = 0
    _ids: itertools.count = field(default_factory=lambda: itertools.count(1))
    _lock: threading.Lock = field(default_factory=threading.Lock)

    # Allocate IDs under a lock so parallel workers do not get the same sequence number.
    def next_id(self, prefix: str) -> str:
        with self._lock:
            return f"{prefix}-{next(self._ids):03d}"

    # --- messages ------------------------------------------------------------
    # Enforce route/message limits, then append the message and its dashboard event together.
    def post(self, msg: AgentMessage) -> AgentMessage:
        allowed = ROUTING.get((msg.sender, msg.recipient), set())
        if msg.kind not in allowed and msg.kind != "evidence_request":
            raise RoutingError(f"{msg.sender} may not send '{msg.kind}' to {msg.recipient}")
        with self._lock:
            if len(self.messages) >= self.budget["max_messages"]:
                raise RoutingError("run message budget exhausted (C8)")
            self.messages.append(msg)
            self.feed.append({"seq": len(self.feed), "ts": time.time(), "type": "message", **msg.model_dump(exclude_none=True)})
        return msg

    # Select messages addressed to one agent after a known list position.
    def inbox(self, agent: str, after: int = 0) -> list[AgentMessage]:
        return [m for m in self.messages[after:] if m.recipient == agent]

    # Append audit details and a corresponding ordered feed event for the dashboard.
    def log(self, **event) -> None:
        with self._lock:
            self.audit.append(event)
            self.feed.append({"seq": len(self.feed), "ts": time.time(), "type": "audit", **event})

    # --- findings, cases, tasks ---------------------------------------------
    # Deduplicate findings by detector type and component before inserting a new record.
    def add_finding(self, f: BoardFinding) -> BoardFinding:
        with self._lock:
            existing = next((x for x in self.findings.values() if x.type == f.type and x.component == f.component), None)
            if existing:
                return existing
            self.findings[f.id] = f
        return f

    # Return only work that has not started; optional assignee filtering supports specialist dispatch.
    def open_tasks(self, assignee: str | None = None) -> list[Task]:
        return [t for t in self.tasks.values() if t.status == "open" and (assignee is None or t.assignee == assignee)]

    # Compute required investigation surfaces that tools have not yet marked as checked.
    def coverage_gaps(self) -> list[str]:
        return sorted(self.coverage_required - self.coverage_done)

    # Publish a compact state summary; large evidence content remains in the evidence store.
    def snapshot(self) -> dict:
        """Compact view for the Lead and the UI (IDs and summaries only, never untrusted content)."""
        return {
            "plan": self.plan,
            "tasks": {k: t.model_dump(include={"assignee", "goal", "scope", "depth", "status"}) for k, t in self.tasks.items()},
            "findings": {k: f.model_dump(include={"type", "component", "summary", "hard_signal", "floor", "risk", "label", "status", "evidence_ids"}) for k, f in self.findings.items()},
            "cases": {k: c.model_dump(include={"title", "finding_ids", "verdict", "risk", "resolved"}) for k, c in self.cases.items()},
            "coverage_gaps": self.coverage_gaps(),
            "verdict": self.verdict,
        }
