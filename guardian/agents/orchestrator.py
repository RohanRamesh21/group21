"""LangGraph control loop (AGENTIC_CORE §4 and §8).

lead -> (tasks?) workers [parallel via Send] -> (hypotheses?) skeptic -> (challenges?) respond
     -> lead re-plans ... -> submit_verdict passes the constitution -> END
"""
from __future__ import annotations

import operator
from typing import Annotated, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from guardian.agents.agents import Agent
from guardian.agents.board import Board
from guardian.agents.boundary import redact, untrusted
from guardian.agents.constitution import ConstitutionError, check_verdict
from guardian.agents.llm import ScriptedBackend
from guardian.agents.tools import ToolRegistry


class State(TypedDict, total=False):
    board: Board
    task_id: str
    done: Annotated[list, operator.add]


class Orchestrator:
    def __init__(self, board: Board, registry: ToolRegistry, backend, max_rounds: int = 30):
        self.board, self.registry, self.backend = board, registry, backend
        self.max_rounds = max_rounds
        self.lead_ended = False
        self.lead = Agent("lead", backend, registry, max_steps=16)
        self.skeptic = Agent("skeptic", backend, registry, max_steps=12)
        self.task_agents: dict[str, Agent] = {}  # one conversation per task
        self.seen: dict[str, int] = {"lead": 0, "skeptic": 0, "hunter": 0, "forensics": 0}
        self.graph = self._build()

    # --- helpers -------------------------------------------------------------
    def _unread(self, agent: str) -> list:
        msgs = [m for m in self.board.messages[self.seen[agent]:] if m.recipient == agent]
        return msgs

    def _mark_read(self, agent: str) -> None:
        self.seen[agent] = len(self.board.messages)

    @staticmethod
    def _fmt(msgs) -> str:
        return untrusted([m.model_dump(exclude_none=True, exclude={"run_id"}) for m in msgs])

    def _run_agent(self, agent: Agent, brief: str) -> str:
        try:
            if agent is self.lead and not isinstance(self.backend, ScriptedBackend):
                result = agent.run(brief, yield_on_dispatch=True)
            else:
                result = agent.run(brief)
        except Exception as exc:
            self.board.log(event="investigation_error", agent=agent.name, error=type(exc).__name__, detail=redact(str(exc))[:200])
            result = "exhausted"
        if result in ("exhausted", "refusal", "max_tokens", "length"):
            self.board.investigation_interrupted = True
        return result

    # --- nodes ---------------------------------------------------------------
    def lead_node(self, state: State) -> dict:
        self.board.rounds += 1
        news = self._unread("lead")
        self._mark_read("lead")
        if self.board.rounds == 1 and self.board.focused:
            text = ("Synthesize the completed scan and focused review. Use board_view or coverage_report to check "
                    "outstanding questions. Read scan_findings only if you need additional scan context. Honor scanner "
                    "policy and hard signals. Submit an inconclusive recommendation if material evidence is missing.\n"
                    f"Scan summary evidence ID: {self.registry.world['scan_summary_id']}\n"
                    "Specialist and Skeptic results:\n" + self._fmt(news))
        elif self.board.rounds == 1:
            text = "Investigate this comparison and submit a verdict.\n" + untrusted({
                "run_id": self.board.run_id, "base": self.board.base, "head": self.board.head,
            })
            if "scan:summary" in self.board.coverage_required:
                text += ("\nRead scan_findings at offset 0 before planning. Package tools backed by this scan cover all inventoried ecosystems. "
                         "Use dispatch_scan_review to send both specialists their exact coverage scopes in one call. "
                         "Use package_advisories for specific packages. Submit an inconclusive recommendation with evidence if required coverage is unfinished.")
        else:
            text = ("Update. New messages to you:\n" + self._fmt(news) +
                    f"\nBoard: {untrusted(self.board.snapshot())}\nContinue: re-plan, build/resolve cases, or submit the verdict.")
        self.lead_ended = self._run_agent(self.lead, text) == "end_turn" and not isinstance(self.backend, ScriptedBackend)
        return {}

    def dispatch_node(self, state: State) -> dict:
        return {}

    def fan_out(self, state: State):
        return [Send("worker", {"board": self.board, "task_id": t.id}) for t in self.board.open_tasks()]

    def worker_node(self, state: State) -> dict:
        task = self.board.tasks[state["task_id"]]
        task.status = "running"
        agent = Agent(task.assignee, self.backend, self.registry, max_steps=task.budget.get("max_steps", 12), task_id=task.id)
        self.task_agents[task.id] = agent
        brief = ("Investigate the scoped items. Once you have evidence, post a hypothesis to the Skeptic and a task_result "
                 "to the Lead in the same batch. The task closes when the result is accepted. Use short claims.\n"
                 + untrusted(task.model_dump(include={"id", "depth", "goal", "scope", "acceptance"})))
        if self.board.focused and any(key.startswith("review:") for key in task.scope):
            brief += ("\nCall review_question for each assigned ID. A focused review credits only questions whose evidence ID "
                      "is cited in both your hypothesis and task_result. Skip general inventory and advisory lookups already "
                      "completed by the scanner. Investigate a specific gap or inconsistency when needed.")
        result = self._run_agent(agent, brief)
        if task.status == "running":
            task.status = "exhausted" if result in {"exhausted", "refusal", "max_tokens", "length"} else "done"
        return {"done": [task.id]}

    def skeptic_node(self, state: State) -> dict:
        news = self._unread("skeptic")
        self._mark_read("skeptic")
        brief = "Review these messages:\n" + self._fmt(news) + "\nChallenge, corroborate, dispute, clear (non-hard only) or report missed risks."
        if self.board.focused:
            brief += (" Check the evidence for each hypothesis. Call record_review with the hypothesis message ID and the "
                      "question IDs you independently assessed. "
                      "A disputed question remains open for review.")
        self._run_agent(self.skeptic, brief)
        return {}

    def respond_node(self, state: State) -> dict:
        for role in ("hunter", "forensics"):
            news = self._unread(role)
            self._mark_read(role)
            for m in news:
                agent = self.task_agents.get(m.task_id or "") or next(
                    (a for tid, a in reversed(list(self.task_agents.items())) if a.name == role), None)
                if agent:
                    self._run_agent(agent, "The Skeptic challenges you:\n" + self._fmt([m]) + "\nAnswer with evidence (kind 'answer').")
        return {}

    # --- routing -------------------------------------------------------------
    def route(self, state: State) -> str:
        b = self.board
        if b.verdict or b.out_of_time() or b.rounds >= self.max_rounds:
            return END
        if b.open_tasks():
            return "dispatch"
        if self._unread("skeptic"):
            return "skeptic"
        if self._unread("hunter") or self._unread("forensics"):
            return "respond"
        if b.focused:
            self.registry.finish_advisory_checks()
        if b.investigation_interrupted or self.lead_ended and b.rounds > 1:
            return END
        return "lead"

    def _build(self):
        g = StateGraph(State)
        g.add_node("lead", self.lead_node)
        g.add_node("dispatch", self.dispatch_node)
        g.add_node("worker", self.worker_node)
        g.add_node("review", lambda state: {})
        g.add_node("skeptic", self.skeptic_node)
        g.add_node("respond", self.respond_node)
        g.add_conditional_edges(START, lambda state: "dispatch" if self.board.focused and self.board.open_tasks() else "lead",
                                {"dispatch": "dispatch", "lead": "lead"})
        targets = {"dispatch": "dispatch", "skeptic": "skeptic", "respond": "respond", "lead": "lead", END: END}
        for node in ("lead", "review", "skeptic", "respond"):
            g.add_conditional_edges(node, self.route, targets)
        g.add_conditional_edges("dispatch", self.fan_out, ["worker"])
        # Route once after the parallel worker superstep so Lead cannot decide while Skeptic is still reviewing.
        g.add_edge("worker", "review")
        return g.compile()

    def run(self) -> Board:
        self.registry.run_required_checks()
        if self.board.focused:
            self.registry.dispatch_focused_review()
            if not self.board.review_questions:
                try:
                    check_verdict(self.board, "safe_to_merge")
                except ConstitutionError:
                    pass
                else:
                    self.board.verdict = {"decision": "safe_to_merge", "case_ids": [],
                                          "rationale": "The scan and required checks passed. No findings needed agent review.",
                                          "evidence_ids": [self.registry.world["scan_summary_id"]]}
                    self.board.log(event="verdict", source="deterministic_scan", **self.board.verdict)
                    return self.board
        self.graph.invoke({"board": self.board, "done": []}, {"recursion_limit": 200})
        return self.board
