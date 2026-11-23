"""LangGraph control loop (AGENTIC_CORE §4 and §8).

lead -> (tasks?) workers [parallel via Send] -> (hypotheses?) skeptic -> (challenges?) respond
     -> lead re-plans ... -> submit_verdict passes the constitution -> END
"""
from __future__ import annotations

import json
import operator
from typing import Annotated, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from guardian.agents.agents import Agent
from guardian.agents.board import Board
from guardian.agents.tools import ToolRegistry


class State(TypedDict, total=False):
    board: Board
    task_id: str
    done: Annotated[list, operator.add]


class Orchestrator:
    def __init__(self, board: Board, registry: ToolRegistry, backend, max_rounds: int = 30):
        self.board, self.registry, self.backend = board, registry, backend
        self.max_rounds = max_rounds
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
        return "\n".join(json.dumps(m.model_dump(exclude_none=True, exclude={"run_id"})) for m in msgs) or "(none)"

    # --- nodes ---------------------------------------------------------------
    def lead_node(self, state: State) -> dict:
        self.board.rounds += 1
        news = self._unread("lead")
        self._mark_read("lead")
        if self.board.rounds == 1:
            text = (f"New run {self.board.run_id}: compare base {self.board.base} with head {self.board.head}. "
                    "Investigate and submit a verdict.")
        else:
            text = ("Update. New messages to you:\n" + self._fmt(news) +
                    f"\nBoard: {json.dumps(self.board.snapshot())}\nContinue: re-plan, build/resolve cases, or submit the verdict.")
        self.lead.run(text)
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
        brief = (f"Task {task.id} ({task.depth}): {task.goal}\nScope: {task.scope}\nAcceptance: {task.acceptance}\n"
                 "Post hypotheses to the Skeptic and finish with a task_result to the Lead (include task_id).")
        result = agent.run(brief)
        if task.status == "running":
            task.status = "done" if result != "exhausted" else "exhausted"
        return {"done": [task.id]}

    def skeptic_node(self, state: State) -> dict:
        news = self._unread("skeptic")
        self._mark_read("skeptic")
        self.skeptic.run("Review these messages:\n" + self._fmt(news) +
                         "\nChallenge, corroborate, dispute, clear (non-hard only) or report missed risks.")
        return {}

    def respond_node(self, state: State) -> dict:
        for role in ("hunter", "forensics"):
            news = self._unread(role)
            self._mark_read(role)
            for m in news:
                agent = self.task_agents.get(m.task_id or "") or next(
                    (a for tid, a in reversed(list(self.task_agents.items())) if a.name == role), None)
                if agent:
                    agent.run("The Skeptic challenges you:\n" + self._fmt([m]) + "\nAnswer with evidence (kind 'answer').")
        return {}

    # --- routing -------------------------------------------------------------
    def route(self, state: State) -> str:
        b = self.board
        if b.verdict or b.rounds >= self.max_rounds:
            return END
        if b.open_tasks():
            return "dispatch"
        if self._unread("skeptic"):
            return "skeptic"
        if self._unread("hunter") or self._unread("forensics"):
            return "respond"
        return "lead"

    def _build(self):
        g = StateGraph(State)
        g.add_node("lead", self.lead_node)
        g.add_node("dispatch", self.dispatch_node)
        g.add_node("worker", self.worker_node)
        g.add_node("skeptic", self.skeptic_node)
        g.add_node("respond", self.respond_node)
        g.add_edge(START, "lead")
        targets = {"dispatch": "dispatch", "skeptic": "skeptic", "respond": "respond", "lead": "lead", END: END}
        for node in ("lead", "skeptic", "respond"):
            g.add_conditional_edges(node, self.route, targets)
        g.add_conditional_edges("dispatch", self.fan_out, ["worker"])
        g.add_conditional_edges("worker", self.route, targets)
        return g.compile()

    def run(self) -> Board:
        self.graph.invoke({"board": self.board, "done": []}, {"recursion_limit": 200})
        return self.board
