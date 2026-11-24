"""Entry point for an agentic run.

world="canned": Stage A fixed facts (works offline; used by the replay test).
world="real":   Stage B real tools on sandbox/uptime-kuma scenario/base..scenario/s3-s9.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from guardian import config
from guardian.agents import fakeworld
from guardian.agents.board import Board
from guardian.agents.llm import ClaudeBackend, FreeModelBackend, GeminiBackend, OpenRouterBackend, ScriptedBackend, load_script, make_resolver
from guardian.agents.orchestrator import Orchestrator
from guardian.agents.tools import ToolRegistry
from guardian.store.evidence import EvidenceStore

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REPLAY = ROOT / "testbed" / "replays" / "s3_s9_agents.json"


def run(out: Path, backend: str = "auto", replay: Path = DEFAULT_REPLAY, run_id: str = "RUN-12",
        world_kind: str = "canned", repo: Path = ROOT / "sandbox" / "uptime-kuma",
        base: str = "scenario/base", head: str = "scenario/s3-s9", pace: float = 0.0,
        human_override=None, on_board=None) -> Board:
    store = EvidenceStore(out)
    if world_kind == "real":
        from guardian.agents.realworld import RealFacts
        facts = RealFacts(repo, base, head, store, ROOT / "guardian.yaml", ROOT / ".cache" / "tarballs")
        world = {"facts": facts}
        board = Board(run_id=run_id, base=base, head=head)
        board.coverage_required = facts.coverage_required()
        human = facts.human
    else:
        world = fakeworld.build(store)
        board = Board(run_id=run_id, base="2.5.12", head="scenario/s3-s9")
        board.coverage_required = set(world["coverage_required"])

        def human(question: str, options: list[str]) -> str:
            return world["human_answers"]["registry"] if "registry" in question.lower() else options[-1]

    if human_override is not None:  # the dashboard asks a real person, with the policy answer as fallback
        fallback = human
        human = lambda q, o: human_override(q, o, fallback)  # noqa: E731
    registry = ToolRegistry(board, store, world, human)
    registry.pace = pace
    if on_board is not None:
        on_board(board, store)
    if backend == "auto":
        backend = config.provider()
    if backend == "replay":
        if world_kind == "real":
            raise SystemExit("replay works only with the canned world; use --backend openrouter|claude for real facts")
        model = ScriptedBackend(load_script(str(replay)), make_resolver(board, world, store))
    elif backend == "openrouter":
        model = OpenRouterBackend()
    elif backend in ("freemodel", "deepseek"):
        from guardian.agents.llm import make_backend
        model = make_backend(backend)  # DeepSeek first, then FreeModel, then Gemini (fallback on quota/outage)
    elif backend == "gemini":
        model = GeminiBackend()
    elif backend == "claude":
        model = ClaudeBackend()
    else:
        raise SystemExit(f"unknown backend {backend}")
    board.log(event="run_start", backend=backend)
    Orchestrator(board, registry, model).run()
    (out / f"{run_id}.board.json").write_text(json.dumps({
        "board": board.snapshot(),
        "messages": [m.model_dump(exclude_none=True) for m in board.messages],
        "audit": board.audit,
    }, indent=1, default=str))
    return board


def timeline(board: Board) -> str:
    lines = []
    for e in board.audit:
        ev = e.get("event")
        if ev == "tool_call":
            lines.append(f"  {e['agent']:<9} ⚙ {e['tool']}({', '.join(f'{k}={v}' for k, v in e['args'].items()) if e['args'] else ''})"[:150])
        elif ev == "rejected":
            lines.append(f"  {e['agent']:<9} ✘ REJECTED {e['kind']}: {e['reason']}"[:170])
        elif ev in ("dispatch", "ask_human", "floor_intervention", "verdict", "coverage_gap", "run_start"):
            lines.append(f"  {'system':<9} • {ev}: " + json.dumps({k: v for k, v in e.items() if k != 'event'}, default=str)[:140])
    for m in board.messages:
        pass
    return "\n".join(lines)
