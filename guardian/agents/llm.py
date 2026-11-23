"""Model back ends for the agents.

ClaudeBackend  real agents on Claude Opus 5.5 (Messages API, manual tool loop so the
               orchestrator can apply the constitution and budgets on every step).
ScriptedBackend replays recorded agent turns: lets the full loop run and be tested without
               an API key, and gives a reproducible demo replay if the venue network fails.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Protocol

MODEL = "claude-opus-5-5"


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict


@dataclass
class Turn:
    text: str
    tool_calls: list[ToolCall]
    stop_reason: str
    raw_content: list = field(default_factory=list)  # appended back unchanged (keeps thinking blocks intact)


class Backend(Protocol):
    def step(self, agent: str, system: str, messages: list, tools: list[dict], effort: str) -> Turn: ...


class ClaudeBackend:
    """Claude Opus 5.5: adaptive thinking is always on; depth is set with output_config.effort.
    No temperature (rejected by this model) and no forced tool_choice (rejected too)."""

    def __init__(self):
        import anthropic

        self.client = anthropic.Anthropic()  # credentials from the environment (ANTHROPIC_API_KEY or an ant profile)

    def step(self, agent, system, messages, tools, effort):
        resp = self.client.beta.messages.create(
            model=MODEL,
            max_tokens=16000,
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            tools=tools,
            messages=messages,
            output_config={"effort": effort},
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",  # security content can trip classifiers; let the API route a declined turn
        )
        if resp.stop_reason == "refusal":
            return Turn(text="(model declined this turn)", tool_calls=[], stop_reason="refusal", raw_content=resp.content)
        calls = [ToolCall(b.id, b.name, dict(b.input)) for b in resp.content if b.type == "tool_use"]
        text = "".join(b.text for b in resp.content if b.type == "text")
        return Turn(text=text, tool_calls=calls, stop_reason=resp.stop_reason, raw_content=resp.content)


class OpenRouterBackend:
    """Claude Opus 5.5 through OpenRouter (OpenAI-style chat completions with tool calling).

    The agent history is kept in one neutral shape (user text, assistant blocks, tool results)
    and translated to OpenRouter's message format on every step. No temperature is sent.
    """

    URL = "https://openrouter.ai/api/v1/chat/completions"
    MODEL = "anthropic/claude-opus-5.5"

    def __init__(self, model: str | None = None, timeout: int = 180):
        import os

        import requests

        self.session = requests.Session()
        self.key = os.environ["OPENROUTER_API_KEY"]
        self.model = model or os.environ.get("GUARDIAN_MODEL", self.MODEL)
        self.timeout = timeout
        self.usage = {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0}

    @staticmethod
    def _to_openai(system: str, messages: list) -> list:
        out = [{"role": "system", "content": system}]
        for m in messages:
            content = m["content"]
            if m["role"] == "user" and isinstance(content, str):
                out.append({"role": "user", "content": content})
            elif m["role"] == "user":  # tool results
                for r in content:
                    out.append({"role": "tool", "tool_call_id": r["tool_use_id"], "content": r["content"]})
            else:  # assistant blocks
                text = "".join(b.get("text", "") for b in content if b.get("type") == "text")
                calls = [{"id": b["id"], "type": "function",
                          "function": {"name": b["name"], "arguments": json.dumps(b["input"])}}
                         for b in content if b.get("type") == "tool_use"]
                msg = {"role": "assistant", "content": text or None}
                if calls:
                    msg["tool_calls"] = calls
                out.append(msg)
        return out

    @staticmethod
    def _tools(tools: list[dict]) -> list[dict]:
        return [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                  "parameters": t["input_schema"]}} for t in tools]

    def step(self, agent, system, messages, tools, effort):
        body = {
            "model": self.model,
            "messages": self._to_openai(system, messages),
            "tools": self._tools(tools),
            "tool_choice": "auto",
            "max_tokens": 16000,
            "reasoning": {"effort": effort},
        }
        last_err = None
        for attempt in range(3):
            r = self.session.post(self.URL, json=body, timeout=self.timeout, headers={
                "Authorization": f"Bearer {self.key}", "X-Title": "Bosch Supply Chain Guardian (hackathon)"})
            if r.status_code == 200:
                break
            last_err = f"HTTP {r.status_code}: {r.text[:300]}"
            if r.status_code not in (429, 500, 502, 503, 504):
                raise RuntimeError(f"OpenRouter error {last_err}")
            import time
            time.sleep(2 * (attempt + 1))
        else:
            raise RuntimeError(f"OpenRouter error after retries: {last_err}")
        data = r.json()
        u = data.get("usage") or {}
        self.usage["calls"] += 1
        self.usage["prompt_tokens"] += u.get("prompt_tokens", 0)
        self.usage["completion_tokens"] += u.get("completion_tokens", 0)
        choice = data["choices"][0]
        msg = choice["message"]
        calls = []
        for tc in msg.get("tool_calls") or []:
            try:
                args = json.loads(tc["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {"_invalid_json": tc["function"].get("arguments", "")[:200]}
            calls.append(ToolCall(tc["id"], tc["function"]["name"], args))
        text = msg.get("content") or ""
        raw = ([{"type": "text", "text": text}] if text else []) + \
              [{"type": "tool_use", "id": c.id, "name": c.name, "input": c.input} for c in calls]
        stop = "tool_use" if calls else ("refusal" if choice.get("finish_reason") == "content_filter" else "end_turn")
        return Turn(text=text, tool_calls=calls, stop_reason=stop, raw_content=raw or [{"type": "text", "text": ""}])


class ScriptedBackend:
    """Replays a script: {agent: [turn, ...]} where a turn is a list of [tool_name, input] pairs
    (empty list = the agent ends its turn). Inputs may contain placeholders resolved at runtime:
      {E:key}        canned evidence id        {F:type}  finding id by type
      {T:assignee}   latest task for assignee  {C:last}  latest case id
      {E:human}      evidence of the last ask_human answer
    """

    def __init__(self, script: dict[str, list], resolver):
        self.queues = {k: list(v) for k, v in script.items()}
        self.resolver = resolver
        self.n = 0

    def step(self, agent, system, messages, tools, effort):
        queue = self.queues.get(agent) or []
        turn = queue.pop(0) if queue else []
        calls = []
        for name, args in turn:
            self.n += 1
            calls.append(ToolCall(f"toolu_s{self.n:04d}", name, self.resolver(args)))
        raw = [{"type": "tool_use", "id": c.id, "name": c.name, "input": c.input} for c in calls] or \
              [{"type": "text", "text": "done"}]
        return Turn(text="" if calls else "done", tool_calls=calls,
                    stop_reason="tool_use" if calls else "end_turn", raw_content=raw)


_PLACEHOLDER = re.compile(r"\{([ETFC]):([^}]+)\}")


def make_resolver(board, world, store):
    def resolve_str(s: str) -> str:
        def sub(m):
            kind, key = m.group(1), m.group(2)
            if kind == "E" and key == "human":
                return next(e["evidence"] for e in reversed(board.audit) if e.get("event") == "ask_human")
            if kind == "E":
                return world["evidence"][key]
            if kind == "F":
                return next(f.id for f in board.findings.values() if f.type == key)
            if kind == "T":
                return [t.id for t in board.tasks.values() if t.assignee == key][-1]
            if kind == "C":
                return list(board.cases)[-1]
            return m.group(0)
        return _PLACEHOLDER.sub(sub, s)

    def resolve(obj):
        if isinstance(obj, str):
            return resolve_str(obj)
        if isinstance(obj, list):
            return [resolve(x) for x in obj]
        if isinstance(obj, dict):
            return {k: resolve(v) for k, v in obj.items()}
        return obj

    return resolve


def load_script(path: str) -> dict:
    return json.loads(open(path).read())
