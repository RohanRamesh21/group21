"""Model back ends for the agents.

ClaudeBackend  real agents on Claude Opus 5.5 (Messages API, manual tool loop so the
               orchestrator can apply the constitution and budgets on every step).
ScriptedBackend replays recorded agent turns: lets the full loop run and be tested without
               an API key, and gives a reproducible demo replay if the venue network fails.
"""
from __future__ import annotations

import itertools
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

        self.client = anthropic.Anthropic(timeout=60.0, max_retries=1)

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

    def __init__(self, model: str | None = None, timeout: int = 60):
        import os

        import requests

        self.session = requests.Session()
        self.key = os.environ["OPENROUTER_API_KEY"]
        self.model = model or os.environ.get("GUARDIAN_MODEL", self.MODEL)
        self.timeout = timeout

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
                          "function": {"name": b["name"], "arguments": json.dumps(b["input"])},
                          # Gemini 3 needs its thought signature sent back with each tool call
                          **({"extra_content": b["extra_content"]} if b.get("extra_content") else {})}
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
        return self._parse(r.json())

    @staticmethod
    def _parse(data: dict) -> Turn:
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
        extra = {tc["id"]: tc.get("extra_content") for tc in msg.get("tool_calls") or []}
        raw = ([{"type": "text", "text": text}] if text else []) + \
              [{"type": "tool_use", "id": c.id, "name": c.name, "input": c.input,
                **({"extra_content": extra[c.id]} if extra.get(c.id) else {})} for c in calls]
        stop = {"content_filter": "refusal", "length": "length"}.get(choice.get("finish_reason"),
                                                                  "tool_use" if calls else "end_turn")
        return Turn(text=text, tool_calls=calls, stop_reason=stop, raw_content=raw or [{"type": "text", "text": ""}])


class DeepSeekBackend(OpenRouterBackend):
    """Native DeepSeek Chat Completions with Guardian's function tools."""

    URL = "https://api.deepseek.com/chat/completions"
    MODEL = "deepseek-flash"

    def __init__(self, timeout: int = 45):
        import os

        import requests

        self.key = os.environ.get("DEEPSEEK_API_KEY")
        if not self.key:
            raise ValueError("DEEPSEEK_API_KEY is required for the DeepSeek backend")
        self.model = os.environ.get("GUARDIAN_DEEPSEEK_MODEL") or self.MODEL
        self.session = requests.Session()
        self.timeout = timeout

    def step(self, agent, system, messages, tools, effort):
        import time

        import requests

        body = {"model": self.model, "messages": self._to_openai(system, messages), "tools": self._tools(tools),
                "tool_choice": "auto", "thinking": {"type": "disabled"}, "max_tokens": 4096}
        for attempt in range(3):
            try:
                response = self.session.post(self.URL, json=body, headers={"Authorization": f"Bearer {self.key}"},
                                             timeout=self.timeout, allow_redirects=False)
            except requests.RequestException as exc:
                raise RuntimeError(f"DeepSeek API request failed: {type(exc).__name__}") from exc
            if response.status_code == 200:
                return self._parse(response.json())
            if response.status_code not in {429, 500, 502, 503, 504} or attempt == 2:
                raise RuntimeError(f"DeepSeek API failed: HTTP {response.status_code}")
            time.sleep(2 ** attempt)


class FreeModelBackend(OpenRouterBackend):
    """FreeModel chat completions using the same tool and message format."""

    URL = "https://freemodel.in/v1/chat/completions"
    MODEL = "deepseek-v4.1-flash"

    def __init__(self, timeout: int = 35):
        import os

        import requests

        self.session = requests.Session()
        self.key = os.environ["FM_API_KEY"]
        model = os.getenv("GUARDIAN_MODEL", self.MODEL)
        fallbacks = [m.strip() for m in os.getenv("GUARDIAN_FALLBACK_MODELS", "").split(",") if m.strip()]
        self.models = list(dict.fromkeys([model, *fallbacks, self.MODEL]))
        self.timeout = timeout
        self.sticky: dict[str, str] = {}

    def step(self, agent, system, messages, tools, effort):
        import requests

        models = list(dict.fromkeys([self.sticky.get(agent, self.models[0]), *self.models]))
        body = {"messages": self._to_openai(system, messages), "tools": self._tools(tools),
                "tool_choice": "auto", "max_tokens": 4096}
        error = "no response"
        for model in models:
            try:
                response = self.session.post(self.URL, json={**body, "model": model},
                                             headers={"Authorization": f"Bearer {self.key}"},
                                             timeout=self.timeout, allow_redirects=False)
            except requests.RequestException as exc:
                error = type(exc).__name__
                continue
            if response.ok:
                turn = self._parse(response.json())
                self.sticky[agent] = model
                return turn
            error = f"HTTP {response.status_code}"
            if response.status_code not in {404, 429, 500, 502, 503, 504}:
                break
        raise RuntimeError(f"FreeModel API failed: {error}")


class GeminiBackend(OpenRouterBackend):
    """Google Gemini through its OpenAI-compatible endpoint (same message translation as OpenRouter).

    Tries GUARDIAN_MODEL first (default gemini-3.5-flash), then the fallback models in order when Google
    reports overload (503) or quota (429).
    """

    URL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
    MODEL = "gemini-3.5-flash"
    FALLBACKS = ("gemini-2.5-flash",)

    def __init__(self, model: str | None = None, timeout: int = 60):
        import os

        import requests

        from guardian import config

        config.load_env()  # the key lives in guardian/.env (git-ignored, mode 600)
        self.session = requests.Session()
        self.key = os.environ["GOOGLE_API_KEY"]
        self.model = model or os.environ.get("GUARDIAN_MODEL", self.MODEL)
        extra = [m.strip() for m in os.environ.get("GUARDIAN_FALLBACK_MODELS", "").split(",") if m.strip()]
        self.models = [self.model] + [m for m in (extra or list(self.FALLBACKS)) if m != self.model]
        self.timeout = timeout
        self._call_ids = itertools.count(1)
        self.sticky: dict[str, str] = {}

    # Gemini 3 requires a thought signature on function calls in the history. Calls produced by a model that
    # gives none (e.g. a fallback model) get Google's documented placeholder so the history stays valid.
    SKIP_SIG = {"google": {"thought_signature": "skip_thought_signature_validator"}}

    def _to_openai(self, system: str, messages: list) -> list:
        out = OpenRouterBackend._to_openai(system, messages)
        for m in out:
            for tc in m.get("tool_calls") or []:
                tc.setdefault("extra_content", self.SKIP_SIG)
        return out

    def step(self, agent, system, messages, tools, effort):
        import time

        import requests

        effort = {"max": "high", "xhigh": "high"}.get(effort, effort)
        last_err = None
        sticky = self.sticky.get(agent)  # once an agent falls back, it stays on that model (keeps its history valid)
        order = [sticky] + [m for m in self.models if m != sticky] if sticky else self.models
        for model in order:
            body = {"model": model, "messages": self._to_openai(system, messages), "tools": self._tools(tools),
                    "tool_choice": "auto", "max_tokens": 16000, "reasoning_effort": effort}
            for attempt in range(4):
                try:
                    r = self.session.post(self.URL, json=body, timeout=self.timeout,
                                          headers={"Authorization": f"Bearer {self.key}"})
                except requests.RequestException as e:  # slow or dropped: move on to the next model
                    last_err = f"{model}: {type(e).__name__}"
                    break
                if r.status_code == 200:
                    if model != self.models[0]:
                        self.sticky[agent] = model
                    return self._parse(r.json())
                last_err = f"{model} HTTP {r.status_code}: {r.text[:300]}"
                if r.status_code == 404:  # model retired or not available to this key: try the next one
                    break
                if r.status_code == 429:
                    wait = self._retry_delay(r)
                    if wait is None or wait > 65:  # daily quota used up: next model
                        break
                    time.sleep(min(max(wait, 0), 10) + 1)
                    continue
                if r.status_code not in (500, 502, 503, 504):
                    raise RuntimeError(f"Gemini error {last_err}")
                time.sleep(3 * (attempt + 1))
        raise RuntimeError(f"Gemini error after trying {', '.join(order)}: {last_err}")

    @staticmethod
    def _retry_delay(r) -> float | None:
        """Seconds Google asks us to wait (RetryInfo), or None if it gives no hint."""
        try:
            body = r.json()
            err = body[0]["error"] if isinstance(body, list) else body["error"]
            for d in err.get("details", []):
                if d.get("retryDelay"):
                    return float(str(d["retryDelay"]).rstrip("s"))
        except Exception:
            return None
        return None

    def _parse(self, data: dict) -> Turn:
        choice = data["choices"][0]
        msg = choice["message"]
        calls = []
        for tc in msg.get("tool_calls") or []:
            tc.setdefault("id", f"call_{next(self._call_ids)}")
            try:
                args = json.loads(tc["function"].get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {"_invalid_json": tc["function"].get("arguments", "")[:200]}
            calls.append(ToolCall(tc["id"], tc["function"]["name"], args))
        text = msg.get("content") or ""
        extra = {tc["id"]: tc.get("extra_content") for tc in msg.get("tool_calls") or []}
        raw = ([{"type": "text", "text": text}] if text else []) + \
              [{"type": "tool_use", "id": c.id, "name": c.name, "input": c.input,
                **({"extra_content": extra[c.id]} if extra.get(c.id) else {})} for c in calls]
        stop = {"content_filter": "refusal", "length": "length"}.get(choice.get("finish_reason"),
                                                                  "tool_use" if calls else "end_turn")
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
